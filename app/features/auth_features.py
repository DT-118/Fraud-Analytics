"""
Authentication feature builders.

These features maintain short-lived authentication behavior state in Redis and
return values consumed by the authentication rules.

Rule mapping:
    AUTH_CONSECUTIVE_FAILURES -> user_fail_count
    AUTH_IP_BRUTE_FORCE -> ip_failed_subject_count
    AUTH_SUCCESS_AFTER_FAILURES -> fail_before_success
    AUTH_BROWSER_DOWNGRADE -> is_old_browser
    AUTH_SUSPICIOUS_SCREEN_RESOLUTION -> suspicious_resolution
    AUTH_LANGUAGE_FLIP -> language_flip_on_success
    AUTH_SUCCESS_VELOCITY -> success_velocity
"""

from __future__ import annotations
import re
import uuid
from pathlib import Path
from typing import Optional
from core.config_loader import HotConfig
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from rules.engine import is_rule_active
from storage.redis_client import redis_client
from storage.redis_utils import touch


_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# Feature-retention configuration. Values are expressed in seconds.
_REDIS_TTL_CONFIG = HotConfig(_CONFIG_DIR / "redis_ttl.yml")

# Feature-specific thresholds. These are detection parameters, not rule weights.
_THRESHOLDS_CONFIG = HotConfig(_CONFIG_DIR / "thresholds.yml")


# Browser tokens must be checked in this order. Edge and Opera UAs also contain
# "Chrome/", so generic Chrome detection must run after their specific tokens.
_BROWSER_UA_PATTERNS = (
    ("EDGE", re.compile(r"Edg/(\d+)")),
    ("OPERA", re.compile(r"OPR/(\d+)")),
    ("CHROME", re.compile(r"Chrome/(\d+)")),
    ("FIREFOX", re.compile(r"Firefox/(\d+)")),
    ("SAFARI", re.compile(r"Version/(\d+)[\d.]*\s+Safari/")),
)

_SUPPORTED_BROWSER_FAMILIES = {"CHROME", "EDGE", "FIREFOX", "SAFARI"}
_KNOWN_BROWSER_FAMILIES = _SUPPORTED_BROWSER_FAMILIES


def _redis_ttl() -> dict:
    """Return the current Redis feature-retention configuration."""
    return _REDIS_TTL_CONFIG.get()


def _thresholds() -> dict:
    """Return the current feature-threshold configuration."""
    return _THRESHOLDS_CONFIG.get()


def is_emulator_resolution(screen_resolution: str) -> bool:
    """Return whether a resolution is in the configured emulator set."""
    return screen_resolution in {"800x600", "1024x768", "1280x720"}


# AUTH_CONSECUTIVE_FAILURES + AUTH_SUCCESS_AFTER_FAILURES
def build_auth01_auth03_features(context: Context, rule_overrides: dict) -> dict:
    """Track authentication failures and detect success after the configured failure streak."""
    safe = {"user_fail_count": 0, "fail_before_success": 0}

    try:
        failure_rule_active = is_rule_active(
            "AUTH_CONSECUTIVE_FAILURES", "AUTH", rule_overrides
        )
        success_after_failures_active = is_rule_active(
            "AUTH_SUCCESS_AFTER_FAILURES", "AUTH", rule_overrides
        )

        if not failure_rule_active and not success_after_failures_active:
            return safe

        redis_key = f"fail:user:{context.subject_id}"
        existing_fail_count = int(redis_client.get(redis_key) or 0)

        if success_after_failures_active:
            threshold = int(
                _thresholds()["AUTH_SUCCESS_AFTER_FAILURES"][
                    "min_failures_before_success"
                ]
            )
        else:
            threshold = 0

        features = safe.copy()

        if context.success:
            if (
                success_after_failures_active
                and context.action_taxonomy == "auth"
                and existing_fail_count >= threshold
            ):
                features["fail_before_success"] = existing_fail_count

            redis_client.delete(redis_key)
            return features

        updated_fail_count = redis_client.incr(redis_key)
        touch(redis_key, int(_redis_ttl()["auth"]["fail_window"]))
        features["user_fail_count"] = int(updated_fail_count)
        return features

    except Exception as exc:
        logger.warning(
            "%s: authentication failure-history Redis error "
            "subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
            exc,
        )
        return safe


# AUTH_IP_BRUTE_FORCE
def build_ip_bruteforce_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """Count distinct subjects receiving failed authentications from the same source IP."""
    try:
        if context.action_taxonomy != "auth":
            return 0

        if not is_rule_active(
            "AUTH_IP_BRUTE_FORCE", "AUTH", rule_overrides
        ):
            return 0

        source_ip = context.security_payload.src_ip
        if not source_ip or context.success:
            return 0

        redis_key = f"ip:fail:subjects:{source_ip}"
        redis_client.sadd(redis_key, context.subject_id)
        touch(redis_key, int(_redis_ttl()["auth"]["ip_fail_window"]))
        return int(redis_client.scard(redis_key))

    except Exception as exc:
        logger.warning(
            "%s: AUTH_IP_BRUTE_FORCE Redis error ip=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR,
            context.security_payload.src_ip,
            exc,
        )
        return 0


def _identify_browser_from_ua(
    user_agent: str,
) -> Optional[tuple[str, int]]:
    """
    Parse one unambiguous browser family and major version from a user agent.

    Returns:
        (family, version): exactly one recognized family was found.
        ("AMBIGUOUS", 0): multiple recognized families were found.
        None: no recognized family was found.
    """
    matches: list[tuple[str, int]] = []

    for family, pattern in _BROWSER_UA_PATTERNS:
        match = pattern.search(user_agent)
        if match:
            matches.append((family, int(match.group(1))))

    if not matches:
        return None

    if len(matches) > 1:
        return ("AMBIGUOUS", 0)

    return matches[0]


def _identify_browser(
    security_payload,
) -> Optional[tuple[str, int]]:
    """
    Resolve browser family/version for AUTH_BROWSER_DOWNGRADE.

    Structured browser fields take precedence when they are recognized and
    valid. Otherwise the raw user agent is parsed with ambiguity detection.
    """
    declared_name = (security_payload.browser_name or "").strip().upper()
    declared_version = security_payload.browser_version

    if declared_name in _KNOWN_BROWSER_FAMILIES and declared_version:
        try:
            return declared_name, int(str(declared_version).split(".")[0])
        except (ValueError, TypeError):
            pass

    user_agent = security_payload.user_agent or ""
    if not user_agent:
        return None

    return _identify_browser_from_ua(user_agent)


# AUTH_BROWSER_DOWNGRADE
def build_old_browser_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """Detect a significant browser-version downgrade after repeated failures."""
    try:
        if context.action_taxonomy != "auth":
            return 0

        if not is_rule_active(
            "AUTH_BROWSER_DOWNGRADE", "AUTH", rule_overrides
        ):
            return 0

        identified = _identify_browser(context.security_payload)
        if identified is None:
            return 0

        family, current_version = identified

        if family == "AMBIGUOUS":
            logger.info(
                "[AUTH_BROWSER_DOWNGRADE] Ambiguous browser UA subject_id=%s",
                context.subject_id,
            )
            return 0

        if family not in _SUPPORTED_BROWSER_FAMILIES:
            return 0

        threshold_config = _thresholds()["AUTH_BROWSER_DOWNGRADE"]
        min_failures = int(threshold_config["min_failures"])
        drop_thresholds = threshold_config["min_browser_drop"]
        minimum_browser_drop = int(
            drop_thresholds.get(
                family,
                drop_thresholds.get("default", 10),
            )
        )

        failure_key = f"fail:user:{context.subject_id}"
        fail_count = int(redis_client.get(failure_key) or 0)
        if fail_count < min_failures:
            return 0

        redis_key = f"browser:user:{context.subject_id}:{family}"
        ttl_seconds = int(_redis_ttl()["identity"]["browser_memory"])
        previous_version_raw = redis_client.get(redis_key)

        if not previous_version_raw:
            redis_client.set(redis_key, current_version, ex=ttl_seconds)
            return 0

        previous_version = int(previous_version_raw)
        downgrade_detected = (
            previous_version - current_version >= minimum_browser_drop
        )

        if downgrade_detected or current_version > previous_version:
            redis_client.set(
                redis_key,
                current_version,
                ex=ttl_seconds,
            )

        return int(downgrade_detected)

    except Exception as exc:
        logger.warning(
            "%s: AUTH_BROWSER_DOWNGRADE Redis error subject_id=%s "
            "— fail-open: %s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
            exc,
        )
        return 0


# AUTH_SUSPICIOUS_SCREEN_RESOLUTION
def build_screen_resolution_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """Count suspicious resolutions observed for the subject within the retention window."""
    try:
        if context.action_taxonomy != "auth":
            return 0

        if not is_rule_active(
            "AUTH_SUSPICIOUS_SCREEN_RESOLUTION",
            "AUTH",
            rule_overrides,
        ):
            return 0

        screen_resolution = context.security_payload.screen_resolution
        if not screen_resolution or not is_emulator_resolution(screen_resolution):
            return 0

        redis_key = f"resolution:user:{context.subject_id}"
        ttl_seconds = int(
            _redis_ttl()["identity"]["screen_resolution_memory"]
        )

        redis_client.sadd(redis_key, screen_resolution)
        touch(redis_key, ttl_seconds)

        return int(redis_client.scard(redis_key))

    except Exception as exc:
        logger.warning(
            "%s: AUTH_SUSPICIOUS_SCREEN_RESOLUTION Redis error "
            "subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
            exc,
        )
        return 0


# _normalize_language
def _normalize_language(value: str | None) -> str | None:
    """'en-US', 'en_GB', 'EN' -> 'en'."""
    if not value:
        return None
    base = value.strip().lower().replace("_", "-").split("-")[0]
    return base or None


# AUTH_LANGUAGE_FLIP
def build_language_flip_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """
    Count language changes on successful authentication within the flip window.

    The last-seen language is remembered for a long time (redis_ttl.yml
    identity.language_memory). Changes are counted only inside the short
    sliding window (thresholds.yml AUTH_LANGUAGE_FLIP.flip_window_seconds).
    Only an event that actually changes the language can return a non-zero count.
    """
    try:
        if context.action_taxonomy != "auth" or not context.success:
            return 0

        if not is_rule_active(
            "AUTH_LANGUAGE_FLIP", "AUTH", rule_overrides
        ):
            return 0

        current_language = _normalize_language(
            context.security_payload.language
        )
        if not current_language:
            return 0

        memory_ttl = int(_redis_ttl()["identity"]["language_memory"])
        window_seconds = int(
            _thresholds()["AUTH_LANGUAGE_FLIP"].get("flip_window_seconds", 86400)
        )

        language_key = f"lang:user:{context.subject_id}"
        flips_key = f"lang:flips:{context.subject_id}"

        previous_language = redis_client.get(language_key)
        redis_client.set(language_key, current_language, ex=memory_ttl)

        # First event, or same language as before: nothing to count.
        if not previous_language or previous_language == current_language:
            return 0

        now = int(context.event_time.timestamp())
        member = f"{now}:{uuid.uuid4().hex}"

        pipe = redis_client.pipeline(transaction=True)
        pipe.zadd(flips_key, {member: now})
        pipe.zremrangebyscore(flips_key, 0, now - window_seconds)
        pipe.expire(flips_key, window_seconds)
        pipe.zcard(flips_key)
        *_, flip_count = pipe.execute()

        return int(flip_count)

    except Exception as exc:
        logger.warning(
            "%s: AUTH_LANGUAGE_FLIP Redis error subject_id=%s "
            "— fail-open: %s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
            exc,
        )
        return 0


# AUTH_SUCCESS_VELOCITY
def build_success_velocity_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """Count successful authentications within a true sliding window."""
    try:
        if context.action_taxonomy != "auth" or not context.success:
            return 0

        if not is_rule_active("AUTH_SUCCESS_VELOCITY", "AUTH", rule_overrides):
            return 0

        redis_key = f"success:velocity:user:{context.subject_id}"
        window_seconds = int(_redis_ttl()["auth"]["success_window"])

        now = int(context.event_time.timestamp())
        member = f"{now}:{uuid.uuid4().hex}"

        pipe = redis_client.pipeline(transaction=True)
        pipe.zadd(redis_key, {member: now})
        pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
        pipe.expire(redis_key, window_seconds)
        pipe.zcard(redis_key)
        *_, success_count = pipe.execute()

        return int(success_count)

    except Exception as exc:
        logger.exception(
            "%s: AUTH_SUCCESS_VELOCITY Redis failure subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


def build_auth_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """Build and return all authentication features for the current event."""
    return {
        **build_auth01_auth03_features(context, rule_overrides),
        "ip_failed_subject_count": build_ip_bruteforce_feature(
            context, rule_overrides
        ),
        "is_old_browser": build_old_browser_feature(
            context, rule_overrides
        ),
        "suspicious_resolution": build_screen_resolution_feature(
            context, rule_overrides
        ),
        "language_flip_on_success": build_language_flip_feature(
            context, rule_overrides
        ),
        "success_velocity": build_success_velocity_feature(
            context, rule_overrides
        ),
    }
