from zoneinfo import ZoneInfo

from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.settings import REDIS_TTL, THRESHOLDS
from storage.redis_client import redis_client
from storage.redis_utils import touch


def is_emulator_resolution(screen_resolution: str) -> bool:
    emulator_resolutions = {"800x600", "1024x768", "1280x720"}
    return screen_resolution in emulator_resolutions


def build_auth01_auth03_features(context: Context) -> dict:
    _SAFE = {"user_fail_count": 0, "fail_before_success": 0}
    try:
        if not THRESHOLDS["AUTH-01"]["enabled"] and not THRESHOLDS["AUTH-03"]["enabled"]:
            return _SAFE

        redis_key = f"fail:user:{context.subject_id}"
        min_failures_before_success = THRESHOLDS["AUTH-03"]["min_failures_before_success"]
        sliding_window_seconds = REDIS_TTL["auth"]["fail_window"]

        existing_fail_count = int(redis_client.get(redis_key) or 0)

        features = {"user_fail_count": 0, "fail_before_success": 0}

        if context.success:
            if existing_fail_count >= min_failures_before_success and context.action_taxonomy == "login":
                features["fail_before_success"] = existing_fail_count
            redis_client.delete(redis_key)
            return features

        updated_fail_count = redis_client.incr(redis_key)
        touch(redis_key, sliding_window_seconds)
        features["user_fail_count"] = updated_fail_count
        return features

    except Exception as err:
        logger.warning(
            "%s: AUTH-01/AUTH-03 Redis failure subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, err,
        )
        return _SAFE


def build_auth02_ip_bruteforce_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["AUTH-02"]["enabled"]:
            return 0

        source_ip = context.security_payload.src_ip
        if not source_ip or context.success:
            return 0

        redis_key = f"ip:fail:subjects:{source_ip}"
        sliding_window_seconds = REDIS_TTL["auth"]["ip_fail_window"]

        redis_client.sadd(redis_key, context.subject_id)
        touch(redis_key, sliding_window_seconds)

        return redis_client.scard(redis_key)

    except Exception as err:
        logger.warning(
            "%s: AUTH-02 Redis failure ip=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.security_payload.src_ip, err,
        )
        return 0


def build_new_device_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["AUTH-04"]["enabled"]:
            return 0

        device_id = context.security_payload.device_id
        if not device_id:
            return 0

        redis_key = f"devices:user:{context.subject_id}"
        device_memory_seconds = REDIS_TTL["identity"]["device_memory"]

        redis_client.sadd(redis_key, device_id)
        touch(redis_key, device_memory_seconds)

        total_known_devices = redis_client.scard(redis_key)
        return max(0, total_known_devices - 1)

    except Exception as err:
        logger.warning(
            "%s: AUTH-04 Redis failure subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, err,
        )
        return 0


def build_geo_mismatch_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["AUTH-05"]["enabled"]:
            return 0

        current_geo_location = context.security_payload.geo_loc
        if not current_geo_location:
            return 0

        current_geo_location = current_geo_location.upper()

        redis_key = f"geo:user:{context.subject_id}"
        geo_memory_seconds = REDIS_TTL["identity"]["geo_memory"]

        previous_geo_location = redis_client.get(redis_key)

        # Atomic: write + TTL in one call
        redis_client.set(redis_key, current_geo_location, ex=geo_memory_seconds)

        if previous_geo_location and previous_geo_location != current_geo_location:
            return 1

        return 0

    except Exception as err:
        logger.warning(
            "%s: AUTH-05 Redis failure subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, err,
        )
        return 0


def build_old_browser_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["AUTH-06"]["enabled"]:
            return 0

        minimum_browser_drop = THRESHOLDS["AUTH-06"]["min_browser_drop"]
        min_failures = THRESHOLDS["AUTH-06"]["min_failures"]

        user_agent_string = context.security_payload.user_agent or ""
        if "Chrome/" not in user_agent_string:
            return 0

        try:
            current_browser_version = int(
                user_agent_string.split("Chrome/")[1].split(".")[0]
            )
        except (ValueError, IndexError):
            return 0

        failure_key = f"fail:user:{context.subject_id}"
        fail_count = int(redis_client.get(failure_key) or 0)
        if fail_count < min_failures:
            return 0

        redis_key = f"browser:user:{context.subject_id}"
        device_memory_seconds = REDIS_TTL["identity"]["browser_memory"]

        previous_browser_version_raw = redis_client.get(redis_key)

        if not previous_browser_version_raw:
            # Atomic: write + TTL in one call
            redis_client.set(redis_key, current_browser_version, ex=device_memory_seconds)
            return 0

        previous_browser_version = int(previous_browser_version_raw)
        downgrade_detected = (
            previous_browser_version - current_browser_version >= minimum_browser_drop
        )

        # Atomic: update version + TTL in one call
        redis_client.set(redis_key, current_browser_version, ex=device_memory_seconds)

        return 1 if downgrade_detected else 0

    except Exception as err:
        logger.warning(
            "%s: AUTH-06 Redis failure subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, err,
        )
        return 0


def build_screen_resolution_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["AUTH-07"]["enabled"]:
            return 0

        screen_resolution = context.security_payload.screen_resolution
        if not screen_resolution:
            return 0

        if not is_emulator_resolution(screen_resolution):
            return 0

        redis_key = f"resolution:user:{context.subject_id}"
        device_memory_seconds = REDIS_TTL["identity"]["screen_resolution_memory"]

        redis_client.sadd(redis_key, screen_resolution)
        touch(redis_key, device_memory_seconds)

        return redis_client.scard(redis_key)

    except Exception as err:
        logger.warning(
            "%s: AUTH-07 Redis failure subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, err,
        )
        return 0


def build_language_flip_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["AUTH-08"]["enabled"]:
            return 0

        if not context.success:
            return 0

        current_language = context.security_payload.language
        if not current_language:
            return 0

        language_memory_seconds = REDIS_TTL["identity"]["language_memory"]
        language_key = f"lang:user:{context.subject_id}"
        language_change_counter_key = f"{language_key}:count"

        previous_language = redis_client.get(language_key)

        # Atomic: write language + TTL in one call
        redis_client.set(language_key, current_language, ex=language_memory_seconds)

        if previous_language and previous_language != current_language:
            change_count = redis_client.incr(language_change_counter_key)
            touch(language_change_counter_key, language_memory_seconds)
            return change_count

        return int(redis_client.get(language_change_counter_key) or 0)

    except Exception as err:
        logger.warning(
            "%s: AUTH-08 Redis failure subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, err,
        )
        return 0


def build_odd_login_hour_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != 'login':
            return 0

        if not THRESHOLDS["AUTH-09"]["enabled"]:
            return 0

        # Read window from thresholds config — fully configurable
        odd_start = int(THRESHOLDS["AUTH-09"].get("odd_hour_start", 0))
        odd_end   = int(THRESHOLDS["AUTH-09"].get("odd_hour_end", 4))

        # Convert UTC event time to IST
        ist_time = context.event_time.astimezone(ZoneInfo("Asia/Kolkata"))
        login_hour = ist_time.hour

        return 1 if odd_start <= login_hour <= odd_end else 0

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_FAILURE rule=AUTH-09 subject_id=%s",
            ErrorCode.INTERNAL_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from err






def build_auth10_success_velocity_feature(context: Context) -> int:
    """
    AUTH-10: Rapid successful login velocity.

    Detects the same user successfully authenticating too many times
    within a short window (default 5 minutes).

    Signals:
      - Credential sharing across multiple people/devices
      - Automated token refresh attacks
      - Session hijacking tools replaying valid credentials

    Only increments on success=True.
    Counter resets after window expires (no new successes in 5 min).
    """
    try:
        if context.action_taxonomy != 'login':
            return 0

        if not THRESHOLDS.get("AUTH-10", {}).get("enabled", True):
            return 0

        if not context.success:
            return 0

        redis_key = f"success:velocity:user:{context.subject_id}"
        window_seconds = REDIS_TTL["auth"]["success_window"]

        success_count = redis_client.incr(redis_key)
        touch(redis_key, window_seconds)

        return success_count

    except Exception as err:
        logger.exception(
            "%s:AUTH_FEATURE_REDIS_FAILURE rule=AUTH-10 subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_auth_features(context: Context) -> dict:
    return {
        **build_auth01_auth03_features(context),
        "ip_failed_subject_count":   build_auth02_ip_bruteforce_feature(context),
        "is_new_device":             build_new_device_feature(context), 
        "geo_mismatch":              build_geo_mismatch_feature(context),                 
        "is_old_browser":            build_old_browser_feature(context),
        "suspicious_resolution":     build_screen_resolution_feature(context),
        "language_flip_on_success":  build_language_flip_feature(context),
        "odd_login_hour":            build_odd_login_hour_feature(context),
        "success_velocity":          build_auth10_success_velocity_feature(context),
    }