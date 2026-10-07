"""
Device-related fraud feature builders.

Rules:
    DEVICE_SHARED_ACCOUNTS (slow accumulation) + DEVICE_SHARED_ACCOUNTS_BURST (velocity)

    DEVICE_NEW_DEVICE_ALLOWANCE
        Flags the first newly observed device after the subject exceeds the
        configured lifetime free-device allowance.

    DEVICE_SWITCH_VELOCITY
        Counts newly observed devices added within the configured short window.

Device history for DEVICE_NEW_DEVICE_ALLOWANCE is intentionally permanent.
The Redis TTL in ``device.device_subject_memory`` applies to the shared-device
history used by DEVICE_SHARED_ACCOUNTS, not to the subject's lifetime device
registry.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from core.config_loader import HotConfig
from core.constants import TAXONOMY_TO_SERVICE
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from rules.engine import is_rule_active
from storage.redis_client import redis_client


_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
# Feature-specific detection parameters. These are not scoring weights.
_THRESHOLDS_CONFIG = HotConfig(_CONFIG_DIR / "thresholds.yml")
# Redis behavioral-state retention values are expressed in seconds.
_REDIS_TTL_CONFIG = HotConfig(_CONFIG_DIR / "redis_ttl.yml")


def _thresholds() -> dict:
    """Return the current feature-threshold configuration."""
    return _THRESHOLDS_CONFIG.get()


def _redis_ttl() -> dict:
    """Return the current Redis feature-retention configuration."""
    return _REDIS_TTL_CONFIG.get()


def _service_for_context(context: Context) -> str:
    """Map the event taxonomy to the canonical service name."""
    return TAXONOMY_TO_SERVICE.get(context.action_taxonomy, "AUTH")


# DEVICE_SHARED_ACCOUNTS (slow accumulation) + DEVICE_SHARED_ACCOUNTS_BURST (velocity)
def build_device_shared_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """
    Count distinct subjects seen on the current device, over two windows,
    from ONE sorted set (member = subject_id, score = last-seen epoch):
      device_subject_count  - long window (default 30d)
      device_subject_burst  - short window (default 1h)
    """
    safe = {"device_subject_count": 0, "device_subject_burst": 0}
    device_id = context.security_payload.device_id
    if not device_id:
        return safe

    service = _service_for_context(context)
    long_active = is_rule_active("DEVICE_SHARED_ACCOUNTS", service, rule_overrides)
    burst_active = is_rule_active("DEVICE_SHARED_ACCOUNTS_BURST", service, rule_overrides)

    if not (long_active or burst_active):
        return safe

    try:
        device_cfg = _redis_ttl()["device"]
        long_window = int(device_cfg["device_subject_memory"])
        burst_window = min(int(device_cfg["device_subject_burst_window"]), long_window)

        # New key name: the old device:subjects:{id} is a SET (WRONGTYPE on ZADD).
        key = f"device:subjects:win:{device_id}"
        now = int(context.event_time.timestamp())

        pipe = redis_client.pipeline(transaction=True)
        pipe.zadd(key, {context.subject_id: now})
        pipe.zremrangebyscore(key, 0, now - long_window)
        pipe.expire(key, long_window)
        pipe.zcard(key)
        pipe.zcount(key, now - burst_window, "+inf")
        *_, long_count, burst_count = pipe.execute()

        return {
            "device_subject_count": int(long_count) if long_active else 0,
            "device_subject_burst": int(burst_count) if burst_active else 0,
        }

    except Exception as exc:
        logger.warning(
            "%s: DEVICE_SHARED_ACCOUNTS Redis failure device_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, device_id, exc,
        )
        return safe


# DEVICE_NEW_DEVICE_ALLOWANCE
def build_device_switch_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """
    Track lifetime device usage and flag the first device beyond the allowance.

    The membership check and mutation are executed in one Redis transaction so
    concurrent requests cannot independently classify the same device as new.
    """
    safe = {"is_new_device": 0, "known_device_count": 0}
    device_id = context.security_payload.device_id

    if not device_id:
        return safe

    try:
        service = _service_for_context(context)

        rule_active = is_rule_active("DEVICE_NEW_DEVICE_ALLOWANCE", service, rule_overrides)


        redis_key = f"device:known:subject:{context.subject_id}"

        pipe = redis_client.pipeline(transaction=True)
        pipe.sismember(redis_key, device_id)
        pipe.sadd(redis_key, device_id)
        pipe.scard(redis_key)
        was_known, _, known_count = pipe.execute()

        if not rule_active:
            # Tracking still happened above; only the scoring signal
            # is suppressed while the rule is disabled.
           return {"is_new_device": 0, "known_device_count": int(known_count)}

        allowance = int(_thresholds()["DEVICE_NEW_DEVICE_ALLOWANCE"].get("free_device_allowance", 3))

        is_new_device = int(
            not was_known and int(known_count) > allowance
        )

        return {
            "is_new_device": is_new_device,
            "known_device_count": int(known_count),
        }

    except Exception as exc:
        logger.warning(
            "%s: DEVICE_NEW_DEVICE_ALLOWANCE Redis failure "
            "subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
            exc,
        )
        return safe


# DEVICE_SWITCH_VELOCITY
def build_device_switch_velocity_feature(
    context: Context,
    rule_overrides: dict,
    device_switch_result: dict,
) -> dict:
    """Count qualifying new-device events within the configured velocity window."""
    safe = {"device_switch_velocity": 0}
    device_id = context.security_payload.device_id

    if not device_id:
        return safe

    try:
        service = _service_for_context(context)

        if not is_rule_active(
            "DEVICE_SWITCH_VELOCITY",
            service,
            rule_overrides,
        ):
            return safe

        # DEVICE_NEW_DEVICE_ALLOWANCE already determined whether this event
        # introduced a qualifying new device before mutating the registry.
        if not device_switch_result.get("is_new_device", 0):
            return safe

        velocity_key = f"device:switch:velocity:{context.subject_id}"
        window_seconds = int(
            _thresholds()["DEVICE_SWITCH_VELOCITY"].get(
                "velocity_window_seconds",
                60,
            )
        )
        now = int(context.event_time.timestamp())

        # UUID keeps multiple new-device events in the same second distinct.
        member = f"{now}:{uuid.uuid4().hex}:{device_id}"

        pipe = redis_client.pipeline(transaction=True)
        pipe.zadd(velocity_key, {member: now})
        pipe.zremrangebyscore(
            velocity_key,
            0,
            now - window_seconds,
        )
        pipe.expire(velocity_key, window_seconds)
        pipe.zcard(velocity_key)
        _, _, _, switch_count = pipe.execute()

        return {"device_switch_velocity": int(switch_count)}

    except Exception as exc:
        logger.warning(
            "%s: DEVICE_SWITCH_VELOCITY Redis failure "
            "subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
            exc,
        )
        return safe


def build_device_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """Build the device feature set and preserve DEVICE_NEW_DEVICE_ALLOWANCE and DEVICE_SWITCH_VELOCITY ordering."""
    device_switch_result = build_device_switch_features(
        context,
        rule_overrides,
    )

    return {
        **build_device_shared_features(context, rule_overrides),
        **device_switch_result,
        **build_device_switch_velocity_feature(
            context,
            rule_overrides,
            device_switch_result,
        ),
    }