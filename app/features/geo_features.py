"""
Geographic feature builders.

Two independent, generic (cross-service) features:

  GEO_POLICY_VIOLATION -> is_outside_uae
      Whether the current event's location falls outside the service's
      configured geographic policy (config/geo_policy.yaml)

  GEO_VELOCITY -> geo_change_velocity
      Counts geographic-location changes for the subject within a configured
      window (config/thresholds.yml). 

Both features are generic across AUTH/LOGIN/CONSENT/WALLET.
"""

from __future__ import annotations
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

_GEO_POLICY_CONFIG = HotConfig(_CONFIG_DIR / "geo_policy.yaml")
_THRESHOLDS_CONFIG = HotConfig(_CONFIG_DIR / "thresholds.yml")
_REDIS_TTL_CONFIG = HotConfig(_CONFIG_DIR / "redis_ttl.yml")


def _thresholds() -> dict:
    return _THRESHOLDS_CONFIG.get()


def _redis_ttl() -> dict:
    return _REDIS_TTL_CONFIG.get()


def _get_allowed_prefixes(service: str | None) -> list[str]:
    config = _GEO_POLICY_CONFIG.get()
    service_key = (service or "").strip().upper()
    service_config = config.get(service_key, config.get("default", {}))
    prefixes = service_config.get("allowed_prefixes", ["AE"])

    if not isinstance(prefixes, list):
        raise ValueError(
            f"geo_policy.yaml allowed_prefixes for {service_key or 'default'} must be a list"
        )

    return [str(p).strip().upper() for p in prefixes if str(p).strip()]


# GEO_POLICY_VIOLATION
def build_geo_policy_feature(
    context: Context,
    rule_overrides: dict,
    service: str | None = None,
) -> dict:
    """
    Feature for GEO_POLICY_VIOLATION.
    Skipped (0) when the rule is disabled in YAML or by an admin override.
    Missing geographic data fails open (0).
    """
    resolved_service = service or TAXONOMY_TO_SERVICE.get(context.action_taxonomy, "AUTH")

    if not is_rule_active("GEO_POLICY_VIOLATION", resolved_service, rule_overrides):
        return {"is_outside_uae": 0}

    geo_loc = getattr(context.security_payload, "geo_loc", None)
    if not geo_loc:
        return {"is_outside_uae": 0}

    geo_value = str(geo_loc).strip().upper()
    if not geo_value:
        return {"is_outside_uae": 0}

    allowed_prefixes = _get_allowed_prefixes(resolved_service)
    is_outside = not any(geo_value.startswith(p) for p in allowed_prefixes)
    return {"is_outside_uae": int(is_outside)}

# Detect a change vs. the subject's last known location.
def build_geo_change_feature(
    context: Context,
    rule_overrides: dict,
    service: str,
) -> dict:
    """
    Detect whether the current event's geo_loc differs from the subject's
    last known location. Generic across all services .
    """
    safe = {"geo_changed": 0}
    try:
        if not is_rule_active("GEO_VELOCITY", service, rule_overrides):
            return safe

        current_geo = context.security_payload.geo_loc
        if not current_geo:
            return safe

        current_geo = current_geo.upper()
        redis_key = f"geo:last:{context.subject_id}"
        ttl_seconds = int(_redis_ttl()["identity"]["geo_memory"])
        previous_geo = redis_client.get(redis_key)
        redis_client.set(redis_key, current_geo, ex=ttl_seconds)

        return {
            "geo_changed": int(bool(previous_geo and previous_geo != current_geo))
        }

    except Exception as exc:
        logger.warning(
            "%s: GEO_VELOCITY change-detection Redis error subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, exc,
        )
        return safe


# Count qualifying geo changes within the configured window.
def build_geo_velocity_feature(
    context: Context,
    rule_overrides: dict,
    service: str,
    geo_change_result: dict,
) -> dict:
    """
    Count geo-location changes for the subject within the configured
    velocity window. Mirrors DEVICE_SWITCH_VELOCITY's ZSET pattern
    (device_features.build_device_switch_velocity_feature).
    """
    safe = {"geo_change_velocity": 0}
    try:
        if not is_rule_active("GEO_VELOCITY", service, rule_overrides):
            return safe

        # Only a qualifying change (this event) advances the velocity counter,
        # same pattern as device-switch velocity re-using is_new_device.
        if not geo_change_result.get("geo_changed", 0):
            return safe

        window_seconds = int(
            _thresholds()["GEO_VELOCITY"].get("velocity_window_seconds", 300)
        )
        velocity_key = f"geo:velocity:{context.subject_id}"
        now = int(context.event_time.timestamp())
        member = f"{now}:{uuid.uuid4().hex}"

        pipe = redis_client.pipeline(transaction=True)
        pipe.zadd(velocity_key, {member: now})
        pipe.zremrangebyscore(velocity_key, 0, now - window_seconds)
        pipe.expire(velocity_key, window_seconds)
        pipe.zcard(velocity_key)
        _, _, _, change_count = pipe.execute()

        return {"geo_change_velocity": int(change_count)}

    except Exception as exc:
        logger.warning(
            "%s: GEO_VELOCITY Redis error subject_id=%s — fail-open: %s",
            ErrorCode.REDIS_ERROR, context.subject_id, exc,
        )
        return safe


def build_geo_features(
    context: Context,
    rule_overrides: dict,
    service: str | None = None,
) -> dict:
    """Build all geo-related features: policy violation + change velocity."""
    resolved_service = service or "AUTH"
    geo_change_result = build_geo_change_feature(context, rule_overrides, resolved_service)

    return {
        **build_geo_policy_feature(context, rule_overrides, resolved_service),
        **geo_change_result,
        **build_geo_velocity_feature(
            context, rule_overrides, resolved_service, geo_change_result
        ),
    }