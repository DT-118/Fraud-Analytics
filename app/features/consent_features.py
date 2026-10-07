"""
Consent feature builders.

Rule:
    CONSENT_GRANT_VELOCITY -> consent_grant_count

The feature counts consent grants for a subject within the configured Redis
retention window.

"""

from __future__ import annotations
from pathlib import Path
from core.config_loader import HotConfig
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from rules.engine import is_rule_active
from storage.redis_client import redis_client
from storage.redis_utils import touch


_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# Redis behavioral-state retention values are expressed in seconds.
_REDIS_TTL_CONFIG = HotConfig(_CONFIG_DIR / "redis_ttl.yml")


def _redis_ttl() -> dict:
    """Return the current Redis feature-retention configuration."""
    return _REDIS_TTL_CONFIG.get()


# CONSENT_GRANT_VELOCITY
def build_consent_grant_spike_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """Count consent grants for the subject within the configured window."""
    try:
        if context.action_taxonomy != "consent":
            return 0

        if not is_rule_active(
            "CONSENT_GRANT_VELOCITY",
            "CONSENT",
            rule_overrides,
        ):
            return 0

        payload = context.consent_payload
        if not payload or payload.operation != "grant":
            return 0

        redis_key = f"consent:grant:user:{context.subject_id}"
        window_seconds = int(_redis_ttl()["consent"]["grant_window"])

        consent_count = redis_client.incr(redis_key)
        touch(redis_key, window_seconds)

        return int(consent_count)

    except Exception as exc:
        logger.exception(
            "%s: CONSENT_GRANT_VELOCITY Redis failure subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


def build_consent_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """Build and return all consent-related features."""
    return {
        "consent_grant_count": build_consent_grant_spike_feature(
            context,
            rule_overrides,
        )
    }