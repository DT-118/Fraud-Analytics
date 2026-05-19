from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.settings import REDIS_TTL, THRESHOLDS
from storage.redis_client import redis_client
from storage.redis_utils import touch


def build_consent_grant_spike_feature(context: Context) -> int:
    """
    CONS-01:
    Detect unusually high number of consent grants
    within a short sliding time window.
    """
    try:
        if context.action_taxonomy != "consent":
            return 0

        if not THRESHOLDS.get("CONS-01", {}).get("enabled", True):
            return 0

        payload = context.consent_payload
        if not payload or payload.operation != "grant":
            return 0

        redis_key = f"consent:grant:user:{context.subject_id}"
        window_seconds = REDIS_TTL["consent"]["grant_window"]

        consent_count = redis_client.incr(redis_key)
        touch(redis_key, window_seconds)

        return consent_count

    except Exception as err:
        logger.exception(
            "%s:CONSENT_GRANT_SPIKE_FAILED subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_consent_features(context: Context) -> dict:
    """
    Aggregate all consent-related features.
    """
    return {
        "consent_grant_count": build_consent_grant_spike_feature(context),
    }
