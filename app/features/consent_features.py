from storage.redis_client import redis_client
from storage.redis_utils import touch
from core.settings import THRESHOLDS, REDIS_TTL
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger


def build_consent_grant_spike_feature(context: Context) -> int:
    """
    Builds CONS-01 feature to detect unusually high volumes of
    consent grant operations within a short time window.
    """
    try:
        if context.action_taxonomy != "consent":
            return 0

        enabled = THRESHOLDS["CONS-01"]["enabled"]
        if not enabled:
            return 0

        payload = context.consent_payload
        if not payload or payload.operation != "grant":
            return 0

        redis_key = f"consent:grant:{context.subject_id}"
        sliding_window_seconds = REDIS_TTL["consent"]["grant_window"]

        redis_client.incr(redis_key)
        touch(redis_key, sliding_window_seconds)

        return int(redis_client.get(redis_key) or 0)

    except Exception:
        logger.exception(
            "%s:CONSENT_GRANT_SPIKE_FAILED subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR} CONS-01 failed")
        raise RuntimeError(ErrorCode.REDIS_ERROR)


def build_consent_scope_violation_feature(context: Context) -> int:
    """
    Builds CONS-02 feature to detect usage of consent
    outside the originally allowed scopes.
    """
    try:
        if context.action_taxonomy != "consent":
            return 0

        enabled = THRESHOLDS["CONS-02"]["enabled"]
        if not enabled:
            return 0

        payload = context.consent_payload
        if not payload or payload.operation != "use":
            return 0

        if not payload.allowed_scopes:
            return 0

        return 0 if payload.scope in payload.allowed_scopes else 1

    except Exception:
        logger.exception(
            "%s:CONSENT_SCOPE_VIOLATION_FAILED subject_id=%s",
            ErrorCode.INTERNAL_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.INTERNAL_ERROR} CONS-02 failed")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR)


def build_consent_features(context: Context) -> dict:
    """
    Aggregates all consent-related fraud features
    into a single feature dictionary.
    """
    return {
        "consent_grant_count": build_consent_grant_spike_feature(context),
        "consent_scope_violation": build_consent_scope_violation_feature(context),
    }
