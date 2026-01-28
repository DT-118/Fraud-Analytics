from storage.redis_client import redis_client
from storage.redis_utils import touch
from core.context import Context
from core.settings import THRESHOLDS, REDIS_TTL
from core.errors import ErrorCode
from core.logger import logger


def build_live01_spoof_feature(context: Context) -> int:
    """
    Builds LIVE-01 feature to track repeated biometric
    liveness spoof detections within a short window.
    """
    try:
        if not THRESHOLDS["LIVE-01"]["enabled"]:
            return 0

        biometric_payload = context.biometric_payload
        if not biometric_payload or biometric_payload.liveness_result != "SPOOF":
            return 0

        redis_key = f"liveness:spoof_attempts:{context.subject_id}"
        attempt_window_seconds = REDIS_TTL["liveness"]["attempt_window"]

        redis_client.incr(redis_key)
        touch(redis_key, attempt_window_seconds)

        return int(redis_client.get(redis_key) or 0)

    except Exception:
        logger.exception(
            "%s:LIVENESS_SPOOF_FAILED subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR} LIVE-01 failed")
        raise RuntimeError(ErrorCode.REDIS_ERROR)


def build_live02_missing_liveness_feature(context: Context) -> int:
    """
    Builds LIVE-02 feature to detect cases where liveness
    verification was required but not provided.
    """
    try:
        if not THRESHOLDS["LIVE-02"]["enabled"]:
            return 0

        biometric_payload = context.biometric_payload
        if not biometric_payload:
            return 0

        if (
            biometric_payload.liveness_required
            and biometric_payload.liveness_result is None
        ):
            return 1

        return 0

    except Exception:
        logger.exception(
            "%s:LIVENESS_MISSING_FAILED subject_id=%s",
            ErrorCode.INTERNAL_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.INTERNAL_ERROR} LIVE-02 failed")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR)


def build_liveness_features(context: Context) -> dict:
    """
    Aggregates all liveness-related fraud features
    into a single feature dictionary.
    """
    return {
        "spoof_detected": build_live01_spoof_feature(context),
        "missing_liveness": build_live02_missing_liveness_feature(context),
    }
