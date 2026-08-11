from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.settings import REDIS_TTL, THRESHOLDS
from storage.redis_client import redis_client
from storage.redis_utils import touch


def build_live01_spoof_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["LIVE-01"]["enabled"]:
            return 0

        biometric_payload = context.biometric_payload
        if not biometric_payload:
            return 0

        if not biometric_payload.liveness_required:
            return 0

        if biometric_payload.liveness_result != "SPOOF":
            return 0

        redis_key = f"liveness:spoof_attempts:{context.subject_id}"
        attempt_window_seconds = REDIS_TTL["liveness"]["attempt_window"]

        spoof_count = redis_client.incr(redis_key)
        touch(redis_key, attempt_window_seconds)
        return spoof_count

    except Exception as err:
        logger.exception(
            "%s:LIVENESS_SPOOF_FAILED subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_live02_missing_liveness_feature(context: Context) -> int:
    try:
        if context.action_taxonomy != "login":
            return 0

        if not THRESHOLDS["LIVE-02"]["enabled"]:
            return 0

        biometric_payload = context.biometric_payload
        if not biometric_payload:
            return 0

        if biometric_payload.liveness_required and biometric_payload.liveness_result is None:
            return 1

        return 0

    except Exception as err:
        logger.exception(
            "%s:LIVENESS_MISSING_FAILED subject_id=%s",
            ErrorCode.INTERNAL_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from err


def build_liveness_features(context: Context) -> dict:
    return {
        "spoof_detected": build_live01_spoof_feature(context),
        "missing_liveness": build_live02_missing_liveness_feature(context),
    }
