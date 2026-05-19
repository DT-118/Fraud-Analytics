from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.settings import REDIS_TTL, THRESHOLDS
from storage.redis_client import redis_client
from storage.redis_utils import touch


def build_enr01_document_fail_feature(context: Context) -> int:
    """
    Builds ENR-01 feature to detect repeated document
    verification failures during enrollment.
    """
    try:
        if not THRESHOLDS["ENR-01"]["enabled"]:
            return 0

        document_payload = context.document_payload
        if not document_payload:
            return 0

        if document_payload.document_scan_passed:
            return 0

        redis_key = f"enroll:document:fail:{context.subject_id}"
        failure_window_seconds = REDIS_TTL["enroll"]["doc_fail_window"]

        redis_client.incr(redis_key)
        touch(redis_key, failure_window_seconds)

        failure_count = int(redis_client.get(redis_key) or 0)
        #minimum_failures = THRESHOLDS["ENR-01"]["min_failures"]

        return failure_count 
        #if failure_count >= minimum_failures else 0

    except Exception as err:
        logger.exception(
            "%s:ENROLL_DOC_FAIL_FAILED subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR} ENR-01 failed")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_enr02_face_doc_mismatch_feature(context: Context) -> int:
    """
    Builds ENR-02 feature to detect repeated face-to-document
    biometric mismatches during enrollment.
    """
    try:
        if not THRESHOLDS["ENR-02"]["enabled"]:
            return 0

        document_payload = context.document_payload
        
        if not document_payload.document_scan_passed:
            return 0
        
        if not document_payload:
            return 0

        if document_payload.doc_face_matched is not False:
            return 0

        redis_key = f"enroll:face_doc:mismatch:{context.subject_id}"
        mismatch_window_seconds = REDIS_TTL["enroll"]["bio_mismatch_window"]

        redis_client.incr(redis_key)
        touch(redis_key, mismatch_window_seconds)

        mismatch_count = int(redis_client.get(redis_key) or 0)
        #minimum_mismatches = THRESHOLDS["ENR-02"]["min_mismatches"]

        return mismatch_count 
        #if mismatch_count >= minimum_mismatches else 0

    except Exception as err:
        logger.exception(
            "%s:ENROLL_FACE_DOC_FAILED subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR} ENR-02 failed")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_enr03_duplicate_device_enroll_feature(context: Context) -> int:
    """
    Builds ENR-03 feature to detect multiple distinct enrollments
    originating from the same device.
    """
    try:
        if not THRESHOLDS["ENR-03"]["enabled"]:
            return 0

        device_id = context.security_payload.device_id
        if not device_id:
            return 0

        redis_key = f"enroll:device:{device_id}"
        identity_window_seconds = REDIS_TTL["enroll"]["device_identity_window"]

        redis_client.sadd(redis_key, context.subject_id)
        touch(redis_key, identity_window_seconds)

        distinct_subject_count = redis_client.scard(redis_key)
        #max_allowed_identities = THRESHOLDS["ENR-03"]["max_identities"]

        return (
            distinct_subject_count
#            if distinct_subject_count > max_allowed_identities
#            else 0
        )

    except Exception as err:
        logger.exception(
            "%s:ENROLL_DEVICE_DUPLICATE_FAILED device_id=%s",
            ErrorCode.REDIS_ERROR,
            device_id,
        )
        print(f"[ERROR] {ErrorCode.REDIS_ERROR} ENR-03 failed")
        raise RuntimeError(ErrorCode.REDIS_ERROR) from err


def build_enroll_features(context: Context) -> dict:
    """
    Aggregates all enrollment-related fraud features
    into a single feature dictionary.
    """
    return {
        "document_failures": build_enr01_document_fail_feature(context),
        "face_doc_mismatch": build_enr02_face_doc_mismatch_feature(context),
        "device_enroll_count": build_enr03_duplicate_device_enroll_feature(context),
    }
