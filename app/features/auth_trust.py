from storage.redis_client import redis_client
from storage.redis_utils import touch
from core.settings import REDIS_TTL
from core.errors import ErrorCode
from core.logger import logger


def record_recent_successful_authentication(context):
    """
    Records the timestamp of the most recent successful authentication
    for a user.

    This trust signal is used by downstream sensitive actions
    (e.g., wallet export, key rotation).
    """

    # Only successful authentications should refresh trust
    if not context.success:
        return

    redis_key = f"auth:reauth:last:{context.subject_id}"

    try:
        # Store the exact time of successful authentication
        redis_client.set(
            redis_key,
            context.event_time.timestamp(),
        )

        # Extend TTL so trust window slides forward on each success
        touch(redis_key, REDIS_TTL["auth"]["reauth_memory"])

    except Exception:
        logger.exception(
            "%s:AUTH_TRUST_REDIS_FAILURE subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        print(
            f"[ERROR] {ErrorCode.REDIS_ERROR}: "
            f"Failed to record recent authentication for subject_id={context.subject_id}"
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR)
