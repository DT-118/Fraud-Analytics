from core.errors import ErrorCode
from core.logger import logger
from storage.redis_client import redis_client


def touch(redis_key: str, ttl_seconds: int):
    """
    Extend TTL of a Redis key if it exists.

    Does nothing if the key does not exist.
    Used to implement sliding window semantics.
    """
    try:
        if redis_client.exists(redis_key):
            redis_client.expire(redis_key, ttl_seconds)
            logger.info(f"Refreshed TTL for redis_key={redis_key} ttl={ttl_seconds}")
            print(f"[REDIS] TTL refreshed for key={redis_key}")

    except Exception as exc:
        logger.exception("FE-502:REDIS_TTL_REFRESH_FAILED")
        print(
            f"[REDIS ERROR] Failed to refresh TTL for key={redis_key}:",
            exc,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc
