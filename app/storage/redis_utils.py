from core.errors import ErrorCode
from core.logger import logger
from storage.redis_client import redis_client


def touch(redis_key: str, ttl_seconds: int) -> None:
    """
    Extend TTL of a Redis key if it exists.

    Does nothing if the key does not exist.
    Used to implement sliding window semantics.
    Fails open — a missed TTL extension is not a scoring blocker.
    """
    try:
        if redis_client.exists(redis_key):
            redis_client.expire(redis_key, ttl_seconds)
    except Exception as exc:
        logger.warning("[REDIS] TTL refresh failed for key=%s: %s", redis_key, exc)
