"""
Small Redis utility helpers shared by the fraud engine.
"""

from __future__ import annotations

from core.logger import logger
from storage.redis_client import redis_client


def touch(redis_key: str, ttl_seconds: int) -> None:
    """
    Extend the TTL of an existing Redis key.

    The key is left unchanged when it does not exist. Redis failures are
    handled as non-blocking because TTL extension is auxiliary to the primary
    scoring operation.
    """
    try:
        if redis_client.exists(redis_key):
            redis_client.expire(redis_key, ttl_seconds)
    except Exception as exc:
        logger.warning(
            "[REDIS] TTL refresh failed for key=%s: %s",
            redis_key,
            exc,
        )
