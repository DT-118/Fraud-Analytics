"""
Lazy Redis client used by the fraud engine.

Redis supports two configuration modes:

1. REDIS_URL
   A complete Redis connection URL. When provided, it takes precedence.

2. REDIS_HOST / REDIS_PORT / REDIS_DB / REDIS_PASSWORD
   Individual Redis connection settings used when REDIS_URL is not provided.

The Redis client is created lazily on first use so importing this module does
not require Redis to be reachable.
"""

from __future__ import annotations

import os
import threading

import redis

from core.errors import ErrorCode
from core.logger import logger


REDIS_URL = os.getenv("REDIS_URL", "").strip() or None
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB_INDEX = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None


def _build_client() -> redis.Redis:
    """Build the Redis client using URL or individual connection settings."""

    if REDIS_URL:
        return redis.from_url(
            REDIS_URL,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=True,
        )

    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB_INDEX,
        password=REDIS_PASSWORD,
        socket_connect_timeout=2,
        socket_timeout=2,
        decode_responses=True,
    )


class _LazyRedisClient:
    """
    Lazily initialize the Redis connection on first use.

    Importing this module does not connect to Redis. The first Redis operation
    creates and verifies the client. A lock protects initialization when
    multiple threads make their first Redis request concurrently.
    """

    def __init__(self):
        self._client: redis.Redis | None = None
        self._lock = threading.Lock()

    def _get_client(self) -> redis.Redis:
        """Return the initialized Redis client."""

        # Fast path: avoid locking after the client has been initialized.
        if self._client is not None:
            return self._client

        with self._lock:
            # Another thread may have initialized the client while this thread
            # waited for the lock.
            if self._client is None:
                try:
                    client = _build_client()
                    client.ping()
                    self._client = client
                    logger.info("[REDIS] Connected")
                except Exception as exc:
                    logger.warning("[REDIS] Connection failed: %s", exc)
                    raise RuntimeError(ErrorCode.REDIS_ERROR) from exc

        return self._client

    def __getattr__(self, name: str):
        """Forward Redis operations to the lazily initialized client."""
        return getattr(self._get_client(), name)


redis_client = _LazyRedisClient()