from dotenv import load_dotenv
load_dotenv()
import os
import threading

import redis

from core.errors import ErrorCode
from core.logger import logger

REDIS_URL      = os.getenv("REDIS_URL", None)
REDIS_HOST     = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT     = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB_INDEX = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)


def _build_client() -> redis.Redis:
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
    Lazily initializes the Redis connection on first use.

    Importing this module at startup never fails even if Redis is down.
    The first actual Redis command triggers the connection attempt.
    Double-checked locking prevents two threads from both creating clients
    if they race on the first call.
    """

    def __init__(self):
        self._client: redis.Redis | None = None
        self._lock = threading.Lock()

    def _get_client(self) -> redis.Redis:
        # Fast path — no lock once connected
        if self._client is not None:
            return self._client
        with self._lock:
            # Double-check: another thread may have connected while we waited
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
        return getattr(self._get_client(), name)


redis_client = _LazyRedisClient()
