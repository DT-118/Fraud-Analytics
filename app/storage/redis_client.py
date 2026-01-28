import os

import redis
from core.errors import ErrorCode
from core.logger import logger

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB_INDEX = int(os.getenv("REDIS_DB", 0))


def get_redis_client():
    """
    Initialize and return a Redis client instance.

    Performs a health check (PING) to ensure Redis connectivity
    before returning the client.
    """
    try:
        logger.info("Initializing Redis client")
        print("[REDIS] Connecting to Redis")

        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB_INDEX,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=True,
        )

        client.ping()
        return client

    except Exception as exc:
        logger.exception("FE-502:REDIS_CONNECTION_FAILED")
        print("[REDIS ERROR] Redis connection failed:", exc)
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


# Singleton Redis client
redis_client = get_redis_client()
