import os
import redis
from core.errors import ErrorCode
from core.logger import logger


# Option 1: Use full Redis connection string (recommended for production)
#REDIS_URL = os.getenv("REDIS_URL","redis://:dtmytrust@#12345@84.46.255.66:5370/0")

REDIS_URL = os.getenv(
    "REDIS_URL",
    None
)


# Option 2: Fallback to individual parameters (for local dev)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB_INDEX = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)


def get_redis_client():
    """
    Initialize and return a Redis client instance.

    Performs a health check (PING) to ensure Redis connectivity
    before returning the client.
    """
    try:
        logger.info("Initializing Redis client")
        print("[REDIS] Connecting to Redis")

        # If full connection URL is provided
        if REDIS_URL:
            client = redis.from_url(
                REDIS_URL,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
        else:
            # Fallback to manual configuration
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB_INDEX,
                password=REDIS_PASSWORD,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )

        # Health check
        client.ping()
        print("[REDIS] Connected successfully")

        return client

    except Exception as exc:
        logger.exception("FE-502:REDIS_CONNECTION_FAILED")
        print("[REDIS ERROR] Redis connection failed:", exc)
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


# Singleton Redis client
redis_client = get_redis_client()
