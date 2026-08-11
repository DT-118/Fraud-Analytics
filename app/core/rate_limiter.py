"""
Redis sliding window rate limiter for the scoring API.

Two limits are enforced per request:
  1. Global  — per API key, across all services (rate_limits.yaml → global)
  2. Service — per (API key, service), from rate_limits.yaml → per_service

Both use 60-second sliding windows via Redis sorted sets.
Fails open on any Redis error — never blocks a request due to limiter failure.
"""

import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, Request, status

from core.config_loader import HotConfig
from core.logger import logger
from storage.redis_client import redis_client

_WINDOW_SECONDS = 60 #per minute
_rate_limits_config = HotConfig(Path(__file__).parent.parent / "config/rate_limits.yaml")


def _get_limits() -> tuple[int, dict[str, int]]:
    cfg = _rate_limits_config.get()
    global_limit = int(cfg.get("global", 2000))
    per_service = {k: int(v) for k, v in cfg.get("per_service", {}).items()}
    return global_limit, per_service


def _sliding_window_count(pipe, redis_key: str, now: int) -> None:
    """Add one command group to a pipeline for a sliding-window counter.

    Member key must be unique per request so concurrent requests in the same
    second are each counted separately (zadd on duplicate key is a no-op).
    """
    window_start = now - _WINDOW_SECONDS
    member = f"{now}:{uuid.uuid4().hex[:8]}"
    pipe.zremrangebyscore(redis_key, 0, window_start)
    pipe.zadd(redis_key, {member: now})
    pipe.zcard(redis_key)
    pipe.expire(redis_key, _WINDOW_SECONDS + 1)


def check_rate_limit(request: Request) -> None:
    """
    FastAPI dependency — enforces global rate limit only (no service context yet).
    Per-service limit requires the parsed body; call check_service_rate_limit()
    from the route handler after parsing.
    """
    api_key = request.headers.get("X-API-Key", "anon")
    now = int(time.time())
    global_limit, _ = _get_limits()

    try:
        pipe = redis_client.pipeline()
        _sliding_window_count(pipe, f"rate:global:{api_key}", now)
        results = pipe.execute()
        count = results[2]

        if count > global_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Global rate limit exceeded: {global_limit} req/min",
            )

    except HTTPException:
        raise

    except Exception as exc:
        logger.warning("[RATE_LIMIT] Global check failed — allowing request: %s", exc)


def check_service_rate_limit(api_key: str, action_taxonomy: Optional[str]) -> None:
    """
    Enforce per-service rate limit after the request body has been parsed.
    Call this from the route handler once action_taxonomy is known.
    Fails open on Redis error.
    """
    from core.constants import TAXONOMY_TO_SERVICE  # avoid circular at module load

    service = TAXONOMY_TO_SERVICE.get(action_taxonomy or "", "default") if action_taxonomy else "default"
    now = int(time.time())
    _, per_service = _get_limits()
    limit = per_service.get(service, per_service.get("default", 600))

    try:
        pipe = redis_client.pipeline()
        _sliding_window_count(pipe, f"rate:svc:{api_key}:{service}", now)
        results = pipe.execute()
        count = results[2]

        if count > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Service rate limit exceeded for {service}: {limit} req/min",
            )

    except HTTPException:
        raise

    except Exception as exc:
        logger.warning("[RATE_LIMIT] Service check failed — allowing request: %s", exc)
