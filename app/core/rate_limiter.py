"""
Redis sliding-window rate limiter for the scoring API.

Two independent limits are enforced:
    1. Global: per API key across all services.
    2. Service: per API key and canonical service.

The limits and window are configured in:
    config/rate_limits.yaml

Redis admin overrides are stored in:
    rate:overrides

Production behavior:
    - Redis sorted sets implement the sliding window.
    - Each request gets a unique member, so requests in the same second are
      counted independently.
    - Redis failures fail open to preserve API availability.
    - Invalid rate-limit configuration fails closed for the configuration
      itself rather than silently applying an unsafe value.
    - API keys are hashed before being used in Redis keys; raw credentials are
      never written into Redis key names or log messages.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from pathlib import Path
from fastapi import HTTPException, Request, status
from core.config_loader import HotConfig
from core.constants import TAXONOMY_TO_SERVICE, VALID_SERVICES
from core.logger import logger
from storage.redis_client import redis_client


_RATE_LIMITS_CONFIG = HotConfig(
    Path(__file__).resolve().parent.parent / "config" / "rate_limits.yaml"
)

_REDIS_RATE_LIMIT_OVERRIDES_KEY = "rate:overrides"
_DEFAULT_GLOBAL_LIMIT = 2000
_DEFAULT_SERVICE_LIMIT = 600
_DEFAULT_WINDOW_SECONDS = 60


def _hash_api_key(api_key: str) -> str:
    """Return a stable non-reversible identifier suitable for a Redis key."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _validate_limit(value: object, name: str) -> int:
    """Validate one positive rate limit."""
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc

    if limit <= 0:
        raise ValueError(f"{name} must be greater than zero")

    return limit


def _validate_window(value: object) -> int:
    """Validate the configured sliding-window duration."""
    try:
        window = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("window_seconds must be an integer") from exc

    if window <= 0:
        raise ValueError("window_seconds must be greater than zero")

    return window


_RESERVED_RATE_LIMIT_KEYS = {"global", "default"}

def normalize_rate_limit_key(service_or_global: str) -> str:
     """Single source of truth for key casing, shared by admin_api.py's
     write path and this module's read path."""
     key = (service_or_global or "").strip()
     lowered = key.lower()
     if lowered in _RESERVED_RATE_LIMIT_KEYS:
         return lowered
     return key.upper()


def _fetch_rate_limit_overrides() -> dict[str, int]:
    """Fetch and validate runtime rate-limit overrides from Redis."""
    try:
        raw = redis_client.hgetall(_REDIS_RATE_LIMIT_OVERRIDES_KEY) or {}
        overrides: dict[str, int] = {}

        for key, value in raw.items():
            normalized_key = normalize_rate_limit_key(key)
            overrides[normalized_key] = _validate_limit(value, f"rate-limit override {normalized_key!r}")
        return overrides

    except Exception as exc:
        logger.warning(
            "[RATE_LIMIT] Override fetch failed; using YAML limits: %s",
            exc,
        )
        return {}


def _get_limits() -> tuple[int, dict[str, int], int]:
    """
    Return the effective global limit, per-service limits, and window.

    YAML values are the baseline. Valid Redis overrides take precedence.
    Unknown service override fields are ignored so an accidental stale Redis
    field cannot create an arbitrary service bucket.
    """
    config = _RATE_LIMITS_CONFIG.get()

    raw_per_service = config.get("per_service", {})
    if not isinstance(raw_per_service, dict):
        raise ValueError("rate_limits.yaml per_service must be a mapping")

    global_limit = _validate_limit(
        config.get("global", _DEFAULT_GLOBAL_LIMIT),
        "global rate limit",
    )
    window_seconds = _validate_window(
        config.get("window_seconds", _DEFAULT_WINDOW_SECONDS)
    )

    per_service = {
        service: _validate_limit(
            raw_per_service.get(service, _DEFAULT_SERVICE_LIMIT),
            f"rate limit for {service}",
        )
        for service in (*sorted(VALID_SERVICES), "default")
    }

    overrides = _fetch_rate_limit_overrides()

    if "global" in overrides:
        global_limit = overrides["global"]

    for service in VALID_SERVICES:
        if service in overrides:
            per_service[service] = overrides[service]

    if "default" in overrides:
        per_service["default"] = overrides["default"]

    return global_limit, per_service, window_seconds


def _queue_sliding_window(
    pipe,
    redis_key: str,
    now: int,
    window_seconds: int,
) -> None:
    """Queue the Redis commands required for one sliding-window counter."""
    window_start = now - window_seconds
    member = f"{now}:{uuid.uuid4().hex}"

    pipe.zremrangebyscore(redis_key, 0, window_start)
    pipe.zadd(redis_key, {member: now})
    pipe.zcard(redis_key)
    pipe.expire(redis_key, window_seconds + 1)


def _retry_after_seconds(redis_key: str, now: int, window_seconds: int, count: int, limit: int,) -> int:
    """
    Seconds until the client can actually be let through again.

    Rejected requests are also recorded in the window, so the next attempt needs
    (count - limit + 1) old entries to expire. That is the entry at index
    (count - limit) when sorted oldest first. It expires at score + window_seconds.
    Falls back to the full window if Redis can't answer.
    """
    try:
        entry = redis_client.zrange(redis_key, count - limit, count - limit, withscores=True)
        if entry:
            return max(1, int(entry[0][1]) + window_seconds - now)
    except Exception:
        pass
    return window_seconds


def _raise_rate_limit(
    service: str,
    limit: int,
    window_seconds: int,
    retry_after: int | None = None,
) -> None:
    """Raise the standardized HTTP 429 response for an exceeded limit."""
    scope = "Global" if service == "global" else f"Service {service}"
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=(
            f"{scope} rate limit exceeded: "
            f"{limit} requests/{window_seconds} seconds"
        ),
        headers={"Retry-After": str(retry_after or window_seconds)},
    )


def check_rate_limit(request: Request) -> None:
    """
    FastAPI dependency enforcing the global per-API-key rate limit.

    Redis failures fail open because rate limiting is a protective control and
    should not make the scoring API unavailable when Redis itself is unhealthy.
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        # Authentication is normally evaluated before this dependency. Keep
        # the fallback explicit for direct reuse/testing of this dependency.
        api_key = "anonymous"

    try:
        global_limit, _, window_seconds = _get_limits()
        now = int(time.time())
        redis_key = f"rate:global:{_hash_api_key(api_key)}"

        pipe = redis_client.pipeline()
        _queue_sliding_window(pipe, redis_key, now, window_seconds)
        results = pipe.execute()

        count = int(results[2])
        if count > global_limit:
            _raise_rate_limit(
                "global", global_limit, window_seconds,
                _retry_after_seconds(redis_key, now, window_seconds, count, global_limit),
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "[RATE_LIMIT] Global check failed; allowing request: %s",
            exc,
        )


def check_service_rate_limit(
    api_key: str,
    action_taxonomy: str | None,
) -> None:
    """
    Enforce the per-service limit after the request body has been parsed.

    Unknown or missing taxonomies use the configured default service bucket.
    Redis failures fail open.
    """
    if not api_key:
        api_key = "anonymous"

    service = TAXONOMY_TO_SERVICE.get(
        action_taxonomy or "",
        "default",
    )

    try:
        _, per_service, window_seconds = _get_limits()
        limit = per_service[service]
        now = int(time.time())

        redis_key = f"rate:service:{service}:{_hash_api_key(api_key)}"

        pipe = redis_client.pipeline()
        _queue_sliding_window(pipe, redis_key, now, window_seconds)
        results = pipe.execute()

        count = int(results[2])
        if count > limit:
            _raise_rate_limit(
                service, limit, window_seconds,
                _retry_after_seconds(redis_key, now, window_seconds, count, limit),
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "[RATE_LIMIT] Service check failed for service=%s; allowing request: %s",
            service,
            exc,
        )