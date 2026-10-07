"""
Redis-backed idempotency guard for fraud-event processing.
The guard uses Redis SET with NX + EX as an atomic check-and-set operation:

    new event      -> key is created -> return False
    duplicate      -> key already exists -> return True

The per-service TTL is loaded from:
    config/idempotency_ttl_config.yaml

The database unique constraint on fraud_decisions.event_id remains the durable
safety net for duplicate persistence.

Important production behavior:
    Redis failure currently fails open so a Redis outage does not stop fraud
    scoring. This is an availability-first decision. It is not a guarantee
    that duplicate feature/profile side effects cannot occur during a Redis
    outage; the durable database constraint only protects persistence.

"""

from __future__ import annotations
from pathlib import Path

from core.config_loader import HotConfig
from core.constants import TAXONOMY_TO_SERVICE
from core.logger import logger
from storage.redis_client import redis_client


_DEFAULT_TTL_SECONDS = 86400  # 86400 seconds = 24 hours

_IDEMPOTENCY_CONFIG = HotConfig(
    Path(__file__).resolve().parent.parent
    / "config"
    / "idempotency_ttl_config.yaml"
)


def _get_ttl(action_taxonomy: str | None) -> int:
    """
    Resolve the idempotency TTL for an incoming action taxonomy.

    Unknown or missing taxonomies use the configured `default` TTL. The
    resulting TTL must be positive because Redis EX requires a positive
    expiration.

    Raises:
        ValueError: If the configured TTL is missing, invalid, or non-positive.
    """
    config = _IDEMPOTENCY_CONFIG.get()
    ttl_config = config.get("ttl_seconds", {})

    if not isinstance(ttl_config, dict):
        raise ValueError("idempotency ttl_seconds must be a mapping")

    service = TAXONOMY_TO_SERVICE.get(action_taxonomy or "", "default")
    configured_ttl = ttl_config.get(
        service,
        ttl_config.get("default", _DEFAULT_TTL_SECONDS),
    )

    try:
        ttl = int(configured_ttl)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid idempotency TTL for service={service!r}: {configured_ttl!r}"
        ) from exc

    if ttl <= 0:
        raise ValueError(
            f"Idempotency TTL must be greater than zero for service={service!r}"
        )

    return ttl


def release_idempotency(event_id: str) -> None:
    """Free the claim so a retry of a failed event is processed, not treated as a duplicate."""
    try:
        redis_client.delete(f"idempotency:{event_id}")
    except Exception:
        logger.exception("[IDEMPOTENCY] release failed event_id=%s", event_id)


def is_duplicate(
    event_id: str,
    action_taxonomy: str | None = None,
) -> bool:
    """
    Atomically check whether an event was already accepted for processing.

    Args:
        event_id: Stable upstream event identifier.
        action_taxonomy: Incoming taxonomy used to select the service TTL.

    Returns:
        True if the event was already seen.
        False if this is the first accepted occurrence or Redis is unavailable.

    Raises:
        ValueError: If event_id is empty or the configured TTL is invalid.

    Notes:
        Redis failure intentionally fails open. The database unique constraint
        is the durable duplicate safeguard, but Redis outages can still allow
        duplicate feature/profile side effects before persistence is rejected.
    """
    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError("event_id must be a non-empty string")

    ttl = _get_ttl(action_taxonomy)
    key = f"idempotency:{event_id}"

    try:
        # SET NX + EX is atomic. No separate EXISTS call is required, so two
        # concurrent consumers cannot both claim the same event in Redis.
        was_created = redis_client.set(
            key,
            "1",
            nx=True,#not-exists
            ex=ttl,
        )

        # Redis returns a truthy value when the key was created and a falsy
        # value when NX prevented creation because the key already existed.
        return not bool(was_created)

    except Exception:
        logger.exception(
            "[IDEMPOTENCY] Redis check failed; proceeding for event_id=%s",
            event_id,
        )
        return False