# core/idempotency.py
"""
Idempotency guard for fraud event processing.

Prevents the same event_id from being scored more than once.
Uses Redis SET NX (atomic check-and-set) as the fast path.
The DB unique index on fraud_decisions.event_id is the safety net
if Redis is temporarily unavailable.

Per-service TTLs are configured in idempotency_config.yaml:
  AUTH/ENROLL  24h — at-least-once Kafka redelivery window
  WALLET        7d — batch reconciliation retries can arrive days later
  CONSENT      48h — overnight batch retry window
"""

from pathlib import Path
from typing import Optional

from core.config_loader import HotConfig
from core.logger import logger
from storage.redis_client import redis_client

_idempotency_config = HotConfig(
    Path(__file__).parent.parent / "config/idempotency_ttl_config.yaml"
)


def _get_ttl(action_taxonomy: Optional[str]) -> int:
    cfg = _idempotency_config.get()
    ttls = cfg.get("ttl_seconds", {})
    from core.constants import TAXONOMY_TO_SERVICE  # avoid circular at module load
    service = TAXONOMY_TO_SERVICE.get(action_taxonomy or "", "default") if action_taxonomy else "default"
    return int(ttls.get(service, ttls.get("default", 86400)))


def is_duplicate(event_id: str, action_taxonomy: Optional[str] = None) -> bool:
    """
    Atomically check if event_id was already processed and mark it as seen.

    Returns True  → duplicate, skip processing.
    Returns False → new event, proceed with scoring.

    Fails open: if Redis is unavailable, returns False (proceed).
    The DB unique constraint on event_id catches any actual duplicates.
    """
    try:
        ttl = _get_ttl(action_taxonomy)
        key = f"idempotency:{event_id}"
        # SET NX: returns True if key was newly set, None if key already existed
        was_new = redis_client.set(key, "1", nx=True, ex=ttl)
        return was_new is None  # None = key existed = duplicate

    except Exception:
        logger.warning(
            "[IDEMPOTENCY] Redis check failed for event_id=%s — proceeding (DB constraint is fallback)",
            event_id,
        )
        return False  # fail-open
