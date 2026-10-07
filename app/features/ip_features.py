"""
IP reputation feature builder.

This feature checks the Redis IP blocklist maintained by the IP reputation
service and returns whether the event source IP is currently flagged.

Rule mapping:
    IP_BLOCKLIST_MATCH -> ip_is_flagged

Redis state:
    The ``ip:flagged`` set is maintained by the IP reputation service.
    This module performs a read-only membership check.

Fail-open behavior:
    Redis lookup failures return ``ip_is_flagged = 0`` so the IP rule does not
    fire when the reputation store is unavailable.

"""

from __future__ import annotations
from core.logger import logger
from service.ip_reputation import REDIS_FLAGGED_KEY
from storage.redis_client import redis_client


# IP_BLOCKLIST_MATCH
def build_ip_reputation_features(src_ip: str | None) -> dict:
    """Return whether the supplied source IP is present in the blocklist."""
    if not src_ip:
        return {"ip_is_flagged": 0}

    try:
        flagged = redis_client.sismember(
            REDIS_FLAGGED_KEY,
            src_ip,
        )

        return {"ip_is_flagged": int(bool(flagged))}

    except Exception as exc:
        logger.warning(
            "[IP_BLOCKLIST_MATCH] Redis lookup failed for ip=%s "
            "— fail-open: %s",
            src_ip,
            exc,
        )
        return {"ip_is_flagged": 0}