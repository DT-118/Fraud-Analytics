"""
device_features.py

Cross-subject device trust scoring (Phase 4).

Tracks how many DISTINCT subjects have used the same device_id.
A device legitimately owned by one person will have subject_count = 1.
A shared fraud device used to impersonate multiple citizens will have
a high subject_count.

Redis key:  device:subjects:{device_id}   (SET, TTL 30 days)
Feature:    device_subject_count          (int — number of distinct subjects)

Rules that consume this feature (defined in rules YAML):
  DEVICE-01: device_subject_count >= 5   → weight 40  (shared device, suspicious)
  DEVICE-02: device_subject_count >= 15  → weight 70  (confirmed fraud device)

Fail-open: Redis failure returns count=0 so no rule fires.
"""

from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from storage.redis_client import redis_client

_DEVICE_TTL_SECONDS = 30 * 86400   # 30-day memory


def build_device_trust_features(context: Context) -> dict:
    """
    Return device_subject_count — the number of distinct subjects
    that have used the same device_id within the last 30 days.

    Applied to ALL service taxonomies because account takeover and
    identity fraud can span any service.
    """
    device_id = context.security_payload.device_id

    if not device_id:
        return {"device_subject_count": 0}

    try:
        key = f"device:subjects:{device_id}"

        redis_client.sadd(key, context.subject_id)
        redis_client.expire(key, _DEVICE_TTL_SECONDS)

        count = redis_client.scard(key)
        return {"device_subject_count": int(count)}

    except Exception as exc:
        logger.warning(
            "[DEVICE] Redis failure for device_id=%s — returning 0: %s", device_id, exc
        )
        return {"device_subject_count": 0}
