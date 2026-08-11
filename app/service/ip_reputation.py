"""
ip_reputation.py

IP reputation checking (Phase 4).

Redis set  ip:flagged  holds all blocked IPs (seeded at startup from
config/ip_blocklist.txt, managed at runtime via the DB ip_reputation table).

Feature returned:
  ip_is_flagged  — 1 if the src_ip is in the blocked set, 0 otherwise

Rule that consumes this feature (defined in rules YAML):
  IP-01: ip_is_flagged >= 1 → weight 50

Fail-open: Redis failure returns ip_is_flagged=0 so no rule fires.
The scoring path is never blocked by reputation lookup failure.

Seeding:
  Call seed_ip_blocklist_from_db(db_connection) once at startup to
  mirror the ip_reputation table into the Redis ip:flagged set.
"""

import os
from pathlib import Path
from typing import Optional

from core.errors import ErrorCode
from core.logger import logger
from storage.redis_client import redis_client

REDIS_FLAGGED_KEY  = "ip:flagged"          # public — imported by admin_api
_REDIS_FLAGGED_KEY = REDIS_FLAGGED_KEY     # internal alias, preserves all usages below
_BLOCKLIST_FILE    = str(Path(__file__).parent.parent / "config/ip_blocklist.txt")


# ---------------------------------------------------------------------------
# Feature builder
# ---------------------------------------------------------------------------

def build_ip_reputation_features(src_ip: Optional[str]) -> dict:
    """
    Return ip_is_flagged = 1 if src_ip is in the Redis blocked set.
    Always returns a dict — never raises.
    """
    if not src_ip:
        return {"ip_is_flagged": 0}

    try:
        flagged = redis_client.sismember(_REDIS_FLAGGED_KEY, src_ip)
        return {"ip_is_flagged": 1 if flagged else 0}

    except Exception as exc:
        logger.warning("[IP_REP] Redis lookup failed for ip=%s — returning 0: %s", src_ip, exc)
        return {"ip_is_flagged": 0}


# ---------------------------------------------------------------------------
# Runtime management — called at startup to warm the Redis set
# ---------------------------------------------------------------------------

def seed_ip_blocklist_from_file() -> int:
    """
    Load IPs from config/ip_blocklist.txt into the Redis ip:flagged set.

    File format: one IP per line, lines starting with # are comments.
    Returns the number of IPs loaded.  Called once at startup.
    """
    if not os.path.exists(_BLOCKLIST_FILE):
        logger.info("[IP_REP] No ip_blocklist.txt found — skipping seed")
        return 0

    try:
        ips = []
        with open(_BLOCKLIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.append(line)

        if ips:
            redis_client.sadd(_REDIS_FLAGGED_KEY, *ips)
            logger.info("[IP_REP] Seeded %d IPs into Redis from blocklist file", len(ips))

        return len(ips)

    except Exception as exc:
        logger.warning("[IP_REP] Blocklist file seed failed: %s", exc)
        return 0


def seed_ip_blocklist_from_db(db_connection) -> int:
    """
    Mirror the active ip_reputation table rows into Redis ip:flagged.

    Call at startup after DB connection is established.
    Returns the number of IPs loaded.
    """
    sql = "SELECT src_ip FROM ip_reputation WHERE is_active = TRUE"
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()

        ips = [r[0] for r in rows]
        if ips:
            redis_client.sadd(_REDIS_FLAGGED_KEY, *ips)
            logger.info("[IP_REP] Seeded %d IPs into Redis from DB", len(ips))

        return len(ips)

    except Exception as exc:
        logger.warning("[IP_REP] DB seed failed — Redis ip:flagged may be empty: %s", exc)
        return 0


def flag_ip(src_ip: str, reason: str, flagged_by: Optional[str] = None,
            db_connection=None) -> None:
    """
    Add an IP to the Redis blocked set and optionally persist to DB.

    Intended for use by the fraud operations team or an admin API.
    """
    try:
        redis_client.sadd(_REDIS_FLAGGED_KEY, src_ip)
        logger.info("[IP_REP] Flagged ip=%s reason=%s", src_ip, reason)
    except Exception as exc:
        logger.warning("[IP_REP] Redis flag failed for ip=%s: %s", src_ip, exc)

    if db_connection:
        sql = """
            INSERT INTO ip_reputation (src_ip, flag_reason, flagged_by)
            VALUES (%s, %s, %s)
            ON CONFLICT (src_ip) DO UPDATE SET
                flag_reason = EXCLUDED.flag_reason,
                flagged_by  = EXCLUDED.flagged_by,
                flagged_at  = NOW(),
                is_active   = TRUE
        """
        try:
            with db_connection.cursor() as cur:
                cur.execute(sql, (src_ip, reason, flagged_by))
        except Exception as exc:
            logger.warning("[IP_REP] DB persist failed for ip=%s: %s", src_ip, exc)
