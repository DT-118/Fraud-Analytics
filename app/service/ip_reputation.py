"""
ip_reputation.py

Manages the IP blocklist lifecycle across two sources: Redis (ip:flagged
set — the hot-path lookup used by features/ip_features.py) and Postgres
(ip_reputation table — durable record + audit trail).

Redis is seeded from the DB at startup, so the DB remains the durable
source of truth even though Redis is what's actually read at scoring time.

Seeding:
  seed_ip_blocklist_from_db(db_connection) is called once at startup
  (api.py lifespan) to warm the Redis set from the durable DB record.

Runtime writes:
  flag_ip() / unflag_ip() write through to both sources and are called
  from admin_api.py's POST /v2/admin/ip/flag and DELETE /v2/admin/ip/{ip}.

Runtime reads:
  list_flagged_ips() surfaces the current state of both sources plus
  drift between them, called from admin_api.py's GET /v2/admin/ip/flagged.
"""
from typing import Optional

from core.errors import ErrorCode
from core.logger import logger
from storage.redis_client import redis_client

REDIS_FLAGGED_KEY  = "ip:flagged"          # public — imported by admin_api
_REDIS_FLAGGED_KEY = REDIS_FLAGGED_KEY     # internal alias, preserves all usages below


# ---------------------------------------------------------------------------
# Runtime management — called at startup to warm the Redis set
# ---------------------------------------------------------------------------

def seed_ip_blocklist_from_db(db_connection) -> int:
    """
    Mirror the active ip_reputation table rows into Redis ip:flagged.

    Call at startup after DB connection is established. This is the sole
    seeding path now that the file source has been retired — Redis is
    ephemeral (can be flushed/restarted), so the DB row set is what
    reconstructs it.
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


def flag_ip(src_ip: str, reason: str, db_connection, flagged_by: Optional[str] = None) -> None:
    """
    Add an IP to both blocklist sources: Postgres (durable record + audit
    trail) and Redis (hot path lookup used by IP scoring).

    db_connection is required, not optional — Postgres is the only durable
    source now that config/ip_blocklist.txt has been retired. A Redis-only
    flag would silently vanish on the next Redis flush/restart with nothing
    to reseed it from, so this call refuses to produce that state.

    The DB write is authoritative and done first: any failure there raises
    immediately, so the caller (the admin API route) surfaces a real error
    instead of reporting success on a flag that was never durably recorded.
    The Redis write is best-effort and done second — Redis is a cache of
    the DB state, so a transient Redis failure here doesn't invalidate an
    otherwise-successful durable write; the next seed_ip_blocklist_from_db()
    call (or admin retry) will catch it up.
    """
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
        logger.info("[IP_REP] Flagged ip=%s reason=%s (db)", src_ip, reason)
    except Exception as exc:
        logger.error("[IP_REP] DB persist failed for ip=%s — flag NOT applied: %s", src_ip, exc)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc

    try:
        redis_client.sadd(_REDIS_FLAGGED_KEY, src_ip)
        logger.info("[IP_REP] Flagged ip=%s reason=%s (redis)", src_ip, reason)
    except Exception as exc:
        logger.warning(
            "[IP_REP] Redis flag failed for ip=%s — DB write succeeded, "
            "Redis will catch up on next seed: %s", src_ip, exc,
        )


def unflag_ip(src_ip: str, db_connection) -> bool:
    """
    Remove an IP from both blocklist sources: Postgres (is_active = FALSE —
    row kept for audit history, not deleted) and Redis.

    db_connection is required — see flag_ip() for why. DB failure raises;
    Redis failure is logged and best-effort, same ordering rationale as
    flag_ip().

    Returns True if the IP was found in the DB as an active flag (so the
    caller can 404 if it wasn't), False otherwise. Redis membership no
    longer factors into "found" — DB is the durable source of truth for
    whether an unflag request is meaningful.
    """
    sql = """
        UPDATE ip_reputation
        SET is_active = FALSE
        WHERE src_ip = %s AND is_active = TRUE
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (src_ip,))
            found = cur.rowcount > 0
        logger.info("[IP_REP] Unflagged ip=%s (db) found=%s", src_ip, found)
    except Exception as exc:
        logger.error("[IP_REP] DB unflag failed for ip=%s: %s", src_ip, exc)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc

    try:
        redis_client.srem(_REDIS_FLAGGED_KEY, src_ip)
        logger.info("[IP_REP] Unflagged ip=%s (redis)", src_ip)
    except Exception as exc:
        logger.warning(
            "[IP_REP] Redis unflag failed for ip=%s — DB updated, Redis "
            "will drift until next seed: %s", src_ip, exc,
        )

    return found


def list_flagged_ips(db_connection=None) -> dict:
    """
    Return the current flagged-IP state across both sources, plus drift
    between them — for admin visibility (GET /v2/admin/ip/flagged).

    Each source is read independently and fails open (empty list/set on
    error) so one source being unavailable never blocks visibility into
    the other — same fail-open posture as feature builders elsewhere in
    this engine.

    Returns:
      {
        "db":    [{"src_ip", "flag_reason", "flagged_by", "flagged_at"}],
                 — from Postgres, is_active = TRUE rows only, newest first.
                 Empty list if db_connection is not supplied or the query fails.
        "redis": [ip, ...]   — current members of the ip:flagged set (hot path
                 lookup actually used by IP_BLOCKLIST_MATCH scoring — this is ground truth
                 for what's blocking traffic *right now*).
        "drift": {
            "in_db_not_redis": [...],  — DB says blocked, Redis doesn't (IP_BLOCKLIST_MATCH not enforcing it!)
            "in_redis_not_db": [...],  — Redis blocking, no DB audit record
        }
      }

    "in_db_not_redis" is the one to watch — it means IP_BLOCKLIST_MATCH is silently NOT
    blocking an IP that the durable record says should be blocked (e.g. a
    Redis flush happened without a re-seed).
    """
    # ---- DB source ----
    db_rows: list[dict] = []
    if db_connection is not None:
        sql = """
            SELECT src_ip, flag_reason, flagged_by, flagged_at
            FROM ip_reputation
            WHERE is_active = TRUE
            ORDER BY flagged_at DESC
        """
        try:
            with db_connection.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchall()
            db_rows = [
                {
                    "src_ip":      r[0],
                    "flag_reason": r[1],
                    "flagged_by":  r[2],
                    "flagged_at":  r[3].isoformat() if r[3] else None,
                }
                for r in rows
            ]
        except Exception as exc:
            logger.warning("[IP_REP] list_flagged_ips DB read failed: %s", exc)
            db_rows = []
    else:
        logger.warning("[IP_REP] list_flagged_ips called without db_connection — db source empty")

    # ---- Redis source ----
    try:
        redis_ips = set(redis_client.smembers(_REDIS_FLAGGED_KEY) or [])
    except Exception as exc:
        logger.warning("[IP_REP] list_flagged_ips Redis read failed: %s", exc)
        redis_ips = set()

    db_ips = {row["src_ip"] for row in db_rows}

    drift = {
        "in_db_not_redis": sorted(db_ips - redis_ips),
        "in_redis_not_db": sorted(redis_ips - db_ips),
    }

    return {
        "db":    db_rows,
        "redis": sorted(redis_ips),
        "drift": drift,
    }