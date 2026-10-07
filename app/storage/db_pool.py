"""
Thread-safe PostgreSQL connection pool.

Wraps psycopg2.pool.ThreadedConnectionPool so every request borrows
a connection from the pool rather than opening a new TCP socket.

Pool size is controlled by env vars:
  DB_POOL_MIN  (default 2)
  DB_POOL_MAX  (default 50)

Connection attempts time out after DB_CONNECT_TIMEOUT_SECONDS (default 5)
so a misconfigured/unreachable DB_HOST fails fast at startup instead of
hanging on the OS-level TCP timeout.

Callers must return connections via release_db_connection() or use
pooled_connection() as a context manager — never call .close() on a
pooled connection, as that destroys it rather than returning it.

On process shutdown, call close_pool() (wired into api.py's lifespan
shutdown phase) so pooled connections terminate cleanly on the Postgres
side rather than relying on the OS to notice a dead socket, which avoids
holding stale connection slots open during rolling deploys.
"""

import os
import threading
from contextlib import contextmanager
from psycopg2 import pool as pg_pool

from core.errors import ErrorCode
from core.logger import logger

_REQUIRED_ENV_VARS = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")


def _validate_db_env() -> None:
    """Validate environment variables required to create the pool."""
    missing = [name for name in _REQUIRED_ENV_VARS if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Set these before starting the fraud engine."
        )


def _create_pool() -> pg_pool.ThreadedConnectionPool:
    _validate_db_env()
    min_conn = int(os.environ.get("DB_POOL_MIN", 2))
    max_conn = int(os.environ.get("DB_POOL_MAX", 50))
    connect_timeout = int(os.environ.get("DB_CONNECT_TIMEOUT_SECONDS", 5))
    statement_timeout = int(os.environ.get("DB_STATEMENT_TIMEOUT_MS", 15000))
    lock_timeout = int(os.environ.get("DB_LOCK_TIMEOUT_MS", 5000))
    try:
        p = pg_pool.ThreadedConnectionPool(
            minconn=min_conn,
            maxconn=max_conn,
            host=os.environ["DB_HOST"],
            port=os.environ["DB_PORT"],
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            connect_timeout=connect_timeout,
            options=f"-c TimeZone=UTC -c statement_timeout={statement_timeout} -c lock_timeout={lock_timeout}",
        )
        logger.info(
            "[DB_POOL] Pool created min=%d max=%d connect_timeout=%ds",
            min_conn, max_conn, connect_timeout,
        )
        return p
    except Exception as exc:
        logger.exception("FE-501:DB_POOL_CREATION_FAILED")
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


_pool: pg_pool.ThreadedConnectionPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> pg_pool.ThreadedConnectionPool:
    """Return the singleton connection pool, creating it on first use."""
    global _pool

    # Fast path: no lock is needed after initialization.
    if _pool is not None:
        return _pool
    with _pool_lock:
        # Another thread may have initialized the pool while this thread waited.
        if _pool is None:
            _pool = _create_pool()
    return _pool


def get_db_connection():
    """Borrow a connection from the pool."""
    try:
        return get_pool().getconn()
    except Exception as exc:
        logger.exception("FE-501:DB_POOL_GETCONN_FAILED")
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def release_db_connection(conn) -> None:
    """
    Return a connection to the pool — or discard it if it's no longer usable.

    conn.closed is 0 while a connection is healthy. psycopg2 sets it to a
    nonzero value once it detects the underlying connection is broken (e.g.
    the network dropped mid-query, raising OperationalError) or has been
    explicitly closed elsewhere. Returning a broken connection to the pool
    via a plain putconn() would just hand the same dead socket to the next
    caller, who fails immediately too — even after Postgres/the network has
    recovered. putconn(conn, close=True) discards it instead, so the pool
    opens a fresh replacement connection the next time one is needed.

    This is centralized here deliberately, rather than requiring every one
    of this codebase's ~15 call sites to catch OperationalError and pass a
    close flag themselves — one check here covers all of them.
    """
    try:
        is_broken = bool(getattr(conn, "closed", 0))
        get_pool().putconn(conn, close=is_broken)
        if is_broken:
            logger.warning("[DB_POOL] Discarded broken connection instead of returning it to the pool")
    except Exception as exc:
        logger.warning("[DB_POOL] putconn failed: %s", exc)


@contextmanager
def pooled_connection():
    """Context manager that borrows and auto-returns a connection."""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        release_db_connection(conn)


def close_pool() -> None:
    """
    Close every connection in the pool and drop the singleton.

    Not required for correctness — the OS reclaims sockets on process exit
    regardless. This exists for *graceful* shutdown (SIGTERM during a
    rolling deploy): closing cleanly lets Postgres free the backend/slot
    immediately, rather than waiting out its TCP keepalive timeout for a
    connection the OS just yanked out from under it. Call from api.py's
    lifespan shutdown phase. Safe to call even if the pool was never
    created (no-op).
    """
    global _pool
    with _pool_lock:
        if _pool is not None:
            try:
                _pool.closeall()
                logger.info("[DB_POOL] Pool closed cleanly on shutdown")
            except Exception as exc:
                logger.warning("[DB_POOL] closeall() failed during shutdown: %s", exc)
            finally:
                _pool = None


@contextmanager
def savepoint(conn, name: str = "sp"):
    """
    Isolate a best-effort statement. If the block raises, roll back to the
    savepoint so the surrounding transaction stays usable, then re-raise.
    """
    with conn.cursor() as cur:
        cur.execute(f"SAVEPOINT {name}")
    try:
        yield
    except Exception:
        with conn.cursor() as cur:
            cur.execute(f"ROLLBACK TO SAVEPOINT {name}")
        raise
    else:
        with conn.cursor() as cur:
            cur.execute(f"RELEASE SAVEPOINT {name}")