"""
Thread-safe PostgreSQL connection pool.

Wraps psycopg2.pool.ThreadedConnectionPool so every request borrows
a connection from the pool rather than opening a new TCP socket.

Pool size is controlled by env vars:
  DB_POOL_MIN  (default 2)
  DB_POOL_MAX  (default 10)

Callers must return connections via release_db_connection() or use
pooled_connection() as a context manager — never call .close() on a
pooled connection, as that destroys it rather than returning it.
"""

from dotenv import load_dotenv

load_dotenv()

import os
import threading
from contextlib import contextmanager

import psycopg2
from psycopg2 import pool as pg_pool

from core.errors import ErrorCode
from core.logger import logger

_REQUIRED_ENV_VARS = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")


def _validate_db_env() -> None:
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Set these before starting the fraud engine."
        )


def _create_pool() -> pg_pool.ThreadedConnectionPool:
    _validate_db_env()
    min_conn = int(os.environ.get("DB_POOL_MIN", 2))
    max_conn = int(os.environ.get("DB_POOL_MAX", 50))
    try:
        p = pg_pool.ThreadedConnectionPool(
            minconn=min_conn,
            maxconn=max_conn,
            host=os.environ["DB_HOST"],
            port=os.environ["DB_PORT"],
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
        )
        logger.info("[DB_POOL] Pool created min=%d max=%d", min_conn, max_conn)
        return p
    except Exception as exc:
        logger.exception("FE-501:DB_POOL_CREATION_FAILED")
        raise RuntimeError(ErrorCode.DB_ERROR) from exc


_pool: pg_pool.ThreadedConnectionPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> pg_pool.ThreadedConnectionPool:
    global _pool
    # Fast path — no lock needed once initialized
    if _pool is not None:
        return _pool
    with _pool_lock:
        # Double-check: another thread may have created the pool while we waited
        if _pool is None:
            _pool = _create_pool()
    return _pool


def get_db_connection():
    """Borrow a connection from the pool."""
    try:
        return get_pool().getconn()
    except Exception as exc:
        logger.exception("FE-501:DB_POOL_GETCONN_FAILED")
        raise RuntimeError(ErrorCode.DB_ERROR) from exc


def release_db_connection(conn) -> None:
    """Return a connection to the pool. Always call this instead of conn.close()."""
    try:
        get_pool().putconn(conn)
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
