"""
Database connection accessor.

Re-exports get_db_connection from db_pool so all callers import from
the same place regardless of whether they use the pool or not.
"""

from storage.db_pool import get_db_connection, release_db_connection, pooled_connection

__all__ = ["get_db_connection", "release_db_connection", "pooled_connection"]
