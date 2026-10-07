"""
Database connection accessors.

This module re-exports the connection-pool helpers so callers have one stable
import location without depending directly on the pool implementation.
"""

from storage.db_pool import (
    close_pool,
    get_db_connection,
    pooled_connection,
    release_db_connection,
    savepoint
)

__all__ = [
    "get_db_connection",
    "release_db_connection",
    "pooled_connection",
    "close_pool",
    "savepoint",
]
