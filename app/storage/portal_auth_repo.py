"""
storage/portal_auth_repo.py

Database repository for portal authentication. Single home for:

  1. Users            - account persistence and existence checks
  2. Password reset   - forgot/reset password tokens (password_reset_tokens)

Email OTPs are stateless (signed challenge + Redis counters, see
service/portal_auth_service.py) and are not stored in the database.

It is separate from fraud-event and fraud-scoring repositories.

Transaction notes:
  * User functions wrap DB failures in RuntimeError(ErrorCode.DATABASE_ERROR).
  * Password-reset functions take an open connection and do NOT commit;
    the caller owns commit/rollback.
"""

from __future__ import annotations
from typing import Optional
from core.errors import ErrorCode
from core.logger import logger
from psycopg2 import errors as pg_errors
from psycopg2.extras import RealDictCursor


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def create_user(
    db_connection,
    name: str,
    mobile: str,
    username: str,
    email: str,
    hashed_password: str,
    role: str,
) -> dict:
    """Create a portal user and return the persisted user fields."""
    sql = """
        INSERT INTO users (name, mobile, username, email, password, role)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id, name, mobile, username, email, role, created_at
    """

    try:
        with db_connection.cursor() as cur:
            cur.execute(
                sql,
                (name, mobile, username, email, hashed_password, role),
            )
            row = cur.fetchone()

        return {
            "id": str(row[0]),
            "name": row[1],
            "mobile": row[2],
            "username": row[3],
            "email": row[4],
            "role": row[5],
            "created_at": row[6].isoformat(),
        }

    except pg_errors.UniqueViolation:
        # Let the API layer turn this into a 409 (race between the
        # *_exists checks and the insert)
        raise

    except Exception as exc:
        logger.exception(
            "create_user failed username=%s",
            username,
        )
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def get_user_by_username(
    db_connection,
    username: str,
) -> Optional[dict]:
    """Return one portal user by username, or None when not found."""
    sql = """
        SELECT id, name, username, password, role, is_active
        FROM users
        WHERE username = %s
    """

    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (username,))
            row = cur.fetchone()

        if not row:
            return None

        return {
            "id": str(row[0]),
            "name": row[1],
            "username": row[2],
            "password": row[3],  # Stored hash; used only for password comparison.
            "role": row[4],
            "is_active": row[5],
        }

    except Exception as exc:
        logger.exception(
            "get_user_by_username failed username=%s",
            username,
        )
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def username_exists(db_connection, username: str) -> bool:
    """Return True when a username already exists."""
    try:
        with db_connection.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM users WHERE username = %s",
                (username,),
            )
            return cur.fetchone() is not None

    except Exception as exc:
        logger.exception(
            "username_exists failed username=%s",
            username,
        )
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def mobile_exists(db_connection, mobile: str) -> bool:
    """Return True when a mobile number already exists."""
    try:
        with db_connection.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM users WHERE mobile = %s",
                (mobile,),
            )
            return cur.fetchone() is not None

    except Exception as exc:
        logger.exception(
            "mobile_exists failed mobile=%s",
            mobile,
        )
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def email_exists(db_connection, email: str) -> bool:
    """Return True when an email address already exists."""
    try:
        with db_connection.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM users WHERE email = %s",
                (email,),
            )
            return cur.fetchone() is not None

    except Exception as exc:
        logger.exception(
            "email_exists failed email=%s",
            email,
        )
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


# ---------------------------------------------------------------------------
# Password reset (password_reset_tokens)
# ---------------------------------------------------------------------------


def find_user_for_reset(db, identifier: str):
    """
    Resolve an email or username to a user.
    Usernames are restricted to [a-zA-Z0-9_], so an '@' means it's an email.
    """
    if "@" in identifier:
        sql = "SELECT id, name, email, is_active FROM users WHERE email = %s"
        value = identifier.lower()
    else:
        sql = "SELECT id, name, email, is_active FROM users WHERE username = %s"
        value = identifier

    with db.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (value,))
        row = cur.fetchone()
    if row:
        row["id"] = str(row["id"])
    return row


def count_recent_tokens(db, user_id: str, window_minutes: int = 60) -> int:
    """Count reset tokens issued to the user within the window."""
    with db.cursor() as cur:
        cur.execute(
            """
            SELECT count(*) FROM password_reset_tokens
            WHERE user_id = %s
              AND created_at > now() - make_interval(mins => %s)
            """,
            (user_id, window_minutes),
        )
        return cur.fetchone()[0]


def invalidate_active_tokens(db, user_id: str) -> None:
    """Mark every unused token for this user as consumed."""
    with db.cursor() as cur:
        cur.execute(
            """
            UPDATE password_reset_tokens
               SET consumed_at = now()
             WHERE user_id = %s AND consumed_at IS NULL
            """,
            (user_id,),
        )


def create_reset_token(db, user_id: str, token_hash: str, valid_minutes: int) -> None:
    """Insert a new reset token that expires in valid_minutes."""
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, now() + make_interval(mins => %s))
            """,
            (user_id, token_hash, valid_minutes),
        )


def consume_reset_token(db, token_hash: str):
    """
    Atomically mark a valid token as used. Returns user_id (str) or None.
    Two concurrent requests with the same token cannot both succeed.
    """
    with db.cursor() as cur:
        cur.execute(
            """
            UPDATE password_reset_tokens
               SET consumed_at = now()
             WHERE token_hash = %s
               AND consumed_at IS NULL
               AND expires_at > now()
         RETURNING user_id
            """,
            (token_hash,),
        )
        row = cur.fetchone()
    return str(row[0]) if row else None


def update_user_password(db, user_id: str, hashed_password: str):
    """Set the new password for an active user. Returns (name, email) or None."""
    with db.cursor() as cur:
        cur.execute(
            """
            UPDATE users
               SET password = %s
             WHERE id = %s AND is_active
         RETURNING name, email
            """,
            (hashed_password, user_id),
        )
        return cur.fetchone()


def delete_expired_tokens(db) -> int:
    """Housekeeping: run from a cron/scheduled job."""
    with db.cursor() as cur:
        cur.execute(
            "DELETE FROM password_reset_tokens WHERE expires_at < now() - interval '1 day'"
        )
        return cur.rowcount