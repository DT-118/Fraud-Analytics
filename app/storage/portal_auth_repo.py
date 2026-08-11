"""
auth_repo.py

DB queries for user auth — completely separate from fraud scoring tables.
"""

from typing import Optional
from core.errors import ErrorCode
from core.logger import logger


def create_user(
    db_connection,
    name: str,
    mobile: str,
    username: str,
    hashed_password: str,
    role: str,
) -> dict:
    sql = """
        INSERT INTO users (name, mobile, username, password, role)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, name, mobile, username, role, created_at
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (name, mobile, username, hashed_password, role))
            row = cur.fetchone()
        db_connection.commit()
        return {
            "id":         str(row[0]),
            "name":       row[1],
            "mobile":     row[2],
            "username":   row[3],
            "role":       row[4],
            "created_at": row[5].isoformat(),
        }
    except Exception as exc:
        db_connection.rollback()
        logger.exception("create_user failed username=%s", username)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc


def get_user_by_username(db_connection, username: str) -> Optional[dict]:
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
            "id":          str(row[0]),
            "name":        row[1],
            "username":    row[2],
            "password":    row[3],   # hashed — only used for bcrypt compare
            "role":        row[4],
            "is_active":   row[5],
        }
    except Exception as exc:
        logger.exception("get_user_by_username failed username=%s", username)
        raise RuntimeError(ErrorCode.DB_ERROR) from exc


def username_exists(db_connection, username: str) -> bool:
    with db_connection.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        return cur.fetchone() is not None


def mobile_exists(db_connection, mobile: str) -> bool:
    with db_connection.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE mobile = %s", (mobile,))
        return cur.fetchone() is not None