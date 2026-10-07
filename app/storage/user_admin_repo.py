"""
Database repository for portal user administration.

Read access to portal users and role updates. Separate from
portal_auth_repo.py (registration / login). Never returns the password hash
and never commits the caller owns the transaction.
"""

from __future__ import annotations

from typing import Optional

from core.errors import ErrorCode
from core.logger import logger

_USER_COLUMNS = "id, name, mobile, username, email, role, is_active, created_at"


HIDDEN_DISPLAY_NAMES: frozenset[str] = frozenset({"Administrator"})


HIDDEN_DISPLAY_NAMES_CASEFOLDED: frozenset[str] = frozenset(
    n.casefold() for n in HIDDEN_DISPLAY_NAMES
)


def _row_to_user(row) -> dict:
    return {
        "id": str(row[0]),
        "name": row[1],
        "mobile": row[2],
        "username": row[3],
        "email": row[4],
        "role": row[5],
        "is_active": row[6],
        "created_at": row[7].isoformat(),
    }


def _escape_like(value: str) -> str:
    
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_users(
    db_connection,
    role: Optional[str],
    is_active: Optional[bool],
    search: Optional[str],
    limit: int,
    offset: int,
) -> tuple[list[dict], int]:
    
    conditions: list[str] = ["NOT (name ILIKE ANY(%s))"]
    params: list = [list(HIDDEN_DISPLAY_NAMES)]

    if role is not None:
        conditions.append("role = %s")
        params.append(role)
    if is_active is not None:
        conditions.append("is_active = %s")
        params.append(is_active)
    if search:
        pattern = f"%{_escape_like(search)}%"
        conditions.append("(username ILIKE %s OR name ILIKE %s OR email ILIKE %s)")
        params.extend([pattern, pattern, pattern])

    where = f"WHERE {' AND '.join(conditions)}"
    count_sql = f"SELECT COUNT(*) FROM users {where}"
    list_sql = (
        f"SELECT {_USER_COLUMNS} FROM users {where} "
        "ORDER BY created_at DESC, id LIMIT %s OFFSET %s"
    )

    try:
        with db_connection.cursor() as cur:
            cur.execute(count_sql, params)
            total = cur.fetchone()[0]

            cur.execute(list_sql, params + [limit, offset])
            rows = cur.fetchall()

        return [_row_to_user(r) for r in rows], total

    except Exception as exc:
        logger.exception("list_users failed")
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def get_user_by_id(db_connection, user_id: str) -> Optional[dict]:
    
    sql = f"SELECT {_USER_COLUMNS} FROM users WHERE id = %s"

    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (user_id,))
            row = cur.fetchone()

        return _row_to_user(row) if row else None

    except Exception as exc:
        logger.exception("get_user_by_id failed user_id=%s", user_id)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def lock_target_and_active_admins(
    db_connection,
    target_id: str,
) -> tuple[Optional[dict], int]:
    
    sql = f"""
        SELECT {_USER_COLUMNS}
        FROM users
        WHERE id = %s OR (role = 'ADMIN' AND is_active)
        ORDER BY id
        FOR UPDATE
    """

    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (target_id,))
            rows = cur.fetchall()

        target: Optional[dict] = None
        active_admins = 0
        for row in rows:
            user = _row_to_user(row)
            if user["id"] == target_id:
                target = user
            if user["role"] == "ADMIN" and user["is_active"]:
                active_admins += 1

        return target, active_admins

    except Exception as exc:
        logger.exception("lock_target_and_active_admins failed target=%s", target_id)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def update_user_role(db_connection, user_id: str, role: str) -> dict:
    
    sql = f"""
        UPDATE users
        SET role = %s
        WHERE id = %s
        RETURNING {_USER_COLUMNS}
    """

    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (role, user_id))
            row = cur.fetchone()

        return _row_to_user(row)

    except Exception as exc:
        logger.exception("update_user_role failed user_id=%s role=%s", user_id, role)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc
