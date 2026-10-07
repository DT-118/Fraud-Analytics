"""
Service layer for portal user administration.

Business rules for listing portal users and changing their roles. Sits
between the admin API router and storage.user_admin_repo. Never commits 
the caller owns the transaction.
"""

from __future__ import annotations

from typing import Optional

from storage import user_admin_repo as repo

# Mirrors users_role_check in the users table.
PORTAL_ROLES = frozenset({"ADMIN", "SERVICE_PROVIDER"})


class UserAdminError(Exception):
    """Base class for expected, caller-facing failures."""


class InvalidRoleError(UserAdminError):
    pass


class UserNotFoundError(UserAdminError):
    pass


class LastAdminError(UserAdminError):
    pass


class ProtectedUserError(UserAdminError):
    """The target account's role is not editable at all.

    Distinct from LastAdminError: that one is a transient constraint about
    how many admins exist, this one is a permanent property of the account.
    """


def _normalize_role(role: str) -> str:
    normalized = (role or "").strip().upper()
    if normalized not in PORTAL_ROLES:
        raise InvalidRoleError(
            f"Invalid role '{role}'. Must be one of {sorted(PORTAL_ROLES)}"
        )
    return normalized


def _is_protected(user: dict) -> bool:
    """True if this account's role must never be changed.

    Compares against the casefolded mirror of the repo's hidden-name set
    because the SQL filter in list_users() matches with ILIKE. Both sides
    have to agree on case, or an account renamed to a different casing would
    vanish from listings while quietly becoming editable again.
    """
    return (user.get("name") or "").casefold() in repo.HIDDEN_DISPLAY_NAMES_CASEFOLDED


def list_users(
    db_connection,
    *,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    role_filter = _normalize_role(role) if role else None
    search_term = search.strip() if search else None

    # repo.list_users applies repo.HIDDEN_DISPLAY_NAMES in SQL, so the
    # `total` returned here already accounts for the hidden account — no
    # post-filtering at this layer, which would desync total from the page.
    users, total = repo.list_users(
        db_connection,
        role=role_filter,
        is_active=is_active,
        search=search_term or None,
        limit=limit,
        offset=offset,
    )
    return {"total": total, "limit": limit, "offset": offset, "users": users}


def get_user(db_connection, user_id: str) -> dict:
    user = repo.get_user_by_id(db_connection, user_id)
    if user is None:
        raise UserNotFoundError(f"User {user_id} not found")
    return user


def change_user_role(
    db_connection,
    *,
    target_id: str,
    new_role: str,
) -> dict:
    """
    Change a user's role. Rules:
      - role must be a valid portal role
      - accounts in repo.HIDDEN_DISPLAY_NAMES (the root admin) cannot be
        re-roled at all, in either direction
      - the last active ADMIN cannot be demoted (checked under row locks, so
        two concurrent demotions can't leave zero admins)
      - setting the role a user already has is a no-op
    Returns {"changed", "previous_role", "user"}.
    """
    role = _normalize_role(new_role)

    target, active_admins = repo.lock_target_and_active_admins(db_connection, target_id)
    if target is None:
        raise UserNotFoundError(f"User {target_id} not found")

    # Checked before the no-op and last-admin rules so a protected account
    # always reports the accurate reason, even when it is also the only
    # remaining admin.
    if _is_protected(target):
        raise ProtectedUserError(
            f"Role of protected account '{target['name']}' cannot be changed"
        )

    previous_role = target["role"]
    if previous_role == role:
        return {"changed": False, "previous_role": previous_role, "user": target}

    if previous_role == "ADMIN" and target["is_active"] and active_admins <= 1:
        raise LastAdminError("Cannot demote the last active ADMIN")

    updated = repo.update_user_role(db_connection, target_id, role)
    return {"changed": True, "previous_role": previous_role, "user": updated}
