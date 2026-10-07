"""
Login feature builders.

These features maintain short-lived login behavior state in Redis and
return values consumed by login fraud rules.

Rule mapping:
    LOGIN_DOCUMENT_UDB_MISMATCH -> document_udb_mismatch_count

"""
from __future__ import annotations
from pathlib import Path
from core.config_loader import HotConfig
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from rules.engine import is_rule_active
from storage.redis_client import redis_client
from storage.redis_utils import touch

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# Redis behavioral-state retention. Values are expressed in seconds.
_REDIS_TTL_CONFIG = HotConfig(_CONFIG_DIR / "redis_ttl.yml")


def _redis_ttl() -> dict:
    """Return the current Redis feature-retention configuration."""
    return _REDIS_TTL_CONFIG.get()


# LOGIN_DOCUMENT_UDB_MISMATCH
def build_document_udb_mismatch_feature(
    context: Context,
    rule_overrides: dict,
) -> int:
    """Count document-to-UDB mismatches within the configured retention window."""
    try:
        if not is_rule_active(
            "LOGIN_DOCUMENT_UDB_MISMATCH",
            "LOGIN",
            rule_overrides,
        ):
            return 0

        payload = context.document_payload
        if not payload or payload.document_udb_matched:
            return 0

        redis_key = f"login:document:udb_matched:{context.subject_id}"
        window_seconds = int(_redis_ttl()["login"]["doc_fail_window"])

        failure_count = redis_client.incr(redis_key)
        touch(redis_key, window_seconds)

        return int(failure_count)

    except Exception as exc:
        logger.exception(
            "%s: LOGIN_DOCUMENT_UDB_MISMATCH Redis failure subject_id=%s",
            ErrorCode.REDIS_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.REDIS_ERROR) from exc


def build_login_features(
    context: Context,
    rule_overrides: dict,
) -> dict:
    """Build and return all login-related features."""
    return {
        "document_udb_mismatch_count": build_document_udb_mismatch_feature(
            context,
            rule_overrides,
        ),
    }