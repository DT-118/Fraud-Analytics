"""
Standard API response builders.

All successful and handled application-error responses use the same top-level
shape:

    {
        "success": bool,
        "message": str,
        "result": object | None,
    }

"""

from __future__ import annotations

from typing import Any

from core.errors import ERROR_MESSAGES, ErrorCode


def success_response(result: Any) -> dict[str, Any]:
    """Build the standard successful API response."""
    return {
        "success": True,
        "message": "SUCCESS",
        "result": result,
    }


def error_response(error_code: ErrorCode, result: Any = None) -> dict[str, Any]:
    """
    Build the standard handled-error response.

    ``ErrorCode.value`` is used deliberately. Using ``str(error_code)`` would
    expose the Python enum representation (for example,
    ``ErrorCode.DATABASE_ERROR``) rather than the public machine-readable code
    such as ``FE-501``.

    ``result`` is optional extra detail (field-level validation errors, the
    stored decision for a duplicate, ...). It stays ``None`` for plain failures.
    """
    message = ERROR_MESSAGES.get(error_code, "INTERNAL_ERROR")

    return {
        "success": False,
        "message": f"{error_code.value}:{message}",
        "result": result,
    }