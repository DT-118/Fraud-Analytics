from typing import Any
from core.errors import ErrorCode, ERROR_MESSAGES


def success_response(result: Any) -> dict:
    """
    Build a successful API response.
    """
    return {
        "success": True,
        "message": "SUCCESS",
        "result": result,
    }


def error_response(error_code: ErrorCode) -> dict:
    """
    Build a standardized error API response.
    """
    return {
        "success": False,
        "message": f"{error_code}:{ERROR_MESSAGES[error_code]}",
        "result": None,
    }
