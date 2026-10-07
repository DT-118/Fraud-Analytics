"""
Centralized application error codes for the fraud analytics engine.

Error codes are part of the application's observable contract: they can
appear in logs, API responses, monitoring, and integration diagnostics.

Do not create ad-hoc string error codes in individual modules. Add a new
code here only when the error represents a distinct, reusable failure class.
"""

from __future__ import annotations
from enum import Enum


class ErrorCode(str, Enum):
    """Stable machine-readable error codes exposed by the application."""

    INVALID_REQUEST = "FE-400"
    UNAUTHORIZED = "FE-401"
    NOT_FOUND = "FE-404"
    DUPLICATE_EVENT = "FE-409"
    RATE_LIMITED = "FE-429"
    INTERNAL_ERROR = "FE-500"
    DATABASE_ERROR = "FE-501"
    REDIS_ERROR = "FE-502"
    KAFKA_ERROR = "FE-503"
    RULE_ENGINE_ERROR = "FE-510"


# Human-readable/logging identifiers corresponding to each public error code.
# Keep these stable because dashboards and log searches may depend on them.
ERROR_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.INVALID_REQUEST: "INVALID_REQUEST",
    ErrorCode.UNAUTHORIZED: "UNAUTHORIZED",
    ErrorCode.NOT_FOUND: "NOT_FOUND",
    ErrorCode.DUPLICATE_EVENT: "DUPLICATE_EVENT",
    ErrorCode.RATE_LIMITED: "RATE_LIMITED",
    ErrorCode.INTERNAL_ERROR: "INTERNAL_ERROR",
    ErrorCode.DATABASE_ERROR: "DATABASE_FAILURE",
    ErrorCode.REDIS_ERROR: "REDIS_FAILURE",
    ErrorCode.KAFKA_ERROR: "KAFKA_FAILURE",
    ErrorCode.RULE_ENGINE_ERROR: "RULE_EVALUATION_FAILED",
}