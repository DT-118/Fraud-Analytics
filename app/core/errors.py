"""
errors.py

Centralized error codes and messages for Fraud Engine.
"""

from enum import Enum


class ErrorCode(str, Enum):
    INVALID_REQUEST = "FE-400"
    INTERNAL_ERROR = "FE-500"
    DB_ERROR = "FE-501"
    REDIS_ERROR = "FE-502"
    KAFKA_ERROR = "FE-503"
    RULE_ENGINE_ERROR = "FE-510"


ERROR_MESSAGES = {
    ErrorCode.INVALID_REQUEST: "INVALID_REQUEST",
    ErrorCode.INTERNAL_ERROR: "INTERNAL_ERROR",
    ErrorCode.DB_ERROR: "DATABASE_FAILURE",
    ErrorCode.REDIS_ERROR: "REDIS_FAILURE",
    ErrorCode.KAFKA_ERROR: "KAFKA_FAILURE",
    ErrorCode.RULE_ENGINE_ERROR: "RULE_EVALUATION_FAILED",
}
