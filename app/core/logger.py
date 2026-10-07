"""
Central application logging configuration.

This module exposes the shared ``logger`` used by the fraud engine. It does
not call ``load_dotenv()`` and does not configure the process-wide root logger:
environment loading and top-level logging ownership belong to the application
entry point/deployment.

The module:
    - reads LOG_LEVEL from the environment;
    - validates the configured level;
    - configures only the fraud-engine logger;
    - avoids adding duplicate handlers when imported multiple times.
"""

from __future__ import annotations

import logging
import os


_DEFAULT_LOG_LEVEL = logging.INFO
_LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


def _resolve_log_level(value: str | None) -> tuple[int, bool]:
    """Resolve LOG_LEVEL and report whether the supplied value was valid."""
    if not value:
        return _DEFAULT_LOG_LEVEL, True

    normalized = value.strip().upper()
    level = getattr(logging, normalized, None)

    if isinstance(level, int):
        return level, True

    return _DEFAULT_LOG_LEVEL, False


def _configure_logger() -> logging.Logger:
    """Create the shared fraud-engine logger without modifying the root logger."""
    configured_level = os.getenv("LOG_LEVEL", "INFO")
    level, is_valid = _resolve_log_level(configured_level)

    application_logger = logging.getLogger("fraud-engine")

    application_logger.setLevel(level)
    application_logger.propagate = False

    if not application_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        application_logger.addHandler(handler)

    if not is_valid:
        application_logger.warning(
            "Invalid LOG_LEVEL=%r; falling back to INFO",
            configured_level,
        )

    return application_logger


logger = _configure_logger()
