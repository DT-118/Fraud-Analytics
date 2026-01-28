# core/settings.py
"""
Centralized configuration loader for fraud engine.

Loads:
- Feature activation thresholds (thresholds.yml)
- Redis TTL and memory windows (redis_ttl.yml)

These configs are consumed by feature builders only.
"""

import yaml
from core.errors import ErrorCode
from core.logger import logger


def _load_yaml_config(path: str, error_code: ErrorCode) -> dict:
    """
    Load a YAML configuration file with standardized error handling.
    """
    try:
        with open(path, "r") as file:
            return yaml.safe_load(file)

    except FileNotFoundError:
        logger.exception(
            "%s:CONFIG_FILE_MISSING path=%s",
            error_code,
            path,
        )
        print(f"[ERROR] {error_code}: CONFIG_FILE_MISSING -> {path}")
        raise RuntimeError(error_code)

    except yaml.YAMLError:
        logger.exception(
            "%s:CONFIG_PARSE_ERROR path=%s",
            error_code,
            path,
        )
        print(f"[ERROR] {error_code}: CONFIG_PARSE_ERROR -> {path}")
        raise RuntimeError(error_code)

    except Exception:
        logger.exception(
            "%s:CONFIG_LOAD_FAILURE path=%s",
            error_code,
            path,
        )
        print(f"[ERROR] {error_code}: CONFIG_LOAD_FAILURE -> {path}")
        raise RuntimeError(error_code)


# -------------------------------------------------
# Thresholds that control WHEN a feature activates
# -------------------------------------------------
THRESHOLDS = _load_yaml_config(
    "config/thresholds.yml",
    ErrorCode.INTERNAL_ERROR,
)

# -------------------------------------------------
# Redis TTLs defining memory windows for behavior
# -------------------------------------------------
REDIS_TTL = _load_yaml_config(
    "config/redis_ttl.yml",
    ErrorCode.INTERNAL_ERROR,
)
