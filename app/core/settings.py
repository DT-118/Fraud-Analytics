# core/settings.py
"""
Centralized configuration loader for fraud engine.

Loads:
- Feature activation thresholds (thresholds.yml)
- Redis TTL and memory windows (redis_ttl.yml)

Paths are resolved relative to this file so the engine can be
launched from any working directory.
"""

from pathlib import Path

import yaml
from core.errors import ErrorCode
from core.logger import logger

_CONFIG_DIR = Path(__file__).parent.parent / "config"


def _load_yaml_config(path: Path, error_code: ErrorCode) -> dict:
    try:
        with open(path) as file:
            return yaml.safe_load(file)

    except FileNotFoundError as err:
        logger.exception(
            "%s:CONFIG_FILE_MISSING path=%s",
            error_code,
            path,
        )
        raise RuntimeError(error_code) from err

    except yaml.YAMLError as err:
        logger.exception(
            "%s:CONFIG_PARSE_ERROR path=%s",
            error_code,
            path,
        )
        raise RuntimeError(error_code) from err

    except Exception as err:
        logger.exception(
            "%s:CONFIG_LOAD_FAILURE path=%s",
            error_code,
            path,
        )
        raise RuntimeError(error_code) from err


# -------------------------------------------------
# Thresholds that control WHEN a feature activates
# -------------------------------------------------
THRESHOLDS = _load_yaml_config(
    _CONFIG_DIR / "thresholds.yml",
    ErrorCode.INTERNAL_ERROR,
)

# -------------------------------------------------
# Redis TTLs defining memory windows for behavior
# -------------------------------------------------
REDIS_TTL = _load_yaml_config(
    _CONFIG_DIR / "redis_ttl.yml",
    ErrorCode.INTERNAL_ERROR,
)
