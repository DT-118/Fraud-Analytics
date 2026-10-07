"""
odd_hour_activity_feature.py

Time-of-day fraud feature builder.

Rule:
    ODD_HOUR_ACTIVITY -> odd_hour_activity

Detects events occurring inside the configured IST off-hours window
(config/thresholds.yml). Generic across all services — AUTH/LOGIN/
CONSENT/WALLET.
"""

from __future__ import annotations

from pathlib import Path
from zoneinfo import ZoneInfo

from core.config_loader import HotConfig
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from rules.engine import is_rule_active

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# Feature-specific detection parameters. Not a scoring weight.
_THRESHOLDS_CONFIG = HotConfig(_CONFIG_DIR / "thresholds.yml")


def _thresholds() -> dict:
    """Return the current feature-threshold configuration."""
    return _THRESHOLDS_CONFIG.get()


def build_odd_hours_feature(
    context: Context,
    rule_overrides: dict,
    service: str,
) -> dict:
    """
    Detect events occurring inside the configured IST off-hours window.
    Works for ALL taxonomies (not AUTH-only).
    """
    try:
        if not is_rule_active("ODD_HOUR_ACTIVITY", service, rule_overrides):
            return {"odd_hour_activity": 0}

        threshold_config = _thresholds()["ODD_HOUR_ACTIVITY"]
        odd_start = int(threshold_config.get("odd_hour_start", 0))
        odd_end = int(threshold_config.get("odd_hour_end", 4))

        ist_time = context.event_time.astimezone(ZoneInfo("Asia/Kolkata"))

        if odd_start <= odd_end:
            is_odd_hour = odd_start <= ist_time.hour < odd_end
        else:
            is_odd_hour = ist_time.hour >= odd_start or ist_time.hour < odd_end

        return {"odd_hour_activity": int(is_odd_hour)}

    except Exception as exc:
        logger.exception(
            "%s: ODD_HOUR_ACTIVITY feature failure subject_id=%s",
            ErrorCode.INTERNAL_ERROR,
            context.subject_id,
        )
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc