from pathlib import Path
from typing import Optional
from core.config_loader import HotConfig
from core.logger import logger

_APP_DIR = Path(__file__).resolve().parent.parent
_profile_amp_config = HotConfig(_APP_DIR / "config/profile_amplifier.yaml")


def get_profile_amplifier(identity_profile: Optional[dict]) -> float:
    """
    Score multiplier from the subject's existing identity profile.
    A = 1 + (P_band - 1) * confidence, always >= 1.0.
    Returns 1.0 if disabled, no profile, or on any error (fail-open).
    """
    try:
        cfg = _profile_amp_config.get()
        if not cfg.get("enabled", True) or not identity_profile:
            return 1.0

        band = identity_profile.get("overall_risk_level")
        p_band = float((cfg.get("band_factors") or {}).get(band, 1.0))
        conf = min(1.0, max(0.0, float(identity_profile.get("confidence") or 0.0)))

        multiplier = round(max(1.0, 1.0 + (p_band - 1.0) * conf), 3)
        if multiplier > 1.0:
            logger.info("[PROFILE_AMP] band=%s conf=%.2f multiplier=%.3f",
                        band, conf, multiplier)
        return multiplier

    except Exception as exc:
        logger.warning("[PROFILE_AMP] failed, defaulting to 1.0: %s", exc)
        return 1.0


def invalidate_profile_amplifier() -> None:
    _profile_amp_config.invalidate()