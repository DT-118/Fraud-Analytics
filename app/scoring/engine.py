


# scoring/engine.py
import json
import time
import warnings
from pathlib import Path
from typing import Optional

import yaml

from core.config_loader import HotConfig
from core.errors import ErrorCode
from core.logger import logger

_APP_DIR = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# In-memory score config cache (scores.yaml — risk band definitions)
# ---------------------------------------------------------------------------
_scores_cache: dict = {}
_scores_loaded_at: float = 0.0
_SCORES_CACHE_TTL: float = 300.0

# NEW: risk-band override, written by PUT /v2/admin/scoring/risk-bands.
# No local caching — read directly from Redis on every classify_risk() call
# so admin changes apply on the very next /v1/score call. Global (not
# per-service), since risk bands classify a single 0-100 score space shared
# by every service.
_REDIS_BAND_OVERRIDES_KEY = "score:band_overrides"

_REQUIRED_RISK_BANDS = {"NORISK", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def load_scores(scores_file_path: str) -> dict:
    """
    Load scoring configuration from YAML with in-memory caching.
    Reloads from disk at most once every 5 minutes.
    Falls back to stale cache if reload fails.
    """
    global _scores_cache, _scores_loaded_at

    now = time.monotonic()
    if _scores_cache and (now - _scores_loaded_at) < _SCORES_CACHE_TTL:
        return _scores_cache

    try:
        with open(scores_file_path) as file:
            score_config = yaml.safe_load(file)

        if not score_config or "risk_bands" not in score_config:
            raise ValueError("Invalid scoring configuration structure")

        _scores_cache = score_config
        _scores_loaded_at = now
        return _scores_cache

    except Exception as exc:
        if _scores_cache:
            logger.warning("[SCORING] Reload failed — using stale cache")
            return _scores_cache
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Failed to load scoring config")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def _fetch_band_override() -> Optional[dict]:
    """
    Fetch the global risk-band override, if one is set.

    No local caching — direct Redis read on every classify_risk() call, so
    an admin PUT/DELETE is reflected on the very next /v1/score call.
    Fails open: any Redis error (or missing key) returns None, meaning the
    caller should fall back to the YAML-defined bands (scores.yaml).
    """
    try:
        from storage.redis_client import redis_client
        raw = redis_client.get(_REDIS_BAND_OVERRIDES_KEY)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning(
            "[SCORING] Failed to fetch risk-band override — using YAML bands: %s", exc
        )
        return None


def validate_risk_bands(bands: dict) -> Optional[str]:
    """
    Strict validation for admin-supplied risk-band override payloads
    (PUT /v2/admin/scoring/risk-bands).

    Unlike thresholds (per-rule, independent), risk bands are one
    interlocking whole — every call must supply the complete set, covering
    0-100 with no gaps or overlaps, since classify_risk() needs every
    possible score to land in exactly one band.

    Rules enforced:
      - exactly the 5 required band names, no more, no less
      - each value is a [min, max] pair
      - lowest band starts at 0, highest band ends at 100
      - bands are contiguous when sorted by min (prev_max + 1 == next_min)
      - no band has min > max

    Returns None if valid, otherwise a human-readable error message.
    """
    if set(bands.keys()) != _REQUIRED_RISK_BANDS:
        missing = _REQUIRED_RISK_BANDS - set(bands.keys())
        extra = set(bands.keys()) - _REQUIRED_RISK_BANDS
        parts = []
        if missing:
            parts.append(f"missing: {sorted(missing)}")
        if extra:
            parts.append(f"unexpected: {sorted(extra)}")
        return f"risk bands must be exactly {sorted(_REQUIRED_RISK_BANDS)} — " + "; ".join(parts)

    try:
        entries = sorted(
            ((float(v[0]), float(v[1]), k) for k, v in bands.items()),
            key=lambda x: x[0],
        )
    except (TypeError, IndexError, ValueError, KeyError):
        return "each band must be a [min, max] pair of numbers"

    for lo, hi, name in entries:
        if lo > hi:
            return f"{name}: min ({lo}) is greater than max ({hi})"

    if entries[0][0] != 0:
        return f"lowest band ({entries[0][2]}) must start at 0, got {entries[0][0]}"
    if entries[-1][1] != 100:
        return f"highest band ({entries[-1][2]}) must end at 100, got {entries[-1][1]}"

    for i in range(1, len(entries)):
        prev_max = entries[i - 1][1]
        curr_min = entries[i][0]
        if curr_min != prev_max + 1:
            return (
                f"gap or overlap between {entries[i - 1][2]} (max={prev_max}) "
                f"and {entries[i][2]} (min={curr_min}) — bands must be contiguous"
            )

    return None


# ---------------------------------------------------------------------------
# Role-based weight modifiers (unchanged — no external config needed;
# role policy is tightly coupled to UAE identity law and changes rarely)
# ---------------------------------------------------------------------------
_ROLE_RULE_MODIFIERS: dict[str, dict[str, float]] = {
    "VISITOR": {
        "AUTH-04": 0.0,
        "AUTH-05": 0.0,
        "AUTH-08": 0.2,
        "AUTH-09": 0.3,
    },
    "RESIDENT": {
        "AUTH-04": 0.7,
        "AUTH-05": 0.5,
        "AUTH-08": 0.6,
        "AUTH-09": 0.7,
    },
    "AGENT": {
        "AUTH-09": 0.0,
        "AUTH-04": 0.5,
        "AUTH-08": 0.5,
    },
    "ADMIN": {
        "AUTH-09": 0.0,
        "AUTH-04": 0.5,
    },
    "SYSTEM": {
        "__all__": 0.0,
    },
}


def _get_role_modifier(rule_id: str, role: Optional[str]) -> float:
    if not role:
        return 1.0
    modifiers = _ROLE_RULE_MODIFIERS.get(role.upper(), {})
    if "__all__" in modifiers:
        return 0.0
    return modifiers.get(rule_id, 1.0)


# ---------------------------------------------------------------------------
# Exception code amplifiers — loaded from exception_amplifiers.yaml
# ---------------------------------------------------------------------------
_amplifiers_config = HotConfig(_APP_DIR / "config/exception_amplifiers.yaml")


def _get_exception_amplifier(exception_code: Optional[str]) -> float:
    if not exception_code:
        return 1.0
    amplifiers = _amplifiers_config.get()
    return float(amplifiers.get(exception_code, 1.0))


# ---------------------------------------------------------------------------
# Phase 2 scoring entry point
# ---------------------------------------------------------------------------
def compute_event_score(
    triggered_rules: list,
    role: Optional[str] = None,
    exception_code: Optional[str] = None,
    service: Optional[str] = None,
) -> dict:
    """
    Compute the final fraud score for a single event.

    Steps:
    1. Apply role modifiers to each triggered rule's weight
    2. Sum role-adjusted weights (raw_score)
    3. Apply exception amplifier (caller-reported anomaly, from YAML)
    4. Cap at 100

    Returns a dict with final_score, raw_score, and adjustments.
    """
    try:
        exception_amplifier = _get_exception_amplifier(exception_code)

        role_adjusted_weights: dict[str, dict] = {}
        raw_score = 0

        for rule in triggered_rules:
            rule_id  = rule["rule_id"]
            modifier = _get_role_modifier(rule_id, role)
            adjusted = int(rule["weight"] * modifier)
            role_adjusted_weights[rule_id] = {
                "weight":        adjusted,
                "base_weight":   rule.get("base_weight", rule["weight"]),
                "chain_reason":  rule.get("chain_reason"),
                "role_modifier": modifier,
            }
            raw_score += adjusted

        amplified_score = int(raw_score * exception_amplifier)
        final_score     = min(100, amplified_score)

        return {
            "final_score":           final_score,
            "raw_score":             raw_score,
            "exception_amplifier":   exception_amplifier,
            "role_adjusted_weights": role_adjusted_weights,
        }

    except Exception as exc:
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Score computation failed")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def apply_session_amplifier(score: int, session_amplifier: float) -> int:
    """Apply the session-level multiplier to the post-scoring score."""
    return min(100, int(score * session_amplifier))


def classify_risk(total_score: int, score_cfg: dict) -> str:
    """
    Classify a numerical fraud score into a risk band.

    Checks the Redis-backed admin override first (score:band_overrides);
    falls back to score_cfg["risk_bands"] (scores.yaml) if no override is
    set or Redis is unreachable.
    """
    try:
        risk_bands = _fetch_band_override() or score_cfg["risk_bands"]
        for risk_level, bounds in risk_bands.items():
            lower_bound, upper_bound = bounds[0], bounds[1]
            if lower_bound <= total_score <= upper_bound:
                return risk_level
        return "UNKNOWN"

    except Exception as exc:
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Risk classification failure")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def aggregate_score(triggered_rules: list) -> int:
    """DEPRECATED — use compute_event_score().  Will be removed 2026-09-01."""
    warnings.warn(
        "aggregate_score() is deprecated; use compute_event_score() instead. "
        "Scheduled removal: 2026-09-01.",
        DeprecationWarning,
        stacklevel=2,
    )
    total = sum(rule["weight"] for rule in triggered_rules)
    return min(total, 100)