"""
Fraud score calculation and risk classification engine.

Responsibilities:
    - Load baseline scoring configuration through HotConfig.
    - Apply administrator-managed risk-band overrides from Redis.
    - Apply role-based rule-weight modifiers.
    - Apply exception-code scoring.
    - Calculate the final event score.
    - Classify the final score into a configured risk band.

Configuration:
    scoring/scores.yaml
        Baseline final-score risk bands.

    config/role_modifiers_config.yaml
        Baseline role-based rule modifiers.

    config/exception_scores.yaml
        Baseline exception-code scores.

Runtime administrator overrides are read directly from Redis so changes apply
to the next scoring request without waiting for a local cache.

"""

import json
from pathlib import Path
from typing import Optional
import math
from core.config_loader import HotConfig
from core.errors import ErrorCode
from core.logger import logger
from storage.redis_client import redis_client

_APP_DIR = Path(__file__).resolve().parent.parent
_scores_config: HotConfig | None = None



# NEW: risk-band override, written by PUT /v2/admin/scoring/risk-bands.
# No local caching — read directly from Redis on every classify_risk() call
# so admin changes apply on the very next /v1/score call. Global (not
# per-service), since risk bands classify a single 0-100 score space shared
# by every service.
_REDIS_BAND_OVERRIDES_KEY = "score:band_overrides"
_REQUIRED_RISK_BANDS = {"NORISK", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_DEFAULT_SCORES_PATH = str(_APP_DIR / "scoring/scores.yaml")


def load_scores(scores_file_path: str) -> dict:
    global _scores_config
    if _scores_config is None:
        _scores_config = HotConfig(Path(scores_file_path))

    try:
        score_config = _scores_config.get()
    except RuntimeError as exc:
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Failed to load scoring config")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc

    if not score_config or "risk_bands" not in score_config:
        logger.error(f"{ErrorCode.INTERNAL_ERROR}: Invalid scoring configuration structure")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR)

    return score_config


def invalidate_scores() -> None:
    """Invalidate the cached score configuration.called in admin_api"""
    if _scores_config is not None:
        _scores_config.invalidate()


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

    Returns None if valid, otherwise a human-readable error message.called in admin_api.
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

def _fetch_band_override() -> Optional[dict]:
    """
    Fetch the global risk-band override, if one is set.

    No local caching — direct Redis read on every classify_risk() call, so
    an admin PUT/DELETE is reflected on the very next /v1/score call.
    Fails open: any Redis error (or missing key) returns None, meaning the
    caller should fall back to the YAML-defined bands (scores.yaml).
    """
    try:
        raw = redis_client.get(_REDIS_BAND_OVERRIDES_KEY)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning(
            "[SCORING] Failed to fetch risk-band override — using YAML bands: %s", exc
        )
        return None


# ---------------------------------------------------------------------------
# Role-based weight modifiers
# ---------------------------------------------------------------------------
# Baseline modifiers are loaded from YAML through HotConfig. Runtime
# administrator overrides are stored in Redis and read directly for each
# scoring request.
# ---------------------------------------------------------------------------

_role_modifiers_config = HotConfig(_APP_DIR / "config/role_modifiers_config.yaml")

# Redis key used by the administration layer for role/rule overrides.
_REDIS_ROLE_MODIFIER_OVERRIDES_KEY = "score:role_modifier_overrides"


def validate_role_modifier_value(value) -> Optional[str]:
    """
    Strict validation for admin-supplied role-modifier override payloads
    (PUT /v2/admin/scoring/role-modifiers/{role}/{rule_id}).

    Role modifiers are a dampening-only mechanism — a value outside 0.0-1.0
    would mean either a no-op negative weight or an amplification that no
    other part of this engine's role-modifier semantics support.

    Returns None if valid, otherwise a human-readable error message.called in admin_api.
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "value must be numeric"
    if not (0.0 <= v <= 1.0):
        return f"value ({v}) must be between 0.0 and 1.0"
    return None


def _fetch_role_modifier_override(role: str, rule_id: str) -> Optional[float]:
    """
    Fetch a single (role, rule_id) modifier override, if one is set.

    No local caching — direct Redis read, same fail-open pattern as
    _fetch_band_override() / _fetch_scoring_override() below. Returns None
    on any Redis error or missing key, meaning the caller should fall back
    to the YAML-defined modifier.
    """
    try:
        raw = redis_client.hget(_REDIS_ROLE_MODIFIER_OVERRIDES_KEY, f"{role}:{rule_id}")
        return float(raw) if raw is not None else None
    except Exception as exc:
        logger.warning(
            "[SCORING] role modifier override fetch failed role=%s rule=%s — using YAML: %s",
            role, rule_id, exc,
        )
        return None


def _get_role_modifier(rule_id: str, role: Optional[str]) -> float:
    """
    Resolve the weight modifier for a (rule_id, role) pair.

    Priority (highest first):
      1. Redis override for this exact (role, rule_id)
      2. Redis override for (role, "__all__")
      3. YAML "__all__" entry for this role (silences every rule for that
         role — same precedence as the original hardcoded behavior)
      4. YAML entry for this exact (role, rule_id)
      5. Default: 1.0 (full weight — no dampening)

    No role → 1.0 (unchanged behavior).
    """
    if not role:
        return 1.0

    role_key = role.upper()

    override = _fetch_role_modifier_override(role_key, rule_id)
    if override is not None:
        return override

    override_all = _fetch_role_modifier_override(role_key, "__all__")
    if override_all is not None:
        return override_all

    yaml_modifiers = _role_modifiers_config.get().get(role_key, {}) or {}

    if "__all__" in yaml_modifiers:
        return float(yaml_modifiers["__all__"].get("value", 0.0))

    rule_cfg = yaml_modifiers.get(rule_id)
    if rule_cfg is not None:
        return float(rule_cfg.get("value", 1.0))

    return 1.0


# ---------------------------------------------------------------------------
# Exception-code scoring
# ---------------------------------------------------------------------------
_exception_scores_config = HotConfig(_APP_DIR / "config/exception_scores.yaml")


_REDIS_SCORING_OVERRIDES_KEY = "score:exception_score_overrides"

def _fetch_scoring_override(exception_code: str) -> Optional[float]:
    """No local cache — fresh Redis read every call, matches band/threshold pattern."""
    try:
        raw = redis_client.hget(_REDIS_SCORING_OVERRIDES_KEY, exception_code)
        return float(raw) if raw is not None else None
    except Exception as exc:
        logger.warning("[SCORING] score override fetch failed code=%s — using YAML: %s", exception_code, exc)
        return None


def _get_exception_scoring(exception_code: Optional[str]) -> float:
    """Resolve an exception score from Redis override or YAML baseline."""
    if not exception_code:
        return 0.0
    override = _fetch_scoring_override(exception_code)
    if override is not None:
        return override
    scorings = _exception_scores_config.get()
    code_cfg = scorings.get(exception_code)
    if not code_cfg:
        return 0.0
    return float(code_cfg.get("value", 0.0))



# ---------------------------------------------------------------------------
# Event score calculation
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
    3. Apply exception scorer (caller-reported anomaly, from YAML)
    4. Cap at 100

    Returns a dict with final_score, raw_score, and adjustments.
    """
    try:
        exception_score = _get_exception_scoring(exception_code)

        role_adjusted_weights: dict[str, dict] = {}
        raw_score = 0

        for rule in triggered_rules:
            rule_id  = rule["rule_id"]
            modifier = _get_role_modifier(rule_id, role)
            adjusted = int(rule["weight"] * modifier)
            role_adjusted_weights[rule_id] = {
                "weight":        adjusted,
                "base_weight":   rule.get("base_weight", rule["weight"]),
                "chain_multiplier": rule.get("chain_multiplier"),
                "chain_reason":  rule.get("chain_reason"),
                "role_modifier": modifier,
            }
            raw_score += adjusted

        amplified_score = int(raw_score + exception_score)
        final_score     = max(0, min(100, amplified_score))

        return {
            "final_score":           final_score,
            "raw_score":             raw_score,
            "exception_score":   exception_score,
            "role_adjusted_weights": role_adjusted_weights,
        }

    except Exception as exc:
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: Score computation failed")
        raise RuntimeError(ErrorCode.INTERNAL_ERROR) from exc


def apply_session_amplifier(score: int, session_amplifier: float) -> int:
    """Apply the session-level multiplier and cap the result at 100."""
    return min(100, int(score * session_amplifier))

def get_effective_risk_bands() -> dict:
     """Redis override if set, else scores.yaml default — the single
     source of truth for band boundaries used everywhere outside the
     main scoring path."""
     try:
        override = _fetch_band_override()
        if override is not None:
             return override
     except Exception:
         pass
     return load_scores(_DEFAULT_SCORES_PATH)["risk_bands"]

def classify_score_band(score: float) -> str:
    """
    Classify a float score by rounding to the nearest whole number first
    (.5 rounds up), then matching the integer bands.
    29.4 -> 29 -> LOW, 29.6 -> 30 -> MEDIUM, 59.5 -> 60 -> HIGH.
    """
    bands = get_effective_risk_bands()
    rounded = math.floor(max(0.0, min(100.0, float(score))) + 0.5)

    for risk_level, bounds in bands.items():
        if bounds[0] <= rounded <= bounds[1]:
            return risk_level
    return "UNKNOWN"


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