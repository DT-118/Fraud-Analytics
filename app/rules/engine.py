

# rules/engine.py

import json
import time
import yaml
from core.errors import ErrorCode
from core.logger import logger
from typing import Optional

_rule_cache: dict[str, dict] = {}
_rule_loaded_at: dict[str, float] = {}
_RULE_CACHE_TTL: float = 300.0  # 5 minutes

# Dynamic rule enable/disable override cache — Redis hash `rule:overrides`,
# read at most once per 30s. UNCHANGED from before — still global per rule_id,
# not per-service (pre-existing collision, out of scope for this change).
_overrides_cache: dict[str, str] = {}
_overrides_loaded_at: float = 0.0
_OVERRIDES_CACHE_TTL: float = 30.0

_REDIS_OVERRIDES_KEY = "rule:overrides"

# NEW: per-(service, rule_id) threshold overrides. No local caching — read
# directly from Redis on every rule evaluation so admin changes apply on the
# very next /v1/score call, matching the existing fail-open pattern used by
# ip_reputation.py / device_features.py.
_REDIS_THRESHOLD_OVERRIDES_KEY = "rule:threshold_overrides"


def _fetch_rule_overrides() -> dict[str, str]:
    """
    Fetch all dynamic rule enable/disable overrides from Redis hash
    `rule:overrides`. Result is cached for 30 seconds to avoid Redis
    round-trips on every event. Returns {} on any failure — no override
    means YAML `enabled` flag wins.
    """
    global _overrides_cache, _overrides_loaded_at

    now = time.monotonic()
    if now - _overrides_loaded_at < _OVERRIDES_CACHE_TTL:
        return _overrides_cache

    try:
        from storage.redis_client import redis_client
        # redis_client is built with decode_responses=True — all values are already str
        raw = redis_client.hgetall(_REDIS_OVERRIDES_KEY)
        overrides = dict(raw or {})
        _overrides_cache = overrides
        _overrides_loaded_at = now
        print(_overrides_cache)
        return _overrides_cache

    except Exception as exc:
        logger.warning("[RULES] Failed to fetch rule overrides from Redis — using YAML flags: %s", exc)
        _overrides_loaded_at = now  # back off for 30s to avoid hammering Redis
        return _overrides_cache


def _fetch_threshold_override(service: str, rule_id: str) -> Optional[list]:
    """
    Fetch a per-(service, rule_id) threshold-band override, if one is set.

    No local caching — this is a direct Redis read on every evaluation of
    this rule, so a PUT/DELETE from the admin API is reflected on the very
    next /v1/score call, same request, no propagation delay.

    Fails open: any Redis error (or missing key) returns None, meaning the
    caller should fall back to the YAML-defined thresholds.
    """
    try:
        from storage.redis_client import redis_client
        raw = redis_client.hget(_REDIS_THRESHOLD_OVERRIDES_KEY, f"{service}:{rule_id}")
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning(
            "[RULES] Failed to fetch threshold override for %s:%s — using YAML thresholds: %s",
            service, rule_id, exc,
        )
        return None


def _is_rule_enabled(rule_id: str, yaml_enabled: bool, overrides: dict[str, str]) -> bool:
    """
    Resolve whether a rule should run.

    Priority: Redis override > YAML enabled flag.
      "disabled" in Redis → skip regardless of YAML
      "enabled"  in Redis → run  regardless of YAML
      Not in Redis         → use YAML enabled flag
    """
    override = overrides.get(rule_id)
    if override == "disabled":
        return False
    if override == "enabled":
        return True
    return yaml_enabled


def _validate_rule_thresholds(rule_id: str, thresholds: list) -> None:
    """
    Validate that threshold bands (as loaded from YAML) are ordered
    correctly (ascending min values) and that no bands overlap.
    Logs a warning but does not raise — a misconfigured YAML rule fires
    as-is rather than silently disappearing.

    NOTE: this is the lenient, log-only check used at YAML load time.
    For strict validation of admin-supplied override payloads (which
    should reject bad input with a 422 instead of just logging), see
    validate_threshold_payload() below.
    """
    if not thresholds or len(thresholds) < 2:
        return
    for i in range(1, len(thresholds)):
        prev_min = float(thresholds[i - 1].get("min", 0))
        curr_min = float(thresholds[i].get("min", 0))
        if curr_min <= prev_min:
            logger.warning(
                "[RULES] Rule %s: threshold band %d (min=%s) is not greater than band %d (min=%s) — "
                "bands may be mis-ordered; first matching band wins",
                rule_id, i, curr_min, i - 1, prev_min,
            )


def validate_threshold_payload(thresholds: list) -> Optional[str]:
    """
    Strict validation for admin-supplied threshold override payloads
    (PUT /v2/admin/rules/{service}/{rule_id}/thresholds).

    Unlike _validate_rule_thresholds() above, this REJECTS bad input by
    returning an error string instead of just logging a warning — admin
    writes should fail loudly with a 422, not silently misbehave later
    during scoring.

    Rules enforced:
      - non-empty list
      - every band has 'min' and 'weight'
      - 'weight' is an int in [0, 100]
      - bands, sorted by min, do not overlap
      - at most one band may be open-ended (no 'max'), and it must be last

    Returns None if valid, otherwise a human-readable error message.
    """
    if not thresholds or not isinstance(thresholds, list):
        return "thresholds must be a non-empty list"

    try:
        sorted_bands = sorted(thresholds, key=lambda b: float(b.get("min", 0)))
    except (TypeError, ValueError):
        return "every band's 'min' must be numeric"

    prev_max: Optional[float] = None
    for i, band in enumerate(sorted_bands):
        if "min" not in band or "weight" not in band:
            return f"band {i} is missing required field 'min' or 'weight'"

        try:
            band_min = float(band["min"])
            weight = int(band["weight"])
        except (TypeError, ValueError):
            return f"band {i} has a non-numeric 'min' or 'weight'"

        if not (0 <= weight <= 100):
            return f"band {i} weight ({weight}) must be between 0 and 100"

        if prev_max is not None and band_min <= prev_max:
            return f"band {i} min ({band_min}) overlaps the previous band's max ({prev_max})"

        if band.get("max") is not None:
            try:
                band_max = float(band["max"])
            except (TypeError, ValueError):
                return f"band {i} has a non-numeric 'max'"
            if band_max < band_min:
                return f"band {i} max ({band_max}) is less than min ({band_min})"
            prev_max = band_max
        else:
            # open-ended band — only the last band is allowed to be open-ended
            if i != len(sorted_bands) - 1:
                return f"band {i} has no 'max' but is not the last band"
            prev_max = None

    return None


def load_rules(rules_file_path: str) -> dict:
    """
    Load fraud rules from YAML with in-memory caching.
    Reloads from disk at most once every 5 minutes.
    Falls back to stale cache on reload failure so scoring is never blocked.
    """
    now = time.monotonic()
    cached_at = _rule_loaded_at.get(rules_file_path, 0.0)

    if rules_file_path in _rule_cache and (now - cached_at) < _RULE_CACHE_TTL:
        return _rule_cache[rules_file_path]

    try:
        with open(rules_file_path) as file:
            rules_config = yaml.safe_load(file)

        if not rules_config or "rules" not in rules_config:
            raise ValueError("Invalid rules configuration structure")

        # Validate threshold ordering for every enabled rule
        for rule_id, rule_def in rules_config.get("rules", {}).items():
            if rule_def.get("enabled", False):
                _validate_rule_thresholds(rule_id, rule_def.get("thresholds", []))

        _rule_cache[rules_file_path] = rules_config
        _rule_loaded_at[rules_file_path] = now
        logger.info("[RULES] Loaded rules from %s", rules_file_path)
        return _rule_cache[rules_file_path]

    except Exception as exc:
        if rules_file_path in _rule_cache:
            logger.warning(
                "[RULES] Reload failed for %s — using stale cache", rules_file_path
            )
            return _rule_cache[rules_file_path]
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Failed to load rules file")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc


def evaluate_rule(
    rule_id: str,
    rule_definition: dict,
    feature_values: dict,
    thresholds_override: Optional[list] = None,
) -> Optional[dict]:
    """
    Evaluate a single fraud rule against computed feature values.

    thresholds_override: if provided (i.e. an admin override is active for
    this service/rule), these bands are used INSTEAD OF rule_definition's
    YAML thresholds. Everything else about evaluation is unchanged.

    Returns a dictionary containing rule_id and weight if triggered,
    otherwise None.
    """
    try:
        feature_name  = rule_definition["feature"]
        feature_value = feature_values.get(feature_name)

        if feature_value is None:
            return None

        thresholds = (
            thresholds_override if thresholds_override is not None
            else rule_definition["thresholds"]
        )

        for threshold_band in thresholds:
            minimum_value = float(threshold_band["min"])
            maximum_value = threshold_band.get("max", None)

            if maximum_value is not None:
                maximum_value = float(maximum_value)
                if minimum_value <= feature_value <= maximum_value:
                    return {"rule_id": rule_id, "weight": threshold_band["weight"]}
            else:
                if feature_value >= minimum_value:
                    return {"rule_id": rule_id, "weight": threshold_band["weight"]}

    except Exception as exc:
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Rule evaluation failure for {rule_id}")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc


def run_rules(rule_config: dict, feature_values: dict, service: str) -> list:
    """
    Execute all enabled fraud rules against the extracted feature set.

    
    Every existing call site (wherever run_rules(rule_config, feature_values)
    is currently called in the scoring pipeline) must be updated to pass the
    service name (e.g. "AUTH", "WALLET") so threshold overrides can be looked
    up under the right namespaced key. This file does not contain those call
    sites — search the codebase for `run_rules(` and update each one.

    Dynamic enable/disable overrides are fetched from Redis hash
    `rule:overrides` (cached 30s, unchanged from before):
      "disabled" → skip rule even if YAML says enabled
      "enabled"  → run  rule even if YAML says disabled

    Dynamic per-service threshold overrides are fetched from Redis hash
    `rule:threshold_overrides` (NEW, no caching, read fresh per rule):
      present → use override bands instead of YAML thresholds
      absent  → use YAML thresholds

    Returns a list of triggered rule dictionaries containing rule_id and weight.
    """
    triggered_rules: list = []
    overrides = _fetch_rule_overrides()

    try:
        for rule_id, rule_definition in rule_config["rules"].items():
            yaml_enabled = rule_definition.get("enabled", False)
            if not _is_rule_enabled(rule_id, yaml_enabled, overrides):
                continue

            threshold_override = _fetch_threshold_override(service, rule_id)
            evaluation_result = evaluate_rule(
                rule_id, rule_definition, feature_values, threshold_override
            )

            if evaluation_result:
                triggered_rules.append(evaluation_result)

        return triggered_rules

    except Exception as exc:
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Rule execution failure")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc


def apply_chains(
    rules_config: dict,
    triggered_rules: list,
    role: Optional[str] = None,
) -> list:
    """
    Apply rule chain definitions from the YAML chains section.

    A chain boosts the weight of a target rule when all its trigger rules
    have already fired.  This models compounding fraud signals — e.g.
    a new device (AUTH-04) combined with login failures (AUTH-01) is
    much stronger evidence than either signal alone.

    IMPORTANT: Chains compound multiplicatively.  If two chains both target
    the same rule (e.g., ×1.5 and ×1.6), the final weight is
    original × 1.5 × 1.6 = original × 2.4.  This is intentional — the
    presence of multiple correlated signals is itself a fraud signal.

    The `role` parameter is accepted for future suppression logic but
    chain compounding is currently not suppressed by role — role modifiers
    are applied to the final weights in compute_event_score instead.

    Returns a new list — the originals are never mutated.
    If no chains are defined, returns the input list unchanged.
    """
    chains = rules_config.get("chains", [])
    if not chains:
        return triggered_rules

    try:
        triggered_ids = {r["rule_id"] for r in triggered_rules}

        result: dict[str, dict] = {r["rule_id"]: dict(r) for r in triggered_rules}
        for rid in result:
            result[rid]["base_weight"] = result[rid]["weight"]   # snapshot before any chain boost
            result[rid]["chain_reason"] = None

        for chain in chains:
            trigger_set = set(chain.get("trigger_rules", []))
            target_id   = chain.get("target_rule")
            multiplier  = float(chain.get("weight_multiplier", 1.0))
            reason      = chain.get("reason", "CHAIN")

            if not trigger_set or not target_id:
                continue

            if trigger_set.issubset(triggered_ids) and target_id in result:
                original_weight = result[target_id]["weight"]
                boosted_weight  = int(original_weight * multiplier)
                result[target_id]["weight"]       = boosted_weight
                result[target_id]["chain_reason"] = reason
                logger.info(
                    "[RULES] Chain applied: triggers=%s target=%s weight %d→%d reason=%s",
                    trigger_set, target_id, original_weight, boosted_weight, reason,
                )

        return list(result.values())

    except Exception as exc:
        logger.warning("[RULES] apply_chains failed — returning unchained rules: %s", exc)
        return triggered_rules