"""Fraud rule loading, activation, evaluation, and chain engine.

This module loads service rule definitions through the shared HotConfig loader,
resolves administrator runtime overrides from Redis, evaluates rules against
computed features, and applies configured rule chains.

Runtime behavior:
    - YAML rule files are managed by HotConfig and its configured reload TTL.
    - Rule enable/disable overrides are read from Redis for each event.
    - Threshold overrides are read directly from Redis for each rule evaluation.
    - Redis override failures fail open to the YAML configuration.

Rule identifiers are meaningful names and must match the rule YAML files,
feature builders, scoring layer, and administration layer.

"""

import json
from core.errors import ErrorCode
from core.logger import logger
from typing import Optional
from storage.redis_client import redis_client
from pathlib import Path
from core.config_loader import HotConfig


_REDIS_OVERRIDES_KEY = "rule:overrides"
_REDIS_THRESHOLD_OVERRIDES_KEY = "rule:threshold_overrides"
SERVICE_RULE_PATHS: dict[str, str] = {
    "AUTH":    str(Path(__file__).parent.parent / "config/rules/auth_rules.yaml"),
    "LOGIN":  str(Path(__file__).parent.parent / "config/rules/login_rules.yaml"),
    "CONSENT": str(Path(__file__).parent.parent / "config/rules/consent_rules.yaml"),
    "WALLET":  str(Path(__file__).parent.parent / "config/rules/wallet_rules.yaml"),
}
_rule_configs: dict[str, HotConfig] = {
    path: HotConfig(Path(path)) for path in SERVICE_RULE_PATHS.values()
}


def fetch_rule_overrides() -> dict[str, str]:
    """
    ONE Redis HGETALL. Call exactly once per event, then thread the
    returned dict through every feature-builder and into run_rules().
    No caching, no TTL — this call itself is the freshness guarantee.
    Fail-open: {} on Redis error, meaning every rule falls through to YAML.
    """
    try:
        raw = redis_client.hgetall(_REDIS_OVERRIDES_KEY)
        return dict(raw or {})
    except Exception as exc:
        logger.warning("[RULES] Failed to fetch rule overrides — using YAML flags: %s", exc)
        return {}


def _fetch_threshold_override(service: str, rule_id: str) -> Optional[list]:
    """
    Fetch a per-(service, rule_id) threshold-band override, if one is set.
    No local caching — this is a direct Redis read on every evaluation of
    this rule, so a PUT/DELETE from the admin API is reflected on the very
    next /v2/score call, same request, no propagation delay.
    Fails open: any Redis error (or missing key) returns None, meaning the
    caller should fall back to the YAML-defined thresholds.
    """
    try:
        raw = redis_client.hget(_REDIS_THRESHOLD_OVERRIDES_KEY, f"{service}:{rule_id}")
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        override = json.loads(raw)
        if not isinstance(override, list):
            return None
        return override
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
      - 'min' and 'max' cannot exceed 100
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

        if band_min > 100:
            return f"band {i} min ({band_min}) must not exceed 100"

        if not (0 <= weight <= 100):
            return f"band {i} weight ({weight}) must be between 0 and 100"

        if prev_max is not None and band_min <= prev_max:
            return f"band {i} min ({band_min}) overlaps the previous band's max ({prev_max})"

        if band.get("max") is not None:
            try:
                band_max = float(band["max"])
            except (TypeError, ValueError):
                return f"band {i} has a non-numeric 'max'"

            if band_max > 100:
                return f"band {i} max ({band_max}) must not exceed 100"

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
    Load fraud rules with HotConfig-backed caching (5-min TTL, invalidate()
    forces reload). Validation (structure + threshold ordering) stays here;
    caching itself is delegated to HotConfig — no duplicate cache logic.
    """
    if rules_file_path not in _rule_configs:
        _rule_configs[rules_file_path] = HotConfig(Path(rules_file_path))

    try:
        rules_config = _rule_configs[rules_file_path].get()
    except RuntimeError as exc:
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Failed to load rules file")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc

    if not rules_config or "rules" not in rules_config:
        logger.error("%s: Invalid rules structure in %s", ErrorCode.RULE_ENGINE_ERROR, rules_file_path)
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR)

    for rule_id, rule_def in rules_config.get("rules", {}).items():
        if rule_def.get("enabled", False):
            _validate_rule_thresholds(rule_id, rule_def.get("thresholds", []))

    return rules_config

def rule_services(rule_id: str) -> list[str]:
     """Return every service whose YAML defines this rule_id (empty if none)."""
     services = []
     for service, path in SERVICE_RULE_PATHS.items():
         try:
             rules_config = load_rules(path)
         except RuntimeError:
             continue
         if rule_id in rules_config.get("rules", {}):
             services.append(service)
     return services


def invalidate_all_rules() -> None:
    """Force every rules YAML to reload from disk on next load_rules() call."""
    for cfg in _rule_configs.values():
        cfg.invalidate()


def is_rule_active(rule_id: str, service: str, overrides: dict[str, str]) -> bool:
    """
    Single source of truth for whether a rule is active — used by BOTH
    feature-builders (gating counter increments) and rule evaluation
    (gating scoring). Priority: Redis override > YAML `enabled` flag.

    Shared rule_ids (see
    admin_api._SHARED_RULE_IDS) are intentionally GLOBAL: disabling one
    disables it for every service, including halting the Redis counters
    those features maintain. 
    """
    rules_config = load_rules(SERVICE_RULE_PATHS[service])
    yaml_enabled = rules_config["rules"].get(rule_id, {}).get("enabled", False)
    return _is_rule_enabled(rule_id, yaml_enabled, overrides)


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
    YAML thresholds. Returns a dictionary containing rule_id and weight if triggered,
    otherwise None.
    """
    try:
        feature_name  = rule_definition["feature"] #here where rule defintions from features and rules.yaml meets 
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

            numeric_feature_value = float(feature_value)

            if maximum_value is not None:
                maximum_value = float(maximum_value)
                if minimum_value <= numeric_feature_value <= maximum_value:
                    return {"rule_id": rule_id, "weight": threshold_band["weight"]}
            else:
                if numeric_feature_value >= minimum_value:
                    return {"rule_id": rule_id, "weight": threshold_band["weight"]}

    except Exception as exc:
        logger.exception(f"{ErrorCode.RULE_ENGINE_ERROR}: Rule evaluation failure for {rule_id}")
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc


def run_rules(
    rule_config: dict,
    feature_values: dict,
    service: str,
    rule_overrides: dict[str, str],
) -> list:
    """
    Execute all enabled fraud rules against the extracted feature set.

    ``rule_overrides`` is the already-fetched Redis override snapshot supplied
    by the caller. It is intentionally reused here so the same override state
    is applied consistently across feature generation and rule evaluation.

    Threshold overrides are fetched directly from Redis for each rule because
    administrator threshold changes must apply to the next scoring request.

    Returns:
        List of triggered rule dictionaries containing ``rule_id`` and
        ``weight``.
    """
    triggered_rules: list = []

    try:
        for rule_id, rule_definition in rule_config["rules"].items():
            yaml_enabled = rule_definition.get("enabled", False)

            if not _is_rule_enabled(
                rule_id,
                yaml_enabled,
                rule_overrides,
            ):
                continue

            threshold_override = _fetch_threshold_override(
                service,
                rule_id,
            )

            evaluation_result = evaluate_rule(
                rule_id,
                rule_definition,
                feature_values,
                threshold_override,
            )

            if evaluation_result:
                triggered_rules.append(evaluation_result)

        return triggered_rules

    except Exception as exc:
        logger.exception(
            f"{ErrorCode.RULE_ENGINE_ERROR}: Rule execution failure"
        )
        raise RuntimeError(ErrorCode.RULE_ENGINE_ERROR) from exc


def apply_chains(
    rules_config: dict,
    triggered_rules: list,
) -> list:
    """
    Apply rule chain definitions from the YAML chains section.

    A chain boosts the weight of a target rule when all its trigger rules
    have already fired.  This models compounding fraud signals — e.g.
    a new device (DEVICE_NEW_DEVICE_ALLOWANCE) combined with authentication failures (AUTH_CONSECUTIVE_FAILURES) is
    much stronger evidence than either signal alone.

    IMPORTANT: Chains compound multiplicatively.  If two chains both target
    the same rule (e.g., ×1.5 and ×1.6), the final weight is
    original × 1.5 × 1.6 = original × 2.4.  This is intentional — the
    presence of multiple correlated signals is itself a fraud signal.

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
                result[target_id]["chain_multiplier"] = multiplier
                result[target_id]["chain_reason"] = reason
                logger.info(
                    "[RULES] Chain applied: triggers=%s target=%s weight %d→%d reason=%s",
                    trigger_set, target_id, original_weight, boosted_weight, reason,
                )
        return list(result.values())

    except Exception as exc:
        logger.warning("[RULES] apply_chains failed — returning unchained rules: %s", exc)
        return triggered_rules