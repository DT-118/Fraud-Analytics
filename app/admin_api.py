"""
admin_api.py

Internal operations endpoints for the Fraud Scoring Engine.

Authentication: requires X-API-Key matching FRAUD_ADMIN_KEY (separate from the
scoring API's FRAUD_API_KEY — admin key must never be distributed to integration
partners).

Rate limiting: global limit (check_rate_limit) applies.

Endpoints:
  Rule toggle (dynamic, takes effect within 30s without restart):
    POST   /v2/admin/rules/{rule_id}/disable
    POST   /v2/admin/rules/{rule_id}/enable
    DELETE /v2/admin/rules/{rule_id}/override   — remove override, revert to YAML

  Rule inspection (NEW):
    GET    /v2/admin/rules                      — list every rule + its effective state
    GET    /v2/admin/rules?service=AUTH          — filtered to one service

  Per-service threshold overrides (NEW, takes effect immediately, next event):
    PUT    /v2/admin/rules/{service}/{rule_id}/thresholds
    DELETE /v2/admin/rules/{service}/{rule_id}/thresholds

  Risk-band overrides (NEW, takes effect immediately, next event):
    PUT    /v2/admin/scoring/risk-bands
    DELETE /v2/admin/scoring/risk-bands

  IP management (Redis blocklist):
    POST   /v2/admin/ip/flag
    DELETE /v2/admin/ip/{ip}

  Config hot-reload (forces HotConfig instances to reload from disk immediately):
    POST   /v2/admin/config/reload

NOTE on scope: the rule-listing / threshold / risk-band endpoints below are
NEW and correctly namespaced per-service from the start. The pre-existing
enable/disable endpoints above them are UNCHANGED — they still key off a
single global `rule:overrides` hash by rule_id only, so a rule_id shared
across services (e.g. DEVICE-01 in AUTH/CONSENT/ENROLL/WALLET) toggles
everywhere at once. That collision is called out explicitly in the new
GET /v2/admin/rules response via "shared_across_services": true, but is not
fixed here — say the word if you want that follow-up done too.
"""

from dotenv import load_dotenv
load_dotenv()

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from core.logger import logger
from core.rate_limiter import check_rate_limit
from rules.engine import load_rules, _is_rule_enabled, validate_threshold_payload
from scoring.engine import validate_risk_bands
from service.ip_reputation import REDIS_FLAGGED_KEY, flag_ip
from storage.redis_client import redis_client

_REDIS_OVERRIDES_KEY = "rule:overrides"
_REDIS_THRESHOLD_OVERRIDES_KEY = "rule:threshold_overrides"
_REDIS_BAND_OVERRIDES_KEY = "score:band_overrides"

# admin_api.py lives at /app/admin_api.py — one .parent gets to /app,
# matching the /app/rules/auth/rules.yaml layout confirmed for this deployment.
_APP_DIR = Path(__file__).parent

SERVICE_RULE_PATHS: dict[str, str] = {
    "AUTH":    str(_APP_DIR / "rules/auth/rules.yaml"),
    "ENROLL":  str(_APP_DIR / "rules/enroll/rules.yaml"),
    "CONSENT": str(_APP_DIR / "rules/consent/rules.yaml"),
    "WALLET":  str(_APP_DIR / "rules/wallet/rules.yaml"),
}

# TODO: confirm this matches SCORES_CONFIG_PATH in fraud_service.py exactly.
SCORES_CONFIG_PATH = str(_APP_DIR / "scoring/scores.yaml")

# Rule IDs that are defined identically across every service YAML and share
# ONE global enable/disable override key (the pre-existing collision).
_SHARED_RULE_IDS = {"DEVICE-01", "IP-01", "GEO-01", "BASELINE-01"}

# Admin key is separate from the scoring API key — never share with integrations
_ADMIN_KEY = os.environ.get("FRAUD_ADMIN_KEY", "")


def require_admin_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    if not _ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="FRAUD_ADMIN_KEY env var is not configured",
        )
    if x_api_key != _ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API key",
        )


router = APIRouter(
    prefix="/v2/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin_key), Depends(check_rate_limit)],
)


# ---------------------------------------------------------------------------
# Rule toggle (UNCHANGED)
# ---------------------------------------------------------------------------

@router.post("/rules/{rule_id}/disable", status_code=status.HTTP_200_OK)
def disable_rule(rule_id: str):
    """
    Dynamically disable a rule without restarting.
    Takes effect within 30 seconds (override cache TTL).
    """
    try:
        redis_client.hset(_REDIS_OVERRIDES_KEY, rule_id, "disabled")
        logger.warning("[ADMIN] Rule %s disabled via admin API", rule_id)
        return {"rule_id": rule_id, "status": "disabled"}
    except Exception as exc:
        logger.error("[ADMIN] Failed to disable rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.post("/rules/{rule_id}/enable", status_code=status.HTTP_200_OK)
def enable_rule(rule_id: str):
    """
    Dynamically enable a rule (even if YAML has enabled: false).
    Takes effect within 30 seconds.
    """
    try:
        redis_client.hset(_REDIS_OVERRIDES_KEY, rule_id, "enabled")
        logger.info("[ADMIN] Rule %s enabled via admin API", rule_id)
        return {"rule_id": rule_id, "status": "enabled"}
    except Exception as exc:
        logger.error("[ADMIN] Failed to enable rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.delete("/rules/{rule_id}/override", status_code=status.HTTP_200_OK)
def clear_rule_override(rule_id: str):
    """
    Remove a dynamic override for a rule — behaviour reverts to YAML enabled flag.
    Takes effect within 30 seconds.
    """
    try:
        removed = redis_client.hdel(_REDIS_OVERRIDES_KEY, rule_id)
        if removed == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No override found for rule {rule_id}",
            )
        logger.info("[ADMIN] Override removed for rule %s — reverting to YAML", rule_id)
        return {"rule_id": rule_id, "status": "override_cleared"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[ADMIN] Failed to clear override for rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


# ---------------------------------------------------------------------------
# Rule inspection (NEW)
# ---------------------------------------------------------------------------

@router.get("/rules", status_code=status.HTTP_200_OK)
def list_rules(service: Optional[str] = None):
    """
    List every rule across every service (or one service, via ?service=),
    with its YAML default, any active override, and the resulting
    effective enabled/disabled state.
    """
    if service is not None:
        service = service.upper()
        if service not in SERVICE_RULE_PATHS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown service '{service}'. Must be one of {sorted(SERVICE_RULE_PATHS)}",
            )
        services_to_load = [service]
    else:
        services_to_load = list(SERVICE_RULE_PATHS.keys())

    try:
        # One round trip gets every enable/disable override at once.
        overrides = dict(redis_client.hgetall(_REDIS_OVERRIDES_KEY) or {})
    except Exception as exc:
        logger.warning("[ADMIN] Failed to fetch overrides for rule listing: %s", exc)
        overrides = {}

    try:
        # One round trip gets every threshold override at once (hash keyed "SERVICE:RULE_ID").
        raw_threshold_overrides = dict(redis_client.hgetall(_REDIS_THRESHOLD_OVERRIDES_KEY) or {})
    except Exception as exc:
        logger.warning("[ADMIN] Failed to fetch threshold overrides for rule listing: %s", exc)
        raw_threshold_overrides = {}

    rules_out = []
    for svc in services_to_load:
        rules_config = load_rules(SERVICE_RULE_PATHS[svc])
        for rule_id, rule_def in rules_config.get("rules", {}).items():
            yaml_enabled = rule_def.get("enabled", False)
            override_val = overrides.get(rule_id)

            yaml_thresholds = rule_def.get("thresholds", [])
            threshold_override_raw = raw_threshold_overrides.get(f"{svc}:{rule_id}")
            threshold_override = json.loads(threshold_override_raw) if threshold_override_raw else None

            rules_out.append({
                "rule_id": rule_id,
                "service": svc,
                "yaml_enabled": yaml_enabled,
                "override": override_val,
                "effective_enabled": _is_rule_enabled(rule_id, yaml_enabled, overrides),
                "shared_across_services": rule_id in _SHARED_RULE_IDS,
                # Threshold state — this is what a "modify thresholds" UI should pre-fill from.
                "yaml_thresholds": yaml_thresholds,
                "threshold_override": threshold_override,       # null if none active
                "effective_thresholds": threshold_override if threshold_override is not None else yaml_thresholds,
            })

    return {"rules": rules_out}


@router.get("/scoring/risk-bands", status_code=status.HTTP_200_OK)
def get_risk_bands():
    """
    Return the current risk-band state: YAML default, any active override,
    and the effective bands actually in use for scoring right now.
    This is what a "modify risk bands" UI should pre-fill from.
    """
    from scoring.engine import load_scores
    yaml_bands = load_scores(SCORES_CONFIG_PATH)["risk_bands"]

    try:
        raw_override = redis_client.get(_REDIS_BAND_OVERRIDES_KEY)
        override = json.loads(raw_override) if raw_override else None
    except Exception as exc:
        logger.warning("[ADMIN] Failed to fetch risk-band override: %s", exc)
        override = None

    return {
        "yaml_risk_bands": yaml_bands,
        "override": override,                                   # null if none active
        "effective_risk_bands": override if override is not None else yaml_bands,
    }


# ---------------------------------------------------------------------------
# Per-service threshold overrides (NEW)
# ---------------------------------------------------------------------------

class ThresholdBand(BaseModel):
    min: float
    max: Optional[float] = None
    weight: int


class ThresholdOverrideRequest(BaseModel):
    thresholds: list[ThresholdBand]


@router.put("/rules/{service}/{rule_id}/thresholds", status_code=status.HTTP_200_OK)
def set_threshold_override(service: str, rule_id: str, body: ThresholdOverrideRequest):
    """
    Set a threshold-band override for one rule in one service.
    Takes effect immediately — the very next /v1/score event for this
    service that evaluates this rule will use these bands.
    """
    service = service.upper()
    if service not in SERVICE_RULE_PATHS:
        raise HTTPException(status_code=400, detail=f"Unknown service '{service}'")

    rules_config = load_rules(SERVICE_RULE_PATHS[service])
    if rule_id not in rules_config.get("rules", {}):
        raise HTTPException(
            status_code=404, detail=f"No rule '{rule_id}' defined for service '{service}'"
        )

    thresholds_raw = [b.model_dump(exclude_none=True) for b in body.thresholds]
    error = validate_threshold_payload(thresholds_raw)
    if error:
        raise HTTPException(status_code=422, detail=error)

    try:
        redis_client.hset(
            _REDIS_THRESHOLD_OVERRIDES_KEY,
            f"{service}:{rule_id}",
            json.dumps(thresholds_raw),
        )
        logger.warning(
            "[ADMIN] Threshold override set for %s:%s -> %s", service, rule_id, thresholds_raw
        )
        return {
            "service": service,
            "rule_id": rule_id,
            "thresholds": thresholds_raw,
            "status": "override_set",
        }
    except Exception as exc:
        logger.error(
            "[ADMIN] Failed to write threshold override for %s:%s: %s", service, rule_id, exc
        )
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.delete("/rules/{service}/{rule_id}/thresholds", status_code=status.HTTP_200_OK)
def clear_threshold_override(service: str, rule_id: str):
    """
    Remove a threshold override — reverts to YAML thresholds immediately.
    """
    service = service.upper()
    if service not in SERVICE_RULE_PATHS:
        raise HTTPException(status_code=400, detail=f"Unknown service '{service}'")

    try:
        removed = redis_client.hdel(_REDIS_THRESHOLD_OVERRIDES_KEY, f"{service}:{rule_id}")
        if removed == 0:
            raise HTTPException(
                status_code=404,
                detail=f"No threshold override set for {service}:{rule_id}",
            )
        logger.info("[ADMIN] Threshold override cleared for %s:%s", service, rule_id)
        return {"service": service, "rule_id": rule_id, "status": "override_cleared"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "[ADMIN] Failed to clear threshold override for %s:%s: %s", service, rule_id, exc
        )
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


# ---------------------------------------------------------------------------
# Risk-band overrides (NEW)
# ---------------------------------------------------------------------------

class RiskBandsRequest(BaseModel):
    NORISK: list[float]
    LOW: list[float]
    MEDIUM: list[float]
    HIGH: list[float]
    CRITICAL: list[float]


@router.put("/scoring/risk-bands", status_code=status.HTTP_200_OK)
def set_risk_bands(body: RiskBandsRequest):
    """
    Overwrite the entire risk-band set. This is global (not per-service) —
    every /v1/score call across every service uses these bands the moment
    this write succeeds.
    """
    bands = body.model_dump()
    error = validate_risk_bands(bands)
    if error:
        raise HTTPException(status_code=422, detail=error)

    try:
        redis_client.set(_REDIS_BAND_OVERRIDES_KEY, json.dumps(bands))
        logger.warning("[ADMIN] Risk-band override set: %s", bands)
        return {"risk_bands": bands, "status": "override_set"}
    except Exception as exc:
        logger.error("[ADMIN] Failed to write risk-band override: %s", exc)
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.delete("/scoring/risk-bands", status_code=status.HTTP_200_OK)
def clear_risk_bands():
    """Remove the risk-band override — reverts to scores.yaml immediately."""
    try:
        removed = redis_client.delete(_REDIS_BAND_OVERRIDES_KEY)
        if removed == 0:
            raise HTTPException(
                status_code=404, detail="No risk-band override is currently active"
            )
        logger.info("[ADMIN] Risk-band override cleared — reverting to scores.yaml")
        return {"status": "override_cleared"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[ADMIN] Failed to clear risk-band override: %s", exc)
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


# ---------------------------------------------------------------------------
# IP management
# ---------------------------------------------------------------------------

class IPFlagRequest(BaseModel):
    ip: str
    reason: str = "manual_admin_flag"


@router.post("/ip/flag", status_code=status.HTTP_200_OK)
def flag_ip_route(body: IPFlagRequest):
    """Add an IP address to the Redis blocklist."""
    try:
        flag_ip(body.ip, reason=body.reason)
        logger.warning("[ADMIN] IP %s added to blocklist — reason: %s", body.ip, body.reason)
        return {"ip": body.ip, "status": "blocked"}
    except Exception as exc:
        logger.error("[ADMIN] Failed to flag IP %s: %s", body.ip, exc)
        raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc


@router.delete("/ip/{ip}", status_code=status.HTTP_200_OK)
def unflag_ip(ip: str):
    """Remove an IP address from the Redis blocklist."""
    try:
        removed = redis_client.srem(REDIS_FLAGGED_KEY, ip)
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"IP {ip} not found in blocklist",
            )
        logger.info("[ADMIN] IP %s removed from blocklist", ip)
        return {"ip": ip, "status": "unblocked"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[ADMIN] Failed to remove IP %s: %s", ip, exc)
        raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc


# ---------------------------------------------------------------------------
# Config hot-reload
# ---------------------------------------------------------------------------

def _invalidate_all_hotconfigs() -> list[str]:
    """Call invalidate() on every known HotConfig instance."""
    from scoring.engine import _amplifiers_config
    from service.session_service import _session_config
    from service.profile_service import _patterns_config
    from storage.profile_repo import _weights_config
    from features.geo_features import _geo_policy_config
    from core.rate_limiter import _rate_limits_config
    from core.idempotency import _idempotency_config

    configs = {
        "exception_amplifiers":   _amplifiers_config,
        "session_config":         _session_config,
        "cross_service_patterns": _patterns_config,
        "service_weights":        _weights_config,
        "geo_policy":             _geo_policy_config,
        "rate_limits":            _rate_limits_config,
        "idempotency_config":     _idempotency_config,
    }

    reloaded = []
    for name, cfg in configs.items():
        try:
            cfg.invalidate()
            reloaded.append(name)
        except Exception as exc:
            logger.warning("[ADMIN] Failed to invalidate config %s: %s", name, exc)

    return reloaded


@router.post("/config/reload", status_code=status.HTTP_200_OK)
def reload_config():
    """
    Force immediate reload of all hot-reloadable YAML config files.
    Normally configs reload automatically every 5 minutes;
    use this endpoint after an urgent config change to apply immediately.
    """
    try:
        reloaded = _invalidate_all_hotconfigs()
        logger.info("[ADMIN] Config reload triggered — invalidated: %s", reloaded)
        return {"status": "reloaded", "configs": reloaded}
    except Exception as exc:
        logger.error("[ADMIN] Config reload failed: %s", exc)
        raise HTTPException(status_code=500, detail="Config reload failed") from exc