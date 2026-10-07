# """
# admin_api.py

# Internal operations endpoints for the Fraud Scoring Engine.
# Authentication: requires X-API-Key matching FRAUD_ADMIN_KEY (separate from the
# scoring API's FRAUD_API_KEY — admin key must never be distributed to integration
# partners).

# Rate limiting: global limit (check_rate_limit) applies.

# Endpoints:
#   Rule toggle (dynamic, instant — no cache/TTL delay):
#     POST   /v2/admin/rules/{rule_id}/disable
#     POST   /v2/admin/rules/{rule_id}/enable
#     DELETE /v2/admin/rules/{rule_id}/override   — remove override, revert to YAML

#   Rule inspection:
#     GET    /v2/admin/rules                      — list every rule + its effective state + description
#     GET    /v2/admin/rules?service=AUTH          — filtered to one service
#     GET    /v2/admin/scoring/risk-bands         — list score bands + its effective state 

#   Per-service threshold overrides (instant, no cache/TTL delay):
#     PUT    /v2/admin/rules/{service}/{rule_id}/thresholds
#     DELETE /v2/admin/rules/{service}/{rule_id}/thresholds

#   Risk-band overrides (instant, global — not per-service):
#     PUT    /v2/admin/scoring/risk-bands
#     DELETE /v2/admin/scoring/risk-bands

#   Exception score overrides (instant, additive to raw_score):
#     GET    /v2/admin/scoring/exception-score
#     PUT    /v2/admin/scoring/exception-score/{code}
#     DELETE /v2/admin/scoring/exception-score/{code}

#   Role modifier overrides (instant, multiplicative dampener on rule weight):
#     GET    /v2/admin/scoring/role-modifiers
#     PUT    /v2/admin/scoring/role-modifiers/{role}/{rule_id}
#     DELETE /v2/admin/scoring/role-modifiers/{role}/{rule_id}

#   Rate limit overrides (instant):
#     GET    /v2/admin/scoring/rate-limits
#     PUT    /v2/admin/scoring/rate-limits/{service_or_global}
#     DELETE /v2/admin/scoring/rate-limits/{service_or_global}

#   IP management (Redis blocklist, DB, and file — all three kept in sync):
#     GET    /v2/admin/ip/flagged                 — list both sources + drift between them
#     POST   /v2/admin/ip/flag
#     DELETE /v2/admin/ip/{ip}

#   Config hot-reload (forces every HotConfig instance, plus rule/score
#   caches, to reload from disk immediately instead of waiting out their TTL):
#     POST   /v2/admin/config/reload

# # NOTE on scope: the rule-listing / threshold / risk-band endpoints below are
# # correctly namespaced per-service. The pre-existing enable/disable endpoints
# # above them are UNCHANGED — they still key off a single global `rule:overrides`
# # hash by rule_id only, so a rule_id shared across services (e.g.
# # DEVICE_SHARED_ACCOUNTS in AUTH/CONSENT/LOGIN/WALLET) toggles everywhere at
# # once. That collision is called out explicitly in GET /v2/admin/rules via
# # "shared_across_services": true — this is a deliberate design decision.
# """

# from dotenv import load_dotenv
# load_dotenv()

# import json
# import os
# from pathlib import Path
# from typing import Optional

# from fastapi import APIRouter, Depends, Header, HTTPException, status
# from pydantic import BaseModel, Field

# from core.context import VALID_ROLES
# from core.logger import logger
# from core.rate_limiter import check_rate_limit, normalize_rate_limit_key
# from rules.engine import (
#     load_rules,
#     _is_rule_enabled,
#     validate_threshold_payload,
#     invalidate_all_rules,
#     rule_services,
# )
# from scoring.engine import (
#     validate_risk_bands,
#     invalidate_scores,
#     validate_role_modifier_value,
# )
# from storage.redis_client import redis_client
# from storage.db import get_db_connection, release_db_connection
# from service.ip_reputation import flag_ip, unflag_ip, list_flagged_ips

# _REDIS_OVERRIDES_KEY = "rule:overrides"
# _REDIS_THRESHOLD_OVERRIDES_KEY = "rule:threshold_overrides"
# _REDIS_BAND_OVERRIDES_KEY = "score:band_overrides"


# # matching the /app/config/rules/*.yaml layout confirmed for this deployment.
# _APP_DIR = Path(__file__).parent

# SERVICE_RULE_PATHS: dict[str, str] = {
#     "AUTH":    str(_APP_DIR / "config/rules/auth_rules.yaml"),
#     "LOGIN":   str(_APP_DIR / "config/rules/login_rules.yaml"),
#     "CONSENT": str(_APP_DIR / "config/rules/consent_rules.yaml"),
#     "WALLET":  str(_APP_DIR / "config/rules/wallet_rules.yaml"),
# }

# SCORES_CONFIG_PATH = str(_APP_DIR / "scoring/scores.yaml")

# # Rule IDs defined identically across every service YAML that share ONE
# # global enable/disable override key — toggling one toggles it everywhere.
# _SHARED_RULE_IDS = {
#     "DEVICE_SHARED_ACCOUNTS",
#     "DEVICE_NEW_DEVICE_ALLOWANCE",
#     "DEVICE_SWITCH_VELOCITY",
#     "IP_BLOCKLIST_MATCH",
#     "GEO_POLICY_VIOLATION",
#     "GEO_VELOCITY",
#     "BASELINE_BEHAVIOR_ANOMALY",
#     "BIOMETRIC_SPOOF_DETECTED",
#     "LIVENESS_RESULT_MISSING",
#     "UDB_FACE_MISMATCH",
#     "ODD_HOUR_ACTIVITY",
# }
# # Roles known to the engine. Sourced directly from core.context.VALID_ROLES
# # — the SAME set that Context's field_validator enforces on incoming events
# # — rather than a second hardcoded copy here, so this can never drift out of
# # sync with what the engine actually accepts. Used so GET /scoring/role-modifiers
# # can show every role (including ones with no overrides/YAML entries yet) and
# # so PUT rejects a role that could never appear on a real event anyway.
# _VALID_ROLES = VALID_ROLES

# _ADMIN_KEY = os.environ.get("FRAUD_ADMIN_KEY", "")

# # At import time it blocks startup
# # entirely, which is the correct failure mode for a config error this
# # serious (fail fast, same posture as the FRAUD_API_KEY/FRAUD_ADMIN_KEY/
# # JWT_SECRET presence checks in api.py's lifespan).
# _SCORING_KEY = os.environ.get("FRAUD_API_KEY", "")
# if _ADMIN_KEY and _SCORING_KEY and _ADMIN_KEY == _SCORING_KEY:
#     raise RuntimeError(
#         "FRAUD_ADMIN_KEY and FRAUD_API_KEY must not be equal — this would "
#         "grant every scoring integration partner full admin access."
#     )

# # ExceptionScoreOverrideRequest below uses these constants.
# _MIN_EXCEPTION_ADDER = 0
# _MAX_EXCEPTION_ADDER = 100


# def require_admin_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
#     """
#     FastAPI dependency — gates every route in this router behind the admin
#     key (FRAUD_ADMIN_KEY), separate from the scoring API's FRAUD_API_KEY.
#     Never share this key with integration partners.
#     """
#     if not _ADMIN_KEY:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="FRAUD_ADMIN_KEY env var is not configured",
#         )
#     if x_api_key != _ADMIN_KEY:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid admin API key",
#         )


# router = APIRouter(
#     prefix="/v2/admin",
#     tags=["admin"],
#     dependencies=[Depends(require_admin_key), Depends(check_rate_limit)],
# )


# # ---------------------------------------------------------------------------
# # Rule toggle
# # ---------------------------------------------------------------------------

# @router.post("/rules/{rule_id}/disable", status_code=status.HTTP_200_OK)
# def disable_rule(rule_id: str):
#     """
#     Force a rule OFF regardless of its YAML `enabled` flag.
#     Writes "disabled" to the rule:overrides Redis hash — read fresh on
#     every event (no cache/TTL), so this takes effect on the very next
#     /v2/score call. For _SHARED_RULE_IDS this disables the rule across
#     ALL services, not just one.
#     """
#     services = rule_services(rule_id)
#     if not services:
#         raise HTTPException(
#             status_code=404,
#             detail=f"Unknown rule_id '{rule_id}' — not defined in any service rules YAML",
#         )
#     try:
#         redis_client.hset(_REDIS_OVERRIDES_KEY, rule_id, "disabled")
#         logger.warning("[ADMIN] Rule %s disabled via admin API (services=%s)", rule_id, services)
#         return {"rule_id": rule_id, "status": "disabled", "services": services}
#     except Exception as exc:
#         logger.error("[ADMIN] Failed to disable rule %s: %s", rule_id, exc)
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# @router.post("/rules/{rule_id}/enable", status_code=status.HTTP_200_OK)
# def enable_rule(rule_id: str):
#     """
#     Force a rule ON regardless of its YAML `enabled` flag (useful for
#     testing a rule that's normally disabled). Same instant-effect,
#     same shared-rule-id caveat as disable_rule() above.
#     """
#     services = rule_services(rule_id)  
#     if not services:
#         raise HTTPException(
#             status_code=404,
#             detail=f"Unknown rule_id '{rule_id}' — not defined in any service rules YAML",
#         )
#     try:
#         redis_client.hset(_REDIS_OVERRIDES_KEY, rule_id, "enabled")
#         logger.info("[ADMIN] Rule %s enabled via admin API (services=%s)", rule_id, services)
#         return {"rule_id": rule_id, "status": "enabled", "services": services}
#     except Exception as exc:
#         logger.error("[ADMIN] Failed to enable rule %s: %s", rule_id, exc)
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# @router.delete("/rules/{rule_id}/override", status_code=status.HTTP_200_OK)
# def clear_rule_override(rule_id: str):
#     """
#     Remove any enable/disable override for this rule — reverts to
#     whatever the YAML `enabled` flag says. 404 if no override was active.
#     """
#     try:
#         removed = redis_client.hdel(_REDIS_OVERRIDES_KEY, rule_id)
#         if removed == 0:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail=f"No override found for rule {rule_id}",
#             )
#         logger.info("[ADMIN] Override removed for rule %s — reverting to YAML", rule_id)
#         return {"rule_id": rule_id, "status": "override_cleared"}
#     except HTTPException:
#         raise
#     except Exception as exc:
#         logger.error("[ADMIN] Failed to clear override for rule %s: %s", rule_id, exc)
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# # ---------------------------------------------------------------------------
# # Rule inspection
# # ---------------------------------------------------------------------------

# @router.get("/rules", status_code=status.HTTP_200_OK)
# def list_rules(service: Optional[str] = None):
#     """
#     List every rule (optionally filtered to one service via ?service=),
#     with its human-readable description, YAML default, any active
#     Redis override, and the resulting effective enabled/disabled state
#     and threshold bands.

#     This is the single source of truth a frontend rule-management screen
#     should build its table from — every field a "view/edit rule" UI needs
#     (name, description, current on/off state, current thresholds, whether
#     toggling it is a global/shared action) is returned per rule here.
#     """
#     if service is not None:
#         service = service.upper()
#         if service not in SERVICE_RULE_PATHS:
#             raise HTTPException(
#                 status_code=400,
#                 detail=f"Unknown service '{service}'. Must be one of {sorted(SERVICE_RULE_PATHS)}",
#             )
#         services_to_load = [service]
#     else:
#         services_to_load = list(SERVICE_RULE_PATHS.keys())

#     try:
#         # One round trip gets every enable/disable override at once.
#         overrides = dict(redis_client.hgetall(_REDIS_OVERRIDES_KEY) or {})
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to fetch overrides for rule listing: %s", exc)
#         overrides = {}

#     try:
#         # One round trip gets every threshold override at once (hash keyed "SERVICE:RULE_ID").
#         raw_threshold_overrides = dict(redis_client.hgetall(_REDIS_THRESHOLD_OVERRIDES_KEY) or {})
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to fetch threshold overrides for rule listing: %s", exc)
#         raw_threshold_overrides = {}

#     rules_out = []
#     for svc in services_to_load:
#         rules_config = load_rules(SERVICE_RULE_PATHS[svc])
#         for rule_id, rule_def in rules_config.get("rules", {}).items():
#             yaml_enabled = rule_def.get("enabled", False)
#             override_val = overrides.get(rule_id)

#             yaml_thresholds = rule_def.get("thresholds", [])
#             threshold_override_raw = raw_threshold_overrides.get(f"{svc}:{rule_id}")
#             threshold_override = json.loads(threshold_override_raw) if threshold_override_raw else None

#             rules_out.append({
#                 "rule_id": rule_id,
#                 "service": svc,
#                 "description": rule_def.get("description", ""),   # human-readable, from rules.yaml
#                 "yaml_enabled": yaml_enabled,
#                 "override": override_val,
#                 "effective_enabled": _is_rule_enabled(rule_id, yaml_enabled, overrides),
#                 "shared_across_services": rule_id in _SHARED_RULE_IDS,
#                 # Threshold state — this is what a "modify thresholds" UI should pre-fill from.
#                 "yaml_thresholds": yaml_thresholds,
#                 "threshold_override": threshold_override,       
#                 "effective_thresholds": threshold_override if threshold_override is not None else yaml_thresholds,
#             })

#     return {"rules": rules_out}


# @router.get("/scoring/risk-bands", status_code=status.HTTP_200_OK)
# def get_risk_bands():
#     """
#     Return the current risk-band state: YAML default (scores.yaml),
#     any active Redis override, and the effective bands actually being
#     used to classify scores right now. Pre-fills a "modify risk bands" UI.
#     """
#     from scoring.engine import load_scores
#     yaml_bands = load_scores(SCORES_CONFIG_PATH)["risk_bands"]

#     try:
#         raw_override = redis_client.get(_REDIS_BAND_OVERRIDES_KEY)
#         override = json.loads(raw_override) if raw_override else None
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to fetch risk-band override: %s", exc)
#         override = None

#     return {
#         "yaml_risk_bands": yaml_bands,
#         "override": override,                                   # null if none active
#         "effective_risk_bands": override if override is not None else yaml_bands,
#     }


# # ---------------------------------------------------------------------------
# # Per-service threshold overrides
# # ---------------------------------------------------------------------------

# class ThresholdBand(BaseModel):
#     """One [min, max?, weight] band. max omitted = open-ended (>= min)."""
#     min: float
#     max: Optional[float] = None
#     weight: int


# class ThresholdOverrideRequest(BaseModel):
#     """Full replacement band list for one (service, rule_id) threshold override."""
#     thresholds: list[ThresholdBand]


# @router.put("/rules/{service}/{rule_id}/thresholds", status_code=status.HTTP_200_OK)
# def set_threshold_override(service: str, rule_id: str, body: ThresholdOverrideRequest):
#     """
#     Replace a rule's threshold bands for one service. Validated for
#     ordering/overlap before writing (validate_threshold_payload). Takes
#     effect on the very next /v2/score event evaluating this rule — no
#     cache, no reload needed.
#     """
#     service = service.upper()
#     if service not in SERVICE_RULE_PATHS:
#         raise HTTPException(status_code=400, detail=f"Unknown service '{service}'")

#     rules_config = load_rules(SERVICE_RULE_PATHS[service])
#     if rule_id not in rules_config.get("rules", {}):
#         raise HTTPException(
#             status_code=404, detail=f"No rule '{rule_id}' defined for service '{service}'"
#         )

#     thresholds_raw = [b.model_dump(exclude_none=True) for b in body.thresholds]
#     error = validate_threshold_payload(thresholds_raw)
#     if error:
#         raise HTTPException(status_code=422, detail=error)

#     try:
#         redis_client.hset(
#             _REDIS_THRESHOLD_OVERRIDES_KEY,
#             f"{service}:{rule_id}",
#             json.dumps(thresholds_raw),
#         )
#         logger.warning(
#             "[ADMIN] Threshold override set for %s:%s -> %s", service, rule_id, thresholds_raw
#         )
#         return {
#             "service": service,
#             "rule_id": rule_id,
#             "thresholds": thresholds_raw,
#             "status": "override_set",
#         }
#     except Exception as exc:
#         logger.error(
#             "[ADMIN] Failed to write threshold override for %s:%s: %s", service, rule_id, exc
#         )
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# @router.delete("/rules/{service}/{rule_id}/thresholds", status_code=status.HTTP_200_OK)
# def clear_threshold_override(service: str, rule_id: str):
#     """
#     Remove a threshold override — reverts to YAML-defined bands immediately.
#     """
#     service = service.upper()
#     if service not in SERVICE_RULE_PATHS:
#         raise HTTPException(status_code=400, detail=f"Unknown service '{service}'")

#     try:
#         removed = redis_client.hdel(_REDIS_THRESHOLD_OVERRIDES_KEY, f"{service}:{rule_id}")
#         if removed == 0:
#             raise HTTPException(
#                 status_code=404,
#                 detail=f"No threshold override set for {service}:{rule_id}",
#             )
#         logger.info("[ADMIN] Threshold override cleared for %s:%s", service, rule_id)
#         return {"service": service, "rule_id": rule_id, "status": "override_cleared"}
#     except HTTPException:
#         raise
#     except Exception as exc:
#         logger.error(
#             "[ADMIN] Failed to clear threshold override for %s:%s: %s", service, rule_id, exc
#         )
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# # ---------------------------------------------------------------------------
# # Risk-band overrides
# # ---------------------------------------------------------------------------

# class RiskBandsRequest(BaseModel):
#     """
#     Full risk-band set — [min, max] per band. Must cover 0-100 with no
#     gaps/overlaps (validated by validate_risk_bands). This is atomic:
#     unlike thresholds, you cannot update one band alone — every PUT must
#     supply the complete set.
#     """
#     NORISK: list[float]
#     LOW: list[float]
#     MEDIUM: list[float]
#     HIGH: list[float]
#     CRITICAL: list[float]


# @router.put("/scoring/risk-bands", status_code=status.HTTP_200_OK)
# def set_risk_bands(body: RiskBandsRequest):
#     """
#     Overwrite the entire risk-band set. Global (not per-service) — every
#     /v2/score call across every service uses these bands the moment this
#     write succeeds. Highest-blast-radius endpoint in this file; consider
#     a confirmation step in the frontend before calling this.
#     """
#     bands = body.model_dump()
#     error = validate_risk_bands(bands)
#     if error:
#         raise HTTPException(status_code=422, detail=error)

#     try:
#         redis_client.set(_REDIS_BAND_OVERRIDES_KEY, json.dumps(bands))
#         logger.warning("[ADMIN] Risk-band override set: %s", bands)
#         return {"risk_bands": bands, "status": "override_set"}
#     except Exception as exc:
#         logger.error("[ADMIN] Failed to write risk-band override: %s", exc)
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# @router.delete("/scoring/risk-bands", status_code=status.HTTP_200_OK)
# def clear_risk_bands():
#     """Remove the risk-band override — reverts to scores.yaml immediately."""
#     try:
#         removed = redis_client.delete(_REDIS_BAND_OVERRIDES_KEY)
#         if removed == 0:
#             raise HTTPException(
#                 status_code=404, detail="No risk-band override is currently active"
#             )
#         logger.info("[ADMIN] Risk-band override cleared — reverting to scores.yaml")
#         return {"status": "override_cleared"}
#     except HTTPException:
#         raise
#     except Exception as exc:
#         logger.error("[ADMIN] Failed to clear risk-band override: %s", exc)
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# # ---------------------------------------------------------------------------
# # IP management
# # ---------------------------------------------------------------------------

# class IPFlagRequest(BaseModel):
#     """IP to add to the blocklist, with an optional operator-supplied reason."""
#     ip: str
#     added_by: str
#     reason: str = "manual_admin_flag"


# @router.get("/ip/flagged", status_code=status.HTTP_200_OK)
# def get_flagged_ips():
#     """
#     List currently flagged IPs as one merged view: {src_ip, reason,
#     flagged_by, flagged_at, enforced}. "enforced" reflects Redis — the only
#     set IP_BLOCKLIST_MISMATCH actually reads at scoring time — so an entry with
#     enforced=false has a durable record but is NOT currently being blocked
#     (usually a Redis flush/restart without a re-seed).
#     """
#     db = get_db_connection()
#     try:
#         return list_flagged_ips(db_connection=db)
#     except Exception as exc:
#         logger.exception("[ADMIN] Failed to list flagged IPs: %s", exc)
#         raise HTTPException(status_code=500, detail="Failed to read blocklist state") from exc
#     finally:
#         release_db_connection(db)


# @router.post("/ip/flag", status_code=status.HTTP_200_OK)
# def flag_ip_route(body: IPFlagRequest):
#     """
#     Add an IP to both blocklist sources kept in sync: Postgres (durable
#     audit record) and Redis (hot-path lookup used by IP-01 scoring).
#     Records which admin key performed the flag.
#     """
#     db = get_db_connection()
#     try:
#         flag_ip(body.ip, reason=body.reason, db_connection=db, flagged_by=body.added_by)
#         db.commit()
#         logger.warning("[ADMIN] IP %s added to blocklist — reason: %s", body.ip, body.reason)
#         return {"ip": body.ip, "status": "blocked"}
#     except RuntimeError as exc:
#         db.rollback()
#         logger.error("[ADMIN] Failed to flag IP %s: %s", body.ip, exc)
#         raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
#     except Exception as exc:
#         db.rollback()
#         logger.error("[ADMIN] Failed to flag IP %s: %s", body.ip, exc)
#         raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
#     finally:
#         release_db_connection(db)


# @router.delete("/ip/{ip}", status_code=status.HTTP_200_OK)
# def unflag_ip_route(ip: str):
#     """Remove an IP from both blocklist sources. 404 if not currently flagged in the DB."""
#     db = get_db_connection()
#     try:
#         found = unflag_ip(ip, db_connection=db)
#         db.commit()
#         if not found:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail=f"IP {ip} not found in blocklist",
#             )
#         logger.info("[ADMIN] IP %s removed from blocklist", ip)
#         return {"ip": ip, "status": "unblocked"}
#     except HTTPException:
#         raise
#     except RuntimeError as exc:
#         db.rollback()
#         logger.error("[ADMIN] Failed to remove IP %s: %s", ip, exc)
#         raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
#     except Exception as exc:
#         db.rollback()
#         logger.error("[ADMIN] Failed to remove IP %s: %s", ip, exc)
#         raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
#     finally:
#         release_db_connection(db)


# # ---------------------------------------------------------------------------
# # Config hot-reload
# # ---------------------------------------------------------------------------

# def _invalidate_all_hotconfigs() -> list[str]:
#     """
#     Force every HotConfig instance in the engine — plus the separate
#     rules.yaml/scores.yaml caches, which have their own invalidate
#     functions rather than being plain HotConfig instances — to reload
#     from disk on their next .get() call, instead of waiting out their
#     normal 5-minute TTL. Returns the list of config names successfully
#     invalidated (a partial failure on one config does not block the rest).
#     """
#     from scoring.engine import _exception_scores_config, _role_modifiers_config
#     from service.session_service import _session_config
#     from service.profile_service import _patterns_config
#     from storage.profile_repo import _weights_config
#     from features.geo_features import _GEO_POLICY_CONFIG
#     from core.rate_limiter import _RATE_LIMITS_CONFIG
#     from core.idempotency import _IDEMPOTENCY_CONFIG

#     configs = {
#         "exception_scores":       _exception_scores_config,
#         "role_modifiers":         _role_modifiers_config,
#         "session_config":         _session_config,
#         "cross_service_patterns": _patterns_config,
#         "service_weights":        _weights_config,
#         "geo_policy":             _GEO_POLICY_CONFIG,
#         "rate_limits":            _RATE_LIMITS_CONFIG,
#         "idempotency_config":     _IDEMPOTENCY_CONFIG,
#     }

#     reloaded = []
#     for name, cfg in configs.items():
#         try:
#             cfg.invalidate()
#             reloaded.append(name)
#         except Exception as exc:
#             logger.warning("[ADMIN] Failed to invalidate config %s: %s", name, exc)

#     try:
#         invalidate_all_rules()
#         reloaded.append("rules")
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to invalidate rules: %s", exc)

#     try:
#         invalidate_scores()
#         reloaded.append("scores")
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to invalidate scores: %s", exc)

#     return reloaded


# @router.post("/config/reload", status_code=status.HTTP_200_OK)
# def reload_config():
#     """
#     Force immediate reload of every hot-reloadable YAML config file.
#     Normally configs reload automatically every 5 minutes; call this
#     right after editing a YAML file directly on disk to apply the change
#     immediately instead of waiting. Not needed for any Redis-backed
#     override (thresholds, bands, exception scores, role modifiers, rate
#     limits) — those are already read fresh on every event with no reload
#     step required.
#     """
#     try:
#         reloaded = _invalidate_all_hotconfigs()
#         logger.info("[ADMIN] Config reload triggered — invalidated: %s", reloaded)
#         return {"status": "reloaded", "configs": reloaded}
#     except Exception as exc:
#         logger.error("[ADMIN] Config reload failed: %s", exc)
#         raise HTTPException(status_code=500, detail="Config reload failed") from exc


# # ---------------------------------------------------------------------------
# # Exception score overrides
# #
# # exception_score is ADDITIVE to raw_score (see scoring/engine.py
# # compute_event_score): final = min(100, raw_score + exception_score).
# # The YAML/override default for an unmapped code should be 0 (the additive
# # identity — "no effect"), NOT 1.0 — confirm scoring/engine.py's
# # _get_exception_scoring() default matches before relying on this.
# # ---------------------------------------------------------------------------

# # NOTE: this key MUST match _REDIS_SCORING_OVERRIDES_KEY in scoring/engine.py
# # exactly — a mismatch here means overrides are written but never read
# # during actual scoring.
# _REDIS_EXCEPTION_SCORE_OVERRIDES_KEY = "score:exception_score_overrides"


# class ExceptionScoreOverrideRequest(BaseModel):
#     """Flat point value ADDED to raw_score when this exception_code is present on an event."""
#     adder: int = Field(
#         ...,
#         ge=_MIN_EXCEPTION_ADDER,
#         le=_MAX_EXCEPTION_ADDER,
#         description="Points added to raw_score when this exception_code is present. Must be 0-100.",
#     )


# @router.get("/scoring/exception-score", status_code=status.HTTP_200_OK)
# def get_exception_scores():
#     """
#     List every known exception code with its description, YAML default
#     value, any active Redis override, and the effective adder in use.
#     """
#     from scoring.engine import _exception_scores_config
#     yaml_scores = _exception_scores_config.get()

#     try:
#         raw_overrides = redis_client.hgetall(_REDIS_EXCEPTION_SCORE_OVERRIDES_KEY) or {}
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to fetch score overrides: %s", exc)
#         raw_overrides = {}
#     overrides = {k: float(v) for k, v in raw_overrides.items()}

#     all_codes = set(yaml_scores.keys()) | set(overrides.keys())

#     codes_out = []
#     for code in sorted(all_codes):
#         code_cfg = yaml_scores.get(code)
#         defined_in_yaml = code_cfg is not None
#         yaml_value = code_cfg.get("value", 0.0) if code_cfg else None
#         override_val = overrides.get(code)

#         codes_out.append({
#             "code": code,
#             "description": (
#                 code_cfg.get("description", "") if code_cfg
#                 else "(override only — not defined in exception_scores.yaml)"
#             ),
#             "defined_in_yaml": defined_in_yaml,
#             "yaml_score": yaml_value,
#             "override": override_val,
#             "effective_score": override_val if override_val is not None else (yaml_value or 0.0),
#         })

#     return {"exception_scores": codes_out}


# @router.put("/scoring/exception-score/{code}", status_code=status.HTTP_200_OK)
# def set_exception_score_override(code: str, body: ExceptionScoreOverrideRequest):
#     """
#     Set (or replace) the point-adder for one exception code. Bounded to
#     keep a single misconfigured code from being able to push an otherwise
#     clean event straight to CRITICAL on its own. Takes
#     effect on the very next /v2/score event carrying this exception_code.
#     """
#     try:
#         redis_client.hset(_REDIS_EXCEPTION_SCORE_OVERRIDES_KEY, code, body.adder)
#         logger.warning("[ADMIN] Exception score override set for %s -> %d", code, body.adder)
#         return {"code": code, "adder": body.adder, "status": "override_set"}
#     except Exception as exc:
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# @router.delete("/scoring/exception-score/{code}", status_code=status.HTTP_200_OK)
# def clear_score_override(code: str):
#     """Remove a code's override — reverts to its YAML-defined value (or 0 if unmapped)."""
#     try:
#         removed = redis_client.hdel(_REDIS_EXCEPTION_SCORE_OVERRIDES_KEY, code)
#         if removed == 0:
#             raise HTTPException(status_code=404, detail=f"No score override set for {code}")
#         logger.info("[ADMIN] Score override cleared for %s", code)
#         return {"code": code, "status": "override_cleared"}
#     except HTTPException:
#         raise
#     except Exception as exc:
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# # ---------------------------------------------------------------------------
# # Role modifier overrides
# #
# # role_modifier is MULTIPLICATIVE against a triggered rule's weight (see
# # scoring/engine.py compute_event_score): adjusted = int(weight * modifier).
# # Bounded to [0.0, 1.0] — this is a dampening-only mechanism, not an
# # amplifier (see validate_role_modifier_value in scoring/engine.py).
# #
# # Redis hash is keyed "ROLE:RULE_ID" (e.g. "VISITOR:AUTH-05"), or
# # "ROLE:__all__" to silence every rule for a role in one write — same
# # "__all__" convention as the YAML default (role_modifiers_config.yaml).
# # ---------------------------------------------------------------------------

# # NOTE: this key MUST match _REDIS_ROLE_MODIFIER_OVERRIDES_KEY in
# # scoring/engine.py exactly — a mismatch here means overrides are written
# # but never read during actual scoring. (Same caveat as the exception-score
# # override key above.)
# _REDIS_ROLE_MODIFIER_OVERRIDES_KEY = "score:role_modifier_overrides"


# _ALL_RULES_ALIASES = {"all", "__all__", "*"}


# def _normalize_rule_id(rule_id: str) -> str:
#     """
#     Accept common variants of the "every rule" wildcard (all / __all__ / *,
#     any casing) and normalize to the canonical "__all__" — the ONLY string
#     scoring.engine._get_role_modifier() actually checks. Without this, a
#     caller who PUTs role-modifiers/SYSTEM/all instead of .../__all__ writes
#     a Redis field the scoring engine will never read, and the override
#     silently does nothing — no error, no warning, just a no-op.
#     Any other rule_id passes through unchanged.
#     """
#     if rule_id.strip().lower() in _ALL_RULES_ALIASES:
#         return "__all__"
#     return rule_id


# class RoleModifierOverrideRequest(BaseModel):
#     """Multiplier (0.0-1.0) applied to a rule's weight when triggered by this role."""
#     value: float


# @router.get("/scoring/role-modifiers", status_code=status.HTTP_200_OK)
# def get_role_modifiers():
#     """
#     List every role known to the engine, each rule_id it has a YAML
#     default or active override for, and the resulting effective modifier.

#     Roles with no YAML entries and no overrides are still listed (empty
#     rule map) so an admin UI can add the first override for that role —
#     e.g. CITIZEN ships with no entries, meaning every rule fires at full
#     weight (1.0) for citizens today.
#     """
#     from scoring.engine import _role_modifiers_config
#     yaml_cfg = _role_modifiers_config.get() or {}

#     try:
#         raw_overrides = redis_client.hgetall(_REDIS_ROLE_MODIFIER_OVERRIDES_KEY) or {}
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to fetch role modifier overrides: %s", exc)
#         raw_overrides = {}

#     # raw_overrides keys are "ROLE:RULE_ID" — group them by role.
#     overrides_by_role: dict[str, dict[str, float]] = {}
#     for combined_key, val in raw_overrides.items():
#         if ":" not in combined_key:
#             continue
#         role_part, rule_part = combined_key.split(":", 1)
#         overrides_by_role.setdefault(role_part, {})[rule_part] = float(val)

#     all_roles = _VALID_ROLES | set(yaml_cfg.keys()) | set(overrides_by_role.keys())

#     roles_out = []
#     for role in sorted(all_roles):
#         yaml_rules = yaml_cfg.get(role, {}) or {}
#         role_overrides = overrides_by_role.get(role, {})

#         rule_ids = set(yaml_rules.keys()) | set(role_overrides.keys())
#         rules_out = []
#         for rule_id in sorted(rule_ids):
#             yaml_rule_cfg = yaml_rules.get(rule_id, {})
#             yaml_value = yaml_rule_cfg.get("value") if yaml_rule_cfg else None
#             override_val = role_overrides.get(rule_id)

#             # Effective value follows the same precedence as
#             # scoring.engine._get_role_modifier(): override(exact) >
#             # override(__all__) > yaml(__all__) > yaml(exact) > 1.0.
#             if override_val is not None:
#                 effective = override_val
#             elif role_overrides.get("__all__") is not None and rule_id != "__all__":
#                 effective = role_overrides["__all__"]
#             elif "__all__" in yaml_rules and rule_id != "__all__":
#                 effective = float(yaml_rules["__all__"].get("value", 0.0))
#             elif yaml_value is not None:
#                 effective = yaml_value
#             else:
#                 effective = 1.0

#             rules_out.append({
#                 "rule_id": rule_id,
#                 "description": yaml_rule_cfg.get("description", "") if yaml_rule_cfg else "",
#                 "yaml_value": yaml_value,
#                 "override": override_val,
#                 "effective_value": effective,
#             })

#         roles_out.append({"role": role, "rules": rules_out})

#     return {"role_modifiers": roles_out}


# @router.put("/scoring/role-modifiers/{role}/{rule_id}", status_code=status.HTTP_200_OK)
# def set_role_modifier_override(role: str, rule_id: str, body: RoleModifierOverrideRequest):
#     """
#     Set (or replace) the weight multiplier for one (role, rule_id) pair.
#     Use rule_id="__all__" (or "all"/"*" — normalized automatically) to
#     silence every rule for this role in a single write (takes priority over
#     any other override/YAML entry for the role, except a more specific
#     override already set for an individual rule_id).

#     Validated to [0.0, 1.0] — dampening only. Takes effect on the very
#     next /v2/score event where this role triggers this rule.
#     """
#     role = role.upper()
#     if role not in _VALID_ROLES:
#         raise HTTPException(
#             status_code=400,
#             detail=f"Unknown role '{role}'. Must be one of {sorted(_VALID_ROLES)}",
#         )

#     rule_id = _normalize_rule_id(rule_id)

#     if rule_id != "__all__" and not rule_services(rule_id):
#         raise HTTPException(
#             status_code=404,
#             detail=f"Unknown rule_id '{rule_id}' — not defined in any service rules YAML",
#         )

#     error = validate_role_modifier_value(body.value)
#     if error:
#         raise HTTPException(status_code=422, detail=error)

#     try:
#         redis_client.hset(_REDIS_ROLE_MODIFIER_OVERRIDES_KEY, f"{role}:{rule_id}", body.value)
#         logger.warning(
#             "[ADMIN] Role modifier override set for %s:%s -> %s", role, rule_id, body.value
#         )
#         return {"role": role, "rule_id": rule_id, "value": body.value, "status": "override_set"}
#     except Exception as exc:
#         logger.error(
#             "[ADMIN] Failed to write role modifier override for %s:%s: %s", role, rule_id, exc
#         )
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# @router.delete("/scoring/role-modifiers/{role}/{rule_id}", status_code=status.HTTP_200_OK)
# def clear_role_modifier_override(role: str, rule_id: str):
#     """
#     Remove a role modifier override — reverts to the YAML-defined value
#     (or 1.0 if unmapped).
#     """
#     role = role.upper()
#     rule_id = _normalize_rule_id(rule_id)
#     try:
#         removed = redis_client.hdel(_REDIS_ROLE_MODIFIER_OVERRIDES_KEY, f"{role}:{rule_id}")
#         if removed == 0:
#             raise HTTPException(
#                 status_code=404, detail=f"No role modifier override set for {role}:{rule_id}"
#             )
#         logger.info("[ADMIN] Role modifier override cleared for %s:%s", role, rule_id)
#         return {"role": role, "rule_id": rule_id, "status": "override_cleared"}
#     except HTTPException:
#         raise
#     except Exception as exc:
#         logger.error(
#             "[ADMIN] Failed to clear role modifier override for %s:%s: %s", role, rule_id, exc
#         )
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# # ---------------------------------------------------------------------------
# # Rate limit overrides
# # ---------------------------------------------------------------------------

# _REDIS_RATE_LIMIT_OVERRIDES_KEY = "rate:overrides"


# class RateLimitOverrideRequest(BaseModel):
#     """Requests-per-minute ceiling to apply, for one service or "global"."""
#     rpm: int


# @router.get("/scoring/rate-limits", status_code=status.HTTP_200_OK)
# def get_rate_limits():
#     """
#     List YAML defaults, active Redis overrides, and effective global +
#     per-service RPM ceilings currently enforced by check_rate_limit /
#     check_service_rate_limit.
#     """
#     from core.rate_limiter import _RATE_LIMITS_CONFIG
#     yaml_limits = _RATE_LIMITS_CONFIG.get()
#     try:
#         raw_overrides = redis_client.hgetall(_REDIS_RATE_LIMIT_OVERRIDES_KEY) or {}
#     except Exception as exc:
#         logger.warning("[ADMIN] Failed to fetch rate limit overrides: %s", exc)
#         raw_overrides = {}

#     overrides = {
#         normalize_rate_limit_key(k): int(v) for k, v in raw_overrides.items()
#     }
#     effective_per_service = {
#         **yaml_limits.get("per_service", {}),
#         **{k: v for k, v in overrides.items() if k != "global"},
#     }
#     return {
#         "yaml_limits": yaml_limits,
#         "overrides": overrides,
#         "effective_global": overrides.get("global", yaml_limits.get("global", 2000)),
#         "effective_per_service": effective_per_service,
#     }


# @router.put("/scoring/rate-limits/{service_or_global}", status_code=status.HTTP_200_OK)
# def set_rate_limit_override(service_or_global: str, body: RateLimitOverrideRequest):
#     """
#     Set an RPM ceiling override — service_or_global is either "global"
#     (hard ceiling across all requests from one API key), "default" (the
#     fallback bucket for unrecognized services), or a service name
#     (AUTH/LOGIN/CONSENT/WALLET). Useful during an active incident to
#     quickly throttle a service being hammered, without a deploy.
#     """
#     if body.rpm <= 0:
#         raise HTTPException(status_code=422, detail="rpm must be a positive integer")

#     key = normalize_rate_limit_key(service_or_global)
#     try:
#         redis_client.hset(_REDIS_RATE_LIMIT_OVERRIDES_KEY, key, body.rpm)
#         logger.warning("[ADMIN] Rate limit override set for %s -> %d rpm", key, body.rpm)
#         return {"key": key, "rpm": body.rpm, "status": "override_set"}
#     except Exception as exc:
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc


# @router.delete("/scoring/rate-limits/{service_or_global}", status_code=status.HTTP_200_OK)
# def clear_rate_limit_override(service_or_global: str):
#     """Remove a rate limit override — reverts to the YAML-defined ceiling."""
#     key = normalize_rate_limit_key(service_or_global)  
#     try:
#         removed = redis_client.hdel(_REDIS_RATE_LIMIT_OVERRIDES_KEY, key)
#         if removed == 0:
#             raise HTTPException(status_code=404, detail=f"No rate limit override set for {key}")
#         logger.info("[ADMIN] Rate limit override cleared for %s", key)
#         return {"key": key, "status": "override_cleared"}
#     except HTTPException:
#         raise
#     except Exception as exc:
#         raise HTTPException(status_code=500, detail="Redis write failed") from exc



"""
admin_api.py

Internal operations endpoints for the Fraud Scoring Engine.
Authentication: requires X-API-Key matching FRAUD_ADMIN_KEY (separate from the
scoring API's FRAUD_API_KEY — admin key must never be distributed to integration
partners).

Rate limiting: global limit (check_rate_limit) applies.

Endpoints:
  Rule toggle (dynamic, instant — no cache/TTL delay):
    POST   /v2/admin/rules/{rule_id}/disable
    POST   /v2/admin/rules/{rule_id}/enable
    DELETE /v2/admin/rules/{rule_id}/override   — remove override, revert to YAML

  Rule inspection:
    GET    /v2/admin/rules                      — list every rule + its effective state + description
    GET    /v2/admin/rules?service=AUTH          — filtered to one service
    GET    /v2/admin/scoring/risk-bands         — list score bands + its effective state 

  Per-service threshold overrides (instant, no cache/TTL delay):
    PUT    /v2/admin/rules/{service}/{rule_id}/thresholds
    DELETE /v2/admin/rules/{service}/{rule_id}/thresholds

  Risk-band overrides (instant, global — not per-service):
    PUT    /v2/admin/scoring/risk-bands
    DELETE /v2/admin/scoring/risk-bands

  Exception score overrides (instant, additive to raw_score):
    GET    /v2/admin/scoring/exception-score
    PUT    /v2/admin/scoring/exception-score/{code}
    DELETE /v2/admin/scoring/exception-score/{code}

  Role modifier overrides (instant, multiplicative dampener on rule weight):
    GET    /v2/admin/scoring/role-modifiers
    PUT    /v2/admin/scoring/role-modifiers/{role}/{rule_id}
    DELETE /v2/admin/scoring/role-modifiers/{role}/{rule_id}

  Rate limit overrides (instant):
    GET    /v2/admin/scoring/rate-limits
    PUT    /v2/admin/scoring/rate-limits/{service_or_global}
    DELETE /v2/admin/scoring/rate-limits/{service_or_global}

  IP management (Redis blocklist and Postgres, kept in sync):
    GET    /v2/admin/ip/flagged                 — list both sources + drift between them
    POST   /v2/admin/ip/flag
    DELETE /v2/admin/ip/{ip}

  Config hot-reload (forces every HotConfig instance, plus rule/score
  caches, to reload from disk immediately instead of waiting out their TTL):
    POST   /v2/admin/config/reload

  Portal user role management (users table roles: ADMIN | SERVICE_PROVIDER —
  not the scoring-engine roles managed under /scoring/role-modifiers):
    GET    /v2/admin/users                      — list users (?role, ?is_active, ?search, ?limit, ?offset)
    GET    /v2/admin/users/{user_id}
    PUT    /v2/admin/users/{user_id}/role       — body {"role": "ADMIN" | "SERVICE_PROVIDER", "changed_by": "<optional>"}

# NOTE on scope: the rule-listing / threshold / risk-band endpoints below are
# correctly namespaced per-service. The pre-existing enable/disable endpoints
# above them are UNCHANGED — they still key off a single global `rule:overrides`
# hash by rule_id only, so a rule_id shared across services (e.g.
# DEVICE_SHARED_ACCOUNTS in AUTH/CONSENT/LOGIN/WALLET) toggles everywhere at
# once. That collision is called out explicitly in GET /v2/admin/rules via
# "shared_across_services": true — this is a deliberate design decision.
"""

from dotenv import load_dotenv
load_dotenv()
import ipaddress
import json
import os
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from core.context import VALID_ROLES
from core.logger import logger
from core.rate_limiter import check_rate_limit, normalize_rate_limit_key
from rules.engine import (
    load_rules,
    _is_rule_enabled,
    validate_threshold_payload,
    invalidate_all_rules,
    rule_services,
)
from scoring.engine import (
    validate_risk_bands,
    invalidate_scores,
    validate_role_modifier_value,
)
from storage.redis_client import redis_client
from storage.db import get_db_connection, release_db_connection
from service import user_admin_service as user_admin
from service.ip_reputation import flag_ip, unflag_ip, list_flagged_ips

_REDIS_OVERRIDES_KEY = "rule:overrides"
_REDIS_THRESHOLD_OVERRIDES_KEY = "rule:threshold_overrides"
_REDIS_BAND_OVERRIDES_KEY = "score:band_overrides"


# matching the /app/config/rules/*.yaml layout confirmed for this deployment.
_APP_DIR = Path(__file__).parent

SERVICE_RULE_PATHS: dict[str, str] = {
    "AUTH":    str(_APP_DIR / "config/rules/auth_rules.yaml"),
    "LOGIN":   str(_APP_DIR / "config/rules/login_rules.yaml"),
    "CONSENT": str(_APP_DIR / "config/rules/consent_rules.yaml"),
    "WALLET":  str(_APP_DIR / "config/rules/wallet_rules.yaml"),
}

SCORES_CONFIG_PATH = str(_APP_DIR / "scoring/scores.yaml")

# Rule IDs defined identically across every service YAML that share ONE
# global enable/disable override key — toggling one toggles it everywhere.
_SHARED_RULE_IDS = {
    "DEVICE_SHARED_ACCOUNTS",
    "DEVICE_SHARED_ACCOUNTS_BURST",
    "DEVICE_NEW_DEVICE_ALLOWANCE",
    "DEVICE_SWITCH_VELOCITY",
    "IP_BLOCKLIST_MATCH",
    "GEO_POLICY_VIOLATION",
    "GEO_VELOCITY",
    "BASELINE_BEHAVIOR_ANOMALY",
    "BIOMETRIC_SPOOF_DETECTED",
    "LIVENESS_RESULT_MISSING",
    "UDB_FACE_MISMATCH",
    "ODD_HOUR_ACTIVITY",
}
# Roles known to the engine. Sourced directly from core.context.VALID_ROLES
# — the SAME set that Context's field_validator enforces on incoming events
# — rather than a second hardcoded copy here, so this can never drift out of
# sync with what the engine actually accepts. Used so GET /scoring/role-modifiers
# can show every role (including ones with no overrides/YAML entries yet) and
# so PUT rejects a role that could never appear on a real event anyway.
_VALID_ROLES = VALID_ROLES

_ADMIN_KEY = os.environ.get("FRAUD_ADMIN_KEY", "")

# At import time it blocks startup
# entirely, which is the correct failure mode for a config error this
# serious (fail fast, same posture as the FRAUD_API_KEY/FRAUD_ADMIN_KEY/
# JWT_SECRET presence checks in api.py's lifespan).
_SCORING_KEY = os.environ.get("FRAUD_API_KEY", "")
if _ADMIN_KEY and _SCORING_KEY and _ADMIN_KEY == _SCORING_KEY:
    raise RuntimeError(
        "FRAUD_ADMIN_KEY and FRAUD_API_KEY must not be equal — this would "
        "grant every scoring integration partner full admin access."
    )

# ExceptionScoreOverrideRequest below uses these constants.
_MIN_EXCEPTION_ADDER = 0
_MAX_EXCEPTION_ADDER = 100


def require_admin_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """
    FastAPI dependency — gates every route in this router behind the admin
    key (FRAUD_ADMIN_KEY), separate from the scoring API's FRAUD_API_KEY.
    Never share this key with integration partners.
    """
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
# Rule toggle
# ---------------------------------------------------------------------------

@router.post("/rules/{rule_id}/disable", status_code=status.HTTP_200_OK)
def disable_rule(rule_id: str):
    """
    Force a rule OFF regardless of its YAML `enabled` flag.
    Writes "disabled" to the rule:overrides Redis hash — read fresh on
    every event (no cache/TTL), so this takes effect on the very next
    /v2/score call. For _SHARED_RULE_IDS this disables the rule across
    ALL services, not just one.
    """
    services = rule_services(rule_id)
    if not services:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown rule_id '{rule_id}' — not defined in any service rules YAML",
        )
    try:
        redis_client.hset(_REDIS_OVERRIDES_KEY, rule_id, "disabled")
        logger.warning("[ADMIN] Rule %s disabled via admin API (services=%s)", rule_id, services)
        return {"rule_id": rule_id, "status": "disabled", "services": services}
    except Exception as exc:
        logger.error("[ADMIN] Failed to disable rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.post("/rules/{rule_id}/enable", status_code=status.HTTP_200_OK)
def enable_rule(rule_id: str):
    """
    Force a rule ON regardless of its YAML `enabled` flag (useful for
    testing a rule that's normally disabled). Same instant-effect,
    same shared-rule-id caveat as disable_rule() above.
    """
    services = rule_services(rule_id)  
    if not services:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown rule_id '{rule_id}' — not defined in any service rules YAML",
        )
    try:
        redis_client.hset(_REDIS_OVERRIDES_KEY, rule_id, "enabled")
        logger.info("[ADMIN] Rule %s enabled via admin API (services=%s)", rule_id, services)
        return {"rule_id": rule_id, "status": "enabled", "services": services}
    except Exception as exc:
        logger.error("[ADMIN] Failed to enable rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.delete("/rules/{rule_id}/override", status_code=status.HTTP_200_OK)
def clear_rule_override(rule_id: str):
    """
    Remove any enable/disable override for this rule — reverts to
    whatever the YAML `enabled` flag says. 404 if no override was active.
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
# Rule inspection
# ---------------------------------------------------------------------------

@router.get("/rules", status_code=status.HTTP_200_OK)
def list_rules(service: Optional[str] = None):
    """
    List every rule (optionally filtered to one service via ?service=),
    with its human-readable description, YAML default, any active
    Redis override, and the resulting effective enabled/disabled state
    and threshold bands.

    This is the single source of truth a frontend rule-management screen
    should build its table from — every field a "view/edit rule" UI needs
    (name, description, current on/off state, current thresholds, whether
    toggling it is a global/shared action) is returned per rule here.
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
                "description": rule_def.get("description", ""),   # human-readable, from rules.yaml
                "yaml_enabled": yaml_enabled,
                "override": override_val,
                "effective_enabled": _is_rule_enabled(rule_id, yaml_enabled, overrides),
                "shared_across_services": rule_id in _SHARED_RULE_IDS,
                # Threshold state — this is what a "modify thresholds" UI should pre-fill from.
                "yaml_thresholds": yaml_thresholds,
                "threshold_override": threshold_override,       
                "effective_thresholds": threshold_override if threshold_override is not None else yaml_thresholds,
            })

    return {"rules": rules_out}


@router.get("/scoring/risk-bands", status_code=status.HTTP_200_OK)
def get_risk_bands():
    """
    Return the current risk-band state: YAML default (scores.yaml),
    any active Redis override, and the effective bands actually being
    used to classify scores right now. Pre-fills a "modify risk bands" UI.
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
# Per-service threshold overrides
# ---------------------------------------------------------------------------

class ThresholdBand(BaseModel):
    """One [min, max?, weight] band. max omitted = open-ended (>= min)."""
    min: float
    max: Optional[float] = None
    weight: int


class ThresholdOverrideRequest(BaseModel):
    """Full replacement band list for one (service, rule_id) threshold override."""
    thresholds: list[ThresholdBand]


@router.put("/rules/{service}/{rule_id}/thresholds", status_code=status.HTTP_200_OK)
def set_threshold_override(service: str, rule_id: str, body: ThresholdOverrideRequest):
    """
    Replace a rule's threshold bands for one service. Validated for
    ordering/overlap before writing (validate_threshold_payload). Takes
    effect on the very next /v2/score event evaluating this rule — no
    cache, no reload needed.
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
    Remove a threshold override — reverts to YAML-defined bands immediately.
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
# Risk-band overrides
# ---------------------------------------------------------------------------

class RiskBandsRequest(BaseModel):
    """
    Full risk-band set — [min, max] per band. Must cover 0-100 with no
    gaps/overlaps (validated by validate_risk_bands). This is atomic:
    unlike thresholds, you cannot update one band alone — every PUT must
    supply the complete set.
    """
    NORISK: list[float]
    LOW: list[float]
    MEDIUM: list[float]
    HIGH: list[float]
    CRITICAL: list[float]


@router.put("/scoring/risk-bands", status_code=status.HTTP_200_OK)
def set_risk_bands(body: RiskBandsRequest):
    """
    Overwrite the entire risk-band set. Global (not per-service) — every
    /v2/score call across every service uses these bands the moment this
    write succeeds. Highest-blast-radius endpoint in this file; consider
    a confirmation step in the frontend before calling this.
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
    """IP to add to the blocklist, with an optional operator-supplied reason."""
    ip: str
    added_by: str = Field(..., min_length=1, max_length=128)
    reason: str = Field("manual_admin_flag", min_length=1, max_length=100)

    @field_validator("ip")
    @classmethod
    def ip_valid(cls, v):
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"invalid IP address: {v!r}")
        return v


@router.get("/ip/flagged", status_code=status.HTTP_200_OK)
def get_flagged_ips():
    """
    List currently flagged IPs from both sources, plus drift between them:
      db    — active Postgres rows (src_ip, flag_reason, flagged_by, flagged_at)
      redis — members of the ip:flagged set, which is what IP_BLOCKLIST_MATCH
              actually reads at scoring time
      drift — in_db_not_redis: recorded but NOT enforced (usually a Redis
              flush/restart without a re-seed); in_redis_not_db: enforced
              but has no audit record
    """
    db = get_db_connection()
    try:
        return list_flagged_ips(db_connection=db)
    except Exception as exc:
        logger.exception("[ADMIN] Failed to list flagged IPs: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read blocklist state") from exc
    finally:
        release_db_connection(db)


@router.post("/ip/flag", status_code=status.HTTP_200_OK)
def flag_ip_route(body: IPFlagRequest):
    """
    Add an IP to both blocklist sources kept in sync: Postgres (durable
    audit record) and Redis (hot-path lookup used by IP scoring).
    Records which admin key performed the flag.
    """
    db = get_db_connection()
    try:
        flag_ip(body.ip, reason=body.reason, db_connection=db, flagged_by=body.added_by)
        db.commit()
        logger.warning("[ADMIN] IP %s added to blocklist — reason: %s", body.ip, body.reason)
        return {"ip": body.ip, "status": "blocked"}
    except RuntimeError as exc:
        db.rollback()
        logger.error("[ADMIN] Failed to flag IP %s: %s", body.ip, exc)
        raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
    except Exception as exc:
        db.rollback()
        logger.error("[ADMIN] Failed to flag IP %s: %s", body.ip, exc)
        raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
    finally:
        release_db_connection(db)


@router.delete("/ip/{ip}", status_code=status.HTTP_200_OK)
def unflag_ip_route(ip: str):
    """Remove an IP from both blocklist sources. 404 if not currently flagged in the DB."""
    db = get_db_connection()
    try:
        found = unflag_ip(ip, db_connection=db)
        db.commit()
        if not found:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"IP {ip} not found in blocklist",
            )
        logger.info("[ADMIN] IP %s removed from blocklist", ip)
        return {"ip": ip, "status": "unblocked"}
    except HTTPException:
        raise
    except RuntimeError as exc:
        db.rollback()
        logger.error("[ADMIN] Failed to remove IP %s: %s", ip, exc)
        raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
    except Exception as exc:
        db.rollback()
        logger.error("[ADMIN] Failed to remove IP %s: %s", ip, exc)
        raise HTTPException(status_code=500, detail="Failed to update blocklist") from exc
    finally:
        release_db_connection(db)


# ---------------------------------------------------------------------------
# Config hot-reload
# ---------------------------------------------------------------------------

def _invalidate_all_hotconfigs() -> list[str]:
    """
    Force every HotConfig instance in the engine — plus the separate
    rules.yaml/scores.yaml caches, which have their own invalidate
    functions rather than being plain HotConfig instances — to reload
    from disk on their next .get() call, instead of waiting out their
    normal 5-minute TTL. Returns the list of config names successfully
    invalidated (a partial failure on one config does not block the rest).
    """
    from scoring.engine import _exception_scores_config, _role_modifiers_config
    from scoring.profile_amplifier import _profile_amp_config
    from service.session_service import _session_config
    from service.profile_service import _patterns_config
    from storage.profile_repo import _weights_config
    from features.geo_features import _GEO_POLICY_CONFIG
    from core.rate_limiter import _RATE_LIMITS_CONFIG
    from core.idempotency import _IDEMPOTENCY_CONFIG

    configs = {
        "exception_scores":       _exception_scores_config,
        "role_modifiers":         _role_modifiers_config,
        "session_config":         _session_config,
        "cross_service_patterns": _patterns_config,
        "service_weights":        _weights_config,
        "geo_policy":             _GEO_POLICY_CONFIG,
        "rate_limits":            _RATE_LIMITS_CONFIG,
        "idempotency_config":     _IDEMPOTENCY_CONFIG,
        "profile_amplifier":      _profile_amp_config,
    }

    reloaded = []
    for name, cfg in configs.items():
        try:
            cfg.invalidate()
            reloaded.append(name)
        except Exception as exc:
            logger.warning("[ADMIN] Failed to invalidate config %s: %s", name, exc)

    try:
        invalidate_all_rules()
        reloaded.append("rules")
    except Exception as exc:
        logger.warning("[ADMIN] Failed to invalidate rules: %s", exc)

    try:
        invalidate_scores()
        reloaded.append("scores")
    except Exception as exc:
        logger.warning("[ADMIN] Failed to invalidate scores: %s", exc)

    return reloaded


@router.post("/config/reload", status_code=status.HTTP_200_OK)
def reload_config():
    """
    Force immediate reload of every hot-reloadable YAML config file.
    Normally configs reload automatically every 5 minutes; call this
    right after editing a YAML file directly on disk to apply the change
    immediately instead of waiting. Not needed for any Redis-backed
    override (thresholds, bands, exception scores, role modifiers, rate
    limits) — those are already read fresh on every event with no reload
    step required.
    """
    try:
        reloaded = _invalidate_all_hotconfigs()
        logger.info("[ADMIN] Config reload triggered — invalidated: %s", reloaded)
        return {"status": "reloaded", "configs": reloaded}
    except Exception as exc:
        logger.error("[ADMIN] Config reload failed: %s", exc)
        raise HTTPException(status_code=500, detail="Config reload failed") from exc


# ---------------------------------------------------------------------------
# Exception score overrides
#
# exception_score is ADDITIVE to raw_score (see scoring/engine.py
# compute_event_score): final = min(100, raw_score + exception_score).
# The YAML/override default for an unmapped code should be 0 (the additive
# identity — "no effect"), NOT 1.0 — confirm scoring/engine.py's
# _get_exception_scoring() default matches before relying on this.
# ---------------------------------------------------------------------------

# NOTE: this key MUST match _REDIS_SCORING_OVERRIDES_KEY in scoring/engine.py
# exactly — a mismatch here means overrides are written but never read
# during actual scoring.
_REDIS_EXCEPTION_SCORE_OVERRIDES_KEY = "score:exception_score_overrides"


class ExceptionScoreOverrideRequest(BaseModel):
    """Flat point value ADDED to raw_score when this exception_code is present on an event."""
    adder: int = Field(
        ...,
        ge=_MIN_EXCEPTION_ADDER,
        le=_MAX_EXCEPTION_ADDER,
        description="Points added to raw_score when this exception_code is present. Must be 0-100.",
    )


@router.get("/scoring/exception-score", status_code=status.HTTP_200_OK)
def get_exception_scores():
    """
    List every known exception code with its description, YAML default
    value, any active Redis override, and the effective adder in use.
    """
    from scoring.engine import _exception_scores_config
    yaml_scores = _exception_scores_config.get()

    try:
        raw_overrides = redis_client.hgetall(_REDIS_EXCEPTION_SCORE_OVERRIDES_KEY) or {}
    except Exception as exc:
        logger.warning("[ADMIN] Failed to fetch score overrides: %s", exc)
        raw_overrides = {}
    overrides = {k: float(v) for k, v in raw_overrides.items()}

    all_codes = set(yaml_scores.keys()) | set(overrides.keys())

    codes_out = []
    for code in sorted(all_codes):
        code_cfg = yaml_scores.get(code)
        defined_in_yaml = code_cfg is not None
        yaml_value = code_cfg.get("value", 0.0) if code_cfg else None
        override_val = overrides.get(code)

        codes_out.append({
            "code": code,
            "description": (
                code_cfg.get("description", "") if code_cfg
                else "(override only — not defined in exception_scores.yaml)"
            ),
            "defined_in_yaml": defined_in_yaml,
            "yaml_score": yaml_value,
            "override": override_val,
            "effective_score": override_val if override_val is not None else (yaml_value or 0.0),
        })

    return {"exception_scores": codes_out}


@router.put("/scoring/exception-score/{code}", status_code=status.HTTP_200_OK)
def set_exception_score_override(code: str, body: ExceptionScoreOverrideRequest):
    """
    Set (or replace) the point-adder for one exception code. Bounded to
    keep a single misconfigured code from being able to push an otherwise
    clean event straight to CRITICAL on its own. Takes
    effect on the very next /v2/score event carrying this exception_code.
    """
    try:
        redis_client.hset(_REDIS_EXCEPTION_SCORE_OVERRIDES_KEY, code, body.adder)
        logger.warning("[ADMIN] Exception score override set for %s -> %d", code, body.adder)
        return {"code": code, "adder": body.adder, "status": "override_set"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.delete("/scoring/exception-score/{code}", status_code=status.HTTP_200_OK)
def clear_score_override(code: str):
    """Remove a code's override — reverts to its YAML-defined value (or 0 if unmapped)."""
    try:
        removed = redis_client.hdel(_REDIS_EXCEPTION_SCORE_OVERRIDES_KEY, code)
        if removed == 0:
            raise HTTPException(status_code=404, detail=f"No score override set for {code}")
        logger.info("[ADMIN] Score override cleared for %s", code)
        return {"code": code, "status": "override_cleared"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


# ---------------------------------------------------------------------------
# Role modifier overrides
#
# role_modifier is MULTIPLICATIVE against a triggered rule's weight (see
# scoring/engine.py compute_event_score): adjusted = int(weight * modifier).
# Bounded to [0.0, 1.0] — this is a dampening-only mechanism, not an
# amplifier (see validate_role_modifier_value in scoring/engine.py).
#
# Redis hash is keyed "ROLE:RULE_ID" (e.g. "VISITOR:GEO_VELOCITY"), or
# "ROLE:__all__" to silence every rule for a role in one write — same
# "__all__" convention as the YAML default (role_modifiers_config.yaml).
# ---------------------------------------------------------------------------

# NOTE: this key MUST match _REDIS_ROLE_MODIFIER_OVERRIDES_KEY in
# scoring/engine.py exactly — a mismatch here means overrides are written
# but never read during actual scoring. (Same caveat as the exception-score
# override key above.)
_REDIS_ROLE_MODIFIER_OVERRIDES_KEY = "score:role_modifier_overrides"


_ALL_RULES_ALIASES = {"all", "__all__", "*"}


def _normalize_rule_id(rule_id: str) -> str:
    """
    Accept common variants of the "every rule" wildcard (all / __all__ / *,
    any casing) and normalize to the canonical "__all__" — the ONLY string
    scoring.engine._get_role_modifier() actually checks. Without this, a
    caller who PUTs role-modifiers/SYSTEM/all instead of .../__all__ writes
    a Redis field the scoring engine will never read, and the override
    silently does nothing — no error, no warning, just a no-op.
    Any other rule_id passes through unchanged.
    """
    if rule_id.strip().lower() in _ALL_RULES_ALIASES:
        return "__all__"
    return rule_id


class RoleModifierOverrideRequest(BaseModel):
    """Multiplier (0.0-1.0) applied to a rule's weight when triggered by this role."""
    value: float


@router.get("/scoring/role-modifiers", status_code=status.HTTP_200_OK)
def get_role_modifiers():
    """
    List every role known to the engine, each rule_id it has a YAML
    default or active override for, and the resulting effective modifier.

    Roles with no YAML entries and no overrides are still listed (empty
    rule map) so an admin UI can add the first override for that role —
    e.g. CITIZEN ships with no entries, meaning every rule fires at full
    weight (1.0) for citizens today.
    """
    from scoring.engine import _role_modifiers_config
    yaml_cfg = _role_modifiers_config.get() or {}

    try:
        raw_overrides = redis_client.hgetall(_REDIS_ROLE_MODIFIER_OVERRIDES_KEY) or {}
    except Exception as exc:
        logger.warning("[ADMIN] Failed to fetch role modifier overrides: %s", exc)
        raw_overrides = {}

    # raw_overrides keys are "ROLE:RULE_ID" — group them by role.
    overrides_by_role: dict[str, dict[str, float]] = {}
    for combined_key, val in raw_overrides.items():
        if ":" not in combined_key:
            continue
        role_part, rule_part = combined_key.split(":", 1)
        overrides_by_role.setdefault(role_part, {})[rule_part] = float(val)

    all_roles = _VALID_ROLES | set(yaml_cfg.keys()) | set(overrides_by_role.keys())

    roles_out = []
    for role in sorted(all_roles):
        yaml_rules = yaml_cfg.get(role, {}) or {}
        role_overrides = overrides_by_role.get(role, {})

        rule_ids = set(yaml_rules.keys()) | set(role_overrides.keys())
        rules_out = []
        for rule_id in sorted(rule_ids):
            yaml_rule_cfg = yaml_rules.get(rule_id, {})
            yaml_value = yaml_rule_cfg.get("value") if yaml_rule_cfg else None
            override_val = role_overrides.get(rule_id)

            # Effective value follows the same precedence as
            # scoring.engine._get_role_modifier(): override(exact) >
            # override(__all__) > yaml(__all__) > yaml(exact) > 1.0.
            if override_val is not None:
                effective = override_val
            elif role_overrides.get("__all__") is not None and rule_id != "__all__":
                effective = role_overrides["__all__"]
            elif "__all__" in yaml_rules and rule_id != "__all__":
                effective = float(yaml_rules["__all__"].get("value", 0.0))
            elif yaml_value is not None:
                effective = yaml_value
            else:
                effective = 1.0

            rules_out.append({
                "rule_id": rule_id,
                "description": yaml_rule_cfg.get("description", "") if yaml_rule_cfg else "",
                "yaml_value": yaml_value,
                "override": override_val,
                "effective_value": effective,
            })

        roles_out.append({"role": role, "rules": rules_out})

    return {"role_modifiers": roles_out}


@router.put("/scoring/role-modifiers/{role}/{rule_id}", status_code=status.HTTP_200_OK)
def set_role_modifier_override(role: str, rule_id: str, body: RoleModifierOverrideRequest):
    """
    Set (or replace) the weight multiplier for one (role, rule_id) pair.
    Use rule_id="__all__" (or "all"/"*" — normalized automatically) to
    silence every rule for this role in a single write (takes priority over
    any other override/YAML entry for the role, except a more specific
    override already set for an individual rule_id).

    Validated to [0.0, 1.0] — dampening only. Takes effect on the very
    next /v2/score event where this role triggers this rule.
    """
    role = role.upper()
    if role not in _VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown role '{role}'. Must be one of {sorted(_VALID_ROLES)}",
        )

    rule_id = _normalize_rule_id(rule_id)

    if rule_id != "__all__" and not rule_services(rule_id):
        raise HTTPException(
            status_code=404,
            detail=f"Unknown rule_id '{rule_id}' — not defined in any service rules YAML",
        )

    error = validate_role_modifier_value(body.value)
    if error:
        raise HTTPException(status_code=422, detail=error)

    try:
        redis_client.hset(_REDIS_ROLE_MODIFIER_OVERRIDES_KEY, f"{role}:{rule_id}", body.value)
        logger.warning(
            "[ADMIN] Role modifier override set for %s:%s -> %s", role, rule_id, body.value
        )
        return {"role": role, "rule_id": rule_id, "value": body.value, "status": "override_set"}
    except Exception as exc:
        logger.error(
            "[ADMIN] Failed to write role modifier override for %s:%s: %s", role, rule_id, exc
        )
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.delete("/scoring/role-modifiers/{role}/{rule_id}", status_code=status.HTTP_200_OK)
def clear_role_modifier_override(role: str, rule_id: str):
    """
    Remove a role modifier override — reverts to the YAML-defined value
    (or 1.0 if unmapped).
    """
    role = role.upper()
    rule_id = _normalize_rule_id(rule_id)
    try:
        removed = redis_client.hdel(_REDIS_ROLE_MODIFIER_OVERRIDES_KEY, f"{role}:{rule_id}")
        if removed == 0:
            raise HTTPException(
                status_code=404, detail=f"No role modifier override set for {role}:{rule_id}"
            )
        logger.info("[ADMIN] Role modifier override cleared for %s:%s", role, rule_id)
        return {"role": role, "rule_id": rule_id, "status": "override_cleared"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "[ADMIN] Failed to clear role modifier override for %s:%s: %s", role, rule_id, exc
        )
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


# ---------------------------------------------------------------------------
# Rate limit overrides
# ---------------------------------------------------------------------------

_REDIS_RATE_LIMIT_OVERRIDES_KEY = "rate:overrides"


class RateLimitOverrideRequest(BaseModel):
    """Requests-per-minute ceiling to apply, for one service or "global"."""
    rpm: int


@router.get("/scoring/rate-limits", status_code=status.HTTP_200_OK)
def get_rate_limits():
    """
    List YAML defaults, active Redis overrides, and effective global +
    per-service RPM ceilings currently enforced by check_rate_limit /
    check_service_rate_limit.
    """
    from core.rate_limiter import _RATE_LIMITS_CONFIG
    yaml_limits = _RATE_LIMITS_CONFIG.get()
    try:
        raw_overrides = redis_client.hgetall(_REDIS_RATE_LIMIT_OVERRIDES_KEY) or {}
    except Exception as exc:
        logger.warning("[ADMIN] Failed to fetch rate limit overrides: %s", exc)
        raw_overrides = {}

    overrides = {
        normalize_rate_limit_key(k): int(v) for k, v in raw_overrides.items()
    }
    effective_per_service = {
        **yaml_limits.get("per_service", {}),
        **{k: v for k, v in overrides.items() if k != "global"},
    }
    return {
        "yaml_limits": yaml_limits,
        "overrides": overrides,
        "effective_global": overrides.get("global", yaml_limits.get("global", 2000)),
        "effective_per_service": effective_per_service,
    }


@router.put("/scoring/rate-limits/{service_or_global}", status_code=status.HTTP_200_OK)
def set_rate_limit_override(service_or_global: str, body: RateLimitOverrideRequest):
    """
    Set an RPM ceiling override — service_or_global is either "global"
    (hard ceiling across all requests from one API key), "default" (the
    fallback bucket for unrecognized services), or a service name
    (AUTH/LOGIN/CONSENT/WALLET). Useful during an active incident to
    quickly throttle a service being hammered, without a deploy.
    """
    if body.rpm <= 0:
        raise HTTPException(status_code=422, detail="rpm must be a positive integer")

    key = normalize_rate_limit_key(service_or_global)
    try:
        redis_client.hset(_REDIS_RATE_LIMIT_OVERRIDES_KEY, key, body.rpm)
        logger.warning("[ADMIN] Rate limit override set for %s -> %d rpm", key, body.rpm)
        return {"key": key, "rpm": body.rpm, "status": "override_set"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


@router.delete("/scoring/rate-limits/{service_or_global}", status_code=status.HTTP_200_OK)
def clear_rate_limit_override(service_or_global: str):
    """Remove a rate limit override — reverts to the YAML-defined ceiling."""
    key = normalize_rate_limit_key(service_or_global)  
    try:
        removed = redis_client.hdel(_REDIS_RATE_LIMIT_OVERRIDES_KEY, key)
        if removed == 0:
            raise HTTPException(status_code=404, detail=f"No rate limit override set for {key}")
        logger.info("[ADMIN] Rate limit override cleared for %s", key)
        return {"key": key, "status": "override_cleared"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Redis write failed") from exc


# ---------------------------------------------------------------------------
# Portal user role management
#
# Manages the portal login roles in the users table (ADMIN | SERVICE_PROVIDER).
# NOT to be confused with /scoring/role-modifiers above, which manages the
# event-actor roles (VALID_ROLES from core.context) used by the scoring engine.
#
# Same auth as every other route here (X-API-Key + global rate limit, via the
# router's dependencies). The API key carries no user identity, so the caller
# can optionally pass `changed_by` for the audit log (same idea as
# IPFlagRequest.added_by). Business rules live in service/user_admin_service.py.
# ---------------------------------------------------------------------------

_USER_ADMIN_ERROR_STATUS = {
    user_admin.InvalidRoleError:  status.HTTP_400_BAD_REQUEST,
    user_admin.UserNotFoundError: status.HTTP_404_NOT_FOUND,
    user_admin.LastAdminError:    status.HTTP_409_CONFLICT,
}


def _user_admin_http_error(exc: user_admin.UserAdminError) -> HTTPException:
    """Map an expected service-layer failure to its HTTP response."""
    return HTTPException(
        status_code=_USER_ADMIN_ERROR_STATUS.get(type(exc), status.HTTP_400_BAD_REQUEST),
        detail=str(exc),
    )


class UserRoleRequest(BaseModel):
    """New portal role for a user: ADMIN or SERVICE_PROVIDER (case-insensitive)."""
    role: str
    changed_by: Optional[str] = Field(
        None,
        max_length=100,
        description="Optional: who is making the change, recorded in the audit log only.",
    )

    class Config:
        extra = "forbid"


@router.get("/users", status_code=status.HTTP_200_OK)
def list_portal_users(
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = Query(None, max_length=100),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    List portal users, newest first, with optional filters: ?role=ADMIN,
    ?is_active=true, ?search= (matches name, username or email,
    case-insensitive). Password hashes are never returned.
    """
    db = get_db_connection()
    try:
        return user_admin.list_users(
            db, role=role, is_active=is_active, search=search, limit=limit, offset=offset
        )
    except user_admin.UserAdminError as exc:
        raise _user_admin_http_error(exc) from exc
    except RuntimeError as exc:
        logger.error("[ADMIN] Failed to list portal users: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read users") from exc
    except Exception as exc:
        logger.exception("[ADMIN] Failed to list portal users")
        raise HTTPException(status_code=500, detail="Failed to read users") from exc
    finally:
        release_db_connection(db)


@router.get("/users/{user_id}", status_code=status.HTTP_200_OK)
def get_portal_user(user_id: UUID):
    """Return one portal user by id. 404 if it does not exist."""
    db = get_db_connection()
    try:
        return {"user": user_admin.get_user(db, str(user_id))}
    except user_admin.UserAdminError as exc:
        raise _user_admin_http_error(exc) from exc
    except RuntimeError as exc:
        logger.error("[ADMIN] Failed to read portal user %s: %s", user_id, exc)
        raise HTTPException(status_code=500, detail="Failed to read user") from exc
    except Exception as exc:
        logger.exception("[ADMIN] Failed to read portal user %s", user_id)
        raise HTTPException(status_code=500, detail="Failed to read user") from exc
    finally:
        release_db_connection(db)


@router.put("/users/{user_id}/role", status_code=status.HTTP_200_OK)
def set_portal_user_role(user_id: UUID, body: UserRoleRequest):
    """
    Change a portal user's role. Rules enforced by the service layer:
      - role must be ADMIN or SERVICE_PROVIDER (400 otherwise)
      - the last active ADMIN cannot be demoted (409)
      - setting the role a user already has is a no-op (200, status
        "role_unchanged")
    Tokens already issued to the user still carry the old role claim until
    they expire (JWT_EXPIRY_HOURS).
    """
    db = get_db_connection()
    try:
        result = user_admin.change_user_role(
            db,
            target_id=str(user_id),
            new_role=body.role,
        )
        db.commit()

        user = result["user"]
        if result["changed"]:
            logger.warning(
                "[ADMIN] Portal role changed by=%s target=%s (%s) %s -> %s",
                body.changed_by or "unspecified", user["username"], user["id"],
                result["previous_role"], user["role"],
            )
        return {
            "status": "role_updated" if result["changed"] else "role_unchanged",
            "previous_role": result["previous_role"],
            "user": user,
        }

    except user_admin.UserAdminError as exc:
        db.rollback()
        raise _user_admin_http_error(exc) from exc
    except RuntimeError as exc:
        db.rollback()
        logger.error("[ADMIN] Failed to change role for user %s: %s", user_id, exc)
        raise HTTPException(status_code=500, detail="Failed to update role") from exc
    except Exception as exc:
        db.rollback()
        logger.exception("[ADMIN] Failed to change role for user %s", user_id)
        raise HTTPException(status_code=500, detail="Failed to update role") from exc
    finally:
        release_db_connection(db)