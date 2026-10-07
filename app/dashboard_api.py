"""
dashboard_api.py

FastAPI router for the fraud dashboard.

All routes are under /fraud prefix.

Sections:
  Event Intelligence    GET /fraud/events/kpis
  Actions & Decisions   GET /fraud/actions/stats
  Score Distribution    GET /fraud/scores/distribution
  Risk Bands            GET /fraud/risk/bands
  Rules & Chains        GET /fraud/rules/stats
  IP & Device           GET /fraud/threats/summary
  Sessions              GET /fraud/sessions
  Cross-Service Flags   GET /fraud/cross-service/flags
  Action Outcomes       GET /users/{subject_id}/actions
  Transactions          GET /fraud/transactions
  Transaction Detail    GET /fraud/transactions/{event_id}
  Role Analytics        GET /fraud/roles/stats

  Legacy chart routes kept for backward compatibility:
  GET /fraud/kpis
  GET /fraud/charts/risk-trend
  GET /fraud/charts/fraud-type
  GET /fraud/charts/risk-classification
  GET /fraud/charts/source-volume
"""
import re
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from core.constants import VALID_SERVICES, RISK_LEVELS_SET
from core.ids import normalize_event_id
from datetime import datetime
from portal_auth_api import require_portal_user
from storage.db import get_db_connection, release_db_connection
from storage.dashboard_repo import (
    fetch_event_kpis,
    fetch_action_stats,
    fetch_score_distribution,
    fetch_risk_band_stats,
    fetch_rules_stats,
    fetch_ip_threat_stats,
    fetch_sessions,
    fetch_cross_service_flag_stats,
    fetch_user_action_outcomes,
    fetch_transactions,
    fetch_transaction_detail,
    fetch_role_stats,
    # legacy aliases
    fetch_kpis,
    risk_trend_over_time,
    fraud_type_stats,
    risk_classification_stats,
    source_volume_stats,
)

router = APIRouter(
    prefix="/fraud",
    tags=["Fraud Dashboard"],
    dependencies=[Depends(require_portal_user)],
)


# ---------------------------------------------------------------------------
# helper — removes boilerplate try/finally on every route
# ---------------------------------------------------------------------------

def _with_db(fn):
    """Open a DB connection, call fn(db), close it, return result."""
    db = get_db_connection()
    try:
        return fn(db)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Internal server error") from exc
    finally:
        release_db_connection(db)   # return to pool, don't destroy the connection



# =============================================================================
# SECTION 1 — EVENT INTELLIGENCE
# =============================================================================

@router.get(
    "/events/kpis",
    summary="Event intelligence KPIs",
    description=(
        "Total events received vs scored, duplicates blocked, throughput, "
        "unique users, breakdown by service / environment / source, "
        "exception code stats, session presence counts."
    ),
)
def get_event_kpis():
    return _with_db(fetch_event_kpis)


# =============================================================================
# SECTION 2 — ACTIONS & DECISIONS
# =============================================================================

@router.get(
    "/actions/stats",
    summary="Action counts, risk trend, source volume",
    description=(
        "Count per action recieved"
        "risk trend last 24h (hourly), source volume last 24h (hourly)."
    ),
)
def get_action_stats():
    return _with_db(fetch_action_stats)


# =============================================================================
# SECTION 3 — SCORE DISTRIBUTION
# =============================================================================

@router.get(
    "/scores/distribution",
    summary="Score histogram and averages",
    description=(
        "overall average score"
        "average score per service"
    ),
)
def get_score_distribution():
    return _with_db(fetch_score_distribution)


# =============================================================================
# SECTION 4 — RISK BAND ANALYTICS
# =============================================================================

@router.get(
    "/risk/bands",
    summary="Risk band counts and breakdown per service",
    description=(
        "Count per band (NORISK/LOW/MEDIUM/HIGH/CRITICAL), "
        "cross-tab of risk band × service for heatmap display."
    ),
)
def get_risk_band_stats():
    return _with_db(fetch_risk_band_stats)


# =============================================================================
# SECTION 5 — RULES & CHAINS
# =============================================================================

@router.get(
    "/rules/stats",
    summary="Top triggered rules and chain activation counts",
    description=(
        "Top 15 most triggered rules by frequency, "
        "count of each named chain that fired (co-occurrence of all trigger rules), "
        "total chain applications ever."
    ),
)
def get_rules_stats():
    return _with_db(fetch_rules_stats)


# =============================================================================
# SECTION 6 — IP THREATS
# =============================================================================

@router.get(
    "/threats/summary",
    summary="Flagged IPs",
    description=(
        "Total active flagged IPs, events from flagged IPs, full IP list."
    ),
)
def get_threat_summary():
    return _with_db(fetch_ip_threat_stats)


# =============================================================================
# SECTION 7 — SESSIONS PANEL
# =============================================================================

@router.get(
    "/sessions",
    summary="Paginated session list with aggregate summary",
    description=(
        "Summary: total sessions, sessions with critical events, sessions where "
        "amplifier was applied, avg events per session. "
        "Paginated table: session_id, subject_id, event_count, high_event_count, "
        "has_critical, max_score, session_risk_level, first/last event timestamps."
    ),
)
def get_sessions(
    page:  int = Query(default=1,  ge=1,  description="Page number"),
    limit: int = Query(default=20, ge=1, le=100, description="Rows per page"),
):
    return _with_db(lambda db: fetch_sessions(db, page=page, limit=limit))


# =============================================================================
# SECTION 8 — CROSS-SERVICE FLAGS (global)
# =============================================================================

@router.get(
    "/cross-service/flags",
    summary="Global cross-service fraud flag stats",
    description=(
        "Total users with cross_service_flag=true, breakdown by reason "
        "(HIGH_AUTH_BEFORE_WALLET_30MIN etc.), list of flagged users "
        "sorted by composite score desc."
    ),
)
def get_cross_service_flags():
    return _with_db(fetch_cross_service_flag_stats)


# =============================================================================
# SECTION 9 — PER-USER ACTIONS TAKEN
# =============================================================================
@router.get(
    "/users/{subject_id}/actions",
    summary="Paginated action-outcome history for a single user",
    description=(
        "Every action actually applied by an originating service for this "
        "subject, newest first: id, event_id, service, action, created_at. "
        "Queried directly off fraud_action_outcomes by subject_id."
    ),
)
def get_user_actions(
    subject_id: str,
    page:  int = Query(default=1,  ge=1),
    limit: int = Query(default=20, ge=1, le=100),
):
    if not subject_id or len(subject_id) > 128 or "\x00" in subject_id:
        raise HTTPException(status_code=400, detail="Invalid subject_id")

    return _with_db(
        lambda db: fetch_user_action_outcomes(db, subject_id, page=page, limit=limit)
    )

# =============================================================================
# SECTION 10 — TRANSACTION LIST
# =============================================================================

_TZ_SPACE_RE = re.compile(
    r"^(.*[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?) (\d{2}:\d{2})$"
)

def _parse_tz_aware_dt(value: Optional[str], name: str) -> Optional[datetime]:
    """Parse an ISO-8601 datetime that must carry a UTC offset."""
    if value is None:
        return None
    v = value.strip()

    # An unencoded '+' in a query string arrives as a space: "...00:00:00 05:30"
    m = _TZ_SPACE_RE.match(v)
    if m:
        v = f"{m.group(1)}+{m.group(2)}"

    if v.endswith(("Z", "z")):
        v = v[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"{name} must be ISO 8601 with a timezone offset, "
                   "e.g. 2026-09-20T00:00:00+05:30 or 2026-09-20T00:00:00Z",
        )
    if dt.tzinfo is None:
        raise HTTPException(
            status_code=400,
            detail=f"{name} must include a timezone offset, "
                   "e.g. 2026-09-20T00:00:00+05:30 or 2026-09-20T00:00:00Z",
        )
    return dt

@router.get(
    "/transactions",
    summary="Paginated + filterable list of fraud decisions",
    description=(
        "Newest-first list of decisions: event_id, subject_id, service, "
        "score, risk_level, action, source, created_at. Supports filtering "
        "by risk_level, service, subject_id (exact match), and date range "
        "(ISO 8601 with timezone offset). Summary block reflects the same filters."
    ),
)
def get_transactions(
    page:  int = Query(default=1,  ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    risk_level: Optional[str] = Query(default=None, description="NORISK|LOW|MEDIUM|HIGH|CRITICAL"),
    service:    Optional[str] = Query(default=None, description="AUTH|LOGIN|CONSENT|WALLET"),
    subject_id: Optional[str] = Query(default=None, description="Exact match, case-sensitive"),
    date_from:  Optional[str] = Query(default=None, description="ISO 8601 with timezone offset, e.g. 2026-09-20T00:00:00+05:30"),
    date_to:    Optional[str] = Query(default=None, description="ISO 8601 with timezone offset, e.g. 2026-09-22T23:59:59+05:30"),
):
    if risk_level and risk_level.upper() not in RISK_LEVELS_SET:
        raise HTTPException(status_code=400, detail=f"Invalid risk_level. Must be one of {sorted(RISK_LEVELS_SET)}")
    if service and service.upper() not in VALID_SERVICES:
        raise HTTPException(status_code=400, detail=f"Invalid service. Must be one of {sorted(VALID_SERVICES)}")
    if subject_id and "\x00" in subject_id:
        raise HTTPException(status_code=400, detail="Invalid subject_id")

    date_from_dt = _parse_tz_aware_dt(date_from, "date_from")
    date_to_dt   = _parse_tz_aware_dt(date_to, "date_to")
    if date_from_dt and date_to_dt and date_from_dt > date_to_dt:
        raise HTTPException(status_code=400, detail="date_from cannot be after date_to")

    return _with_db(lambda db: fetch_transactions(
        db, page=page, limit=limit,
        risk_level=risk_level, service=service,
        subject_id=subject_id, date_from=date_from_dt, date_to=date_to_dt,
    ))

# =============================================================================
# SECTION 11 — TRANSACTION DRILL-DOWN
# =============================================================================
@router.get(
    "/transactions/{event_id}",
    summary="Full scoring journey for a single event",
    description=(
        "event_context: identifiers, role, exception code, session_id, "
        "source, config version, and the raw security / biometric / document / "
        "consent / wallet payloads. "
        "features_extracted: every computed feature and a count. "
        "rules_triggered: per rule, base weight -> chain boost (with reason) "
        "-> role modifier -> final weight. "
        "scoring_breakdown: raw score -> exception score -> session amplifier "
        "-> final score and risk level. "
        "active_liveness_suggestion: only when applicable. "
        "action_outcome: the action applied by the originating service, if recorded. "
        "Returns status DECISION_NOT_YET_AVAILABLE with event_context only if the "
        "event is stored but not yet scored."
    ),
)
def get_transaction_detail(event_id: str):
    try:
        event_id = normalize_event_id(event_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="event_id must be a valid UUID")
    result = _with_db(lambda db: fetch_transaction_detail(db, event_id))
    if result.get("status") == "EVENT_NOT_FOUND":
        raise HTTPException(status_code=404, detail=f"Event not found: {event_id}")
    return result

# =============================================================================
# SECTION 12 — ROLE ANALYTICS
# =============================================================================

@router.get(
    "/roles/stats",
    summary="Role-based event and risk analytics",
    description=(
        "Event counts, avg scores, risk breakdown, action breakdown, "
        "and block rates per role (USER/AGENT/ADMIN/SYSTEM). "
        "Also returns the role modifier reference showing which rules "
        "are suppressed or reduced per role."
    ),
)
def get_role_stats():
    return _with_db(fetch_role_stats)


# =============================================================================
# LEGACY ROUTES — kept so existing frontend doesn't break
# =============================================================================

@router.get("/kpis", include_in_schema=False)
def get_kpis_legacy():
    return _with_db(fetch_kpis)


@router.get("/charts/risk-trend", include_in_schema=False)
def risk_trend_legacy():
    return _with_db(risk_trend_over_time)


@router.get("/charts/fraud-type", include_in_schema=False)
def fraud_type_legacy():
    return _with_db(fraud_type_stats)


@router.get("/charts/risk-classification", include_in_schema=False)
def risk_classification_legacy():
    return _with_db(risk_classification_stats)


@router.get("/charts/source-volume", include_in_schema=False)
def source_volume_legacy():
    return _with_db(source_volume_stats)