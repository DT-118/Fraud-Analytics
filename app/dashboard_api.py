



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
  User Profile          GET /fraud/users/{subject_id}/profile
  Service Activity Log  GET /fraud/services/{service}/activity
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

from fastapi import APIRouter, HTTPException, Query
from typing import Literal

# from storage.db import get_db_connection
from storage.db import get_db_connection, release_db_connection
from storage.dashboard_repo import (
    fetch_event_kpis,
    fetch_action_stats,
    fetch_score_distribution,
    fetch_risk_band_stats,
    fetch_rules_stats,
    fetch_ip_device_stats,
    fetch_sessions,
    fetch_cross_service_flag_stats,
    fetch_user_profile,
    fetch_service_activity_log,
    fetch_transactions,
    fetch_transaction_detail,
    # legacy aliases
    fetch_kpis,
    risk_trend_over_time,
    fraud_type_stats,
    risk_classification_stats,
    source_volume_stats,
    fetch_role_stats,
)

router = APIRouter(prefix="/fraud", tags=["Fraud Dashboard"])

_VALID_SERVICES = {"AUTH", "ENROLL", "CONSENT", "WALLET"}


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
    summary="Action counts, breakdown by service, risk trend, source volume",
    description=(
        "Count per action (ALLOW/MONITOR/FLAG/STEP_UP/BLOCK), "
        "breakdown by service, block & step-up rate %, "
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
        "Histogram in 10-point buckets, overall average score, "
        "average score per service, average score per action."
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
# SECTION 6 — IP & DEVICE THREATS
# =============================================================================

@router.get(
    "/threats/summary",
    summary="Flagged IPs and flagged/shared devices",
    description=(
        "Total active flagged IPs, events from flagged IPs, full IP list. "
        "Total flagged devices, events from shared devices (≥5 subjects), "
        "flagged device list with subject counts."
    ),
)
def get_threat_summary():
    return _with_db(fetch_ip_device_stats)


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
# SECTION 8B — ROLE ANALYTICS
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
# SECTION 9 — PER-USER RISK PROFILE
# =============================================================================

@router.get(
    "/users/{subject_id}/profile",
    summary="Full risk profile for a single user",
    description=(
        "Identity profile (composite score, per-service scores, cross-service flag, "
        "highest risk level, total events). "
        "Per-service rolling scores (AUTH/ENROLL/CONSENT/WALLET) with last event details. "
        "Full activity log: every past decision with score, risk, action, triggered rules, "
        "features, and a human-readable log_line sentence describing what happened. "
        "Session history for this user."
    ),
)
def get_user_profile(subject_id: str):
    if not subject_id or len(subject_id) > 128:
        raise HTTPException(status_code=400, detail="Invalid subject_id")

    result = _with_db(lambda db: fetch_user_profile(db, subject_id))

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No profile found for subject_id={subject_id}",
        )
    return result


# =============================================================================
# SECTION 10 — PER-SERVICE ACTIVITY LOG
# =============================================================================

@router.get(
    "/services/{service}/activity",
    summary="Paginated activity log for a service with summary stats",
    description=(
        "All decisions for AUTH / ENROLL / CONSENT / WALLET. "
        "Summary: total events, avg score, top risk level, action breakdown, "
        "top 10 triggered rules for that service. "
        "Paginated rows with human-readable log_line per event."
    ),
)
def get_service_activity(
    service: str,
    page:    int = Query(default=1,  ge=1),
    limit:   int = Query(default=50, ge=1, le=200),
):
    svc = service.upper()
    if svc not in _VALID_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"service must be one of {sorted(_VALID_SERVICES)}",
        )
    return _with_db(
        lambda db: fetch_service_activity_log(db, service=svc, page=page, limit=limit)
    )


# =============================================================================
# SECTION 11 — TRANSACTION LIST
# =============================================================================

@router.get(
    "/transactions",
    summary="Paginated list of all fraud decisions",
    description=(
        "Newest-first list of decisions: event_id, subject_id, service, "
        "score, risk_level, action, status (ALLOWED/REVIEWED), source, created_at."
    ),
)
def get_transactions(
    page:  int = Query(default=1,  ge=1),
    limit: int = Query(default=20, ge=1, le=100),
):
    return _with_db(lambda db: fetch_transactions(db, page=page, limit=limit))


# =============================================================================
# SECTION 12 — TRANSACTION DRILL-DOWN
# =============================================================================

@router.get(
    "/transactions/{event_id}",
    summary="Full journey for a single event",
    description=(
        "Decision: score, risk, action, triggered rules, rule weights, "
        "all features computed, source, config version, human-readable log_line. "
        "Event: raw security / biometric / document / consent / wallet payloads. "
        "Session: session state (event count, high count, has_critical, max_score). "
        "User state: previous decision for this user + current composite profile."
    ),
)
def get_transaction_detail(event_id: str):
    result = _with_db(lambda db: fetch_transaction_detail(db, event_id))
    if result.get("status") == "EVENT_NOT_FOUND":
        raise HTTPException(status_code=404, detail=f"Event not found: {event_id}")
    return result


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