"""
Database query repository for the fraud dashboard.

Dashboard API return areas:
    1. Event Intelligence KPIs
       fetch_event_kpis()
       Event volume, scoring coverage, duplicate count, service/source
       distribution, exception-code statistics, and session statistics.

    2. Actions & Decisions
       fetch_action_stats()
       Action counts, 24-hour risk trend, and API/Kafka source volume.

    3. Score Distribution
       fetch_score_distribution()
       Score histogram and average scores by overall, service, and action.

    4. Risk Band Analytics
       fetch_risk_band_stats()
       Risk-level totals and distribution by service.

    5. Rules & Chains Analytics
       fetch_rules_stats()
       Top triggered rules, chain co-occurrence counts, and total chain
       applications.

    6. IP Flags
       fetch_ip_threat_stats()
       Flagged IP totals, affected event count, and flagged IP list.

    7. Sessions Panel
       fetch_sessions()
       Session summary statistics and paginated session records.

    8. Cross-Service Flags
       fetch_cross_service_flag_stats()
       Globally flagged-user totals, reason breakdown, and flagged users.

    9. Per-User Action taken
        fetch_user_action_outcomes()
        Paginated action-outcome history for a single user

    10. Transaction List
        fetch_transactions()
        Paginated scored transactions.

    11. Transaction Drill-Down
        fetch_transaction_detail()
        Decision, event payloads, session context, and user state for one event.

    12. Role Analytics
        fetch_role_stats()
        Role event counts, average scores, risk/action distributions, and
        block rates.

Backward-compatible route aliases:
    fetch_kpis()
    risk_trend_over_time()
    fraud_type_stats()
    risk_classification_stats()
    source_volume_stats()
"""

from __future__ import annotations
import os
from typing import Optional
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

def _load_report_tz() -> str:
    name = (os.environ.get("REPORT_TIMEZONE") or "UTC").strip() or "UTC"
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise RuntimeError(
            f"REPORT_TIMEZONE={name!r} is not a valid IANA timezone "
            "(e.g. 'UTC', 'Asia/Dubai', 'Asia/Kolkata')"
        ) from exc
    return name

_REPORT_TZ = _load_report_tz()

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _isoformat(val) -> Optional[str]:
    """Convert a nullable datetime value to ISO-8601 text."""
    return val.isoformat() if val else None


def _int(val, default=0) -> int:
    """Convert a nullable database value to int."""
    return int(val) if val is not None else default


def _float(val, default=0.0) -> float:
    """Convert a nullable database value to float."""
    return float(val) if val is not None else default


# =============================================================================
# 1. EVENT INTELLIGENCE KPIs
# =============================================================================

def fetch_event_kpis(db) -> dict:
    """
    Returns:
      total_events_received      — all rows in fraud_events
      total_events_scored        — all rows in fraud_decisions
      duplicates_blocked         — received - scored (idempotency catch)
      events_today               — fraud_events since midnight in REPORT_TIMEZONE
      events_last_1h             — fraud_events in last 60 min
      events_scored_per_minute   — decisions in last 60s / 60
      unique_users               — distinct subject_ids in fraud_events
      events_by_service          — {AUTH, LOGIN, CONSENT, WALLET: count}
      auth_events_by_method      — {pin, wallet, unspecified: count} (auth events only)
      events_by_environment      — {prod, staging, sandbox: count}
      events_by_source           — {API, KAFKA: count}
      events_with_exception_code — count where exception_code IS NOT NULL
      exception_code_breakdown   — [{code, count}]
      events_in_same_session          — events that have a non-null session_id
      unique_sessions            — distinct session_ids seen
    """
    cur = db.cursor()

    # total received vs scored
    cur.execute("SELECT COUNT(*) FROM fraud_events")
    total_received = _int(cur.fetchone()[0])

    cur.execute("SELECT COUNT(*) FROM fraud_decisions")
    total_scored = _int(cur.fetchone()[0])

    # events today
    cur.execute("""
        SELECT COUNT(*) FROM fraud_events
        WHERE created_at >= (DATE_TRUNC('day', NOW() AT TIME ZONE %s)) AT TIME ZONE %s
    """, (_REPORT_TZ, _REPORT_TZ))
    events_today = _int(cur.fetchone()[0])

    # events last 1h
    cur.execute("""
        SELECT COUNT(*) FROM fraud_events
        WHERE created_at > NOW() - INTERVAL '1 hour'
    """)
    events_last_1h = _int(cur.fetchone()[0])

    # throughput (decisions per minute based on last 60s)
    cur.execute("""
        SELECT COUNT(*) FROM fraud_decisions
        WHERE created_at > NOW() - INTERVAL '1 minute'
    """)
    recent = _int(cur.fetchone()[0])
    events_scored_per_minute = recent

    # unique users
    cur.execute("SELECT COUNT(DISTINCT subject_id) FROM fraud_events")
    unique_users = _int(cur.fetchone()[0])

    # by service (action_taxonomy is the service name)
    cur.execute("""
        SELECT UPPER(action_taxonomy), COUNT(*)
        FROM fraud_events
        GROUP BY UPPER(action_taxonomy)
    """)
    events_by_service = {row[0]: _int(row[1]) for row in cur.fetchall()}

    # by environment
    cur.execute("""
        SELECT environment, COUNT(*)
        FROM fraud_events
        GROUP BY environment
    """)
    events_by_environment = {row[0]: _int(row[1]) for row in cur.fetchall()}

    # by source (from decisions — events table has no source col)
    cur.execute("""
        SELECT source, COUNT(*)
        FROM fraud_decisions
        GROUP BY source
    """)
    events_by_source = {row[0]: _int(row[1]) for row in cur.fetchall()}

    # authentication events by method 
    cur.execute("""
        SELECT COALESCE(action_taxonomy_sub_method, 'unspecified'), COUNT(*)
        FROM fraud_events
        WHERE action_taxonomy = 'auth'
        GROUP BY 1
    """)
    auth_events_by_method = {row[0]: _int(row[1]) for row in cur.fetchall()}

    # exception codes
    cur.execute("""
        SELECT COUNT(*) FROM fraud_events
        WHERE exception_code IS NOT NULL
    """)
    events_with_exception_code = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT exception_code, COUNT(*) AS cnt
        FROM fraud_events
        WHERE exception_code IS NOT NULL
        GROUP BY exception_code
        ORDER BY cnt DESC
    """)
    exception_code_breakdown = [
        {"code": row[0], "count": _int(row[1])}
        for row in cur.fetchall()
    ]

    # session presence
    cur.execute("""
        SELECT COUNT(*) FROM fraud_events
        WHERE session_id IS NOT NULL
    """)
    events_in_same_session = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT COUNT(DISTINCT session_id) FROM fraud_events
        WHERE session_id IS NOT NULL
    """)
    unique_sessions = _int(cur.fetchone()[0])

    return {
        "total_events_received":      total_received,
        "total_events_scored":        total_scored,
        "duplicates_blocked":         max(0, total_received - total_scored),
        "events_today":               events_today,
        "events_last_1h":             events_last_1h,
        "events_scored_per_minute":   events_scored_per_minute,
        "unique_users":               unique_users,
        "events_by_service":          events_by_service,
        "auth_events_by_method":      auth_events_by_method,
        "events_by_environment":      events_by_environment,
        "events_by_source":           events_by_source,
        "events_with_exception_code": events_with_exception_code,
        "exception_code_breakdown":   exception_code_breakdown,
        "events_in_same_session":     events_in_same_session,
        "unique_sessions":            unique_sessions,
    }


# =============================================================================
# 2. ACTIONS & DECISIONS
# =============================================================================

def fetch_action_stats(db) -> dict:
    """
    Returns:
      total_action_outcomes_received — count
      risk_trend             — [{hour, NORISK, LOW, MEDIUM, HIGH, CRITICAL}] last 24h
      source_volume          — [{hour, api, kafka}] last 24h
    """
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM fraud_action_outcomes")
    total_action_outcomes_received = _int(cur.fetchone()[0])

    # risk trend last 24h (hourly)
    cur.execute("""
        SELECT
            DATE_TRUNC('hour', created_at AT TIME ZONE %s) AT TIME ZONE %s AS hour,
            SUM(CASE WHEN risk_level = 'NORISK'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'LOW'      THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'MEDIUM'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'HIGH'     THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END)
        FROM fraud_decisions
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY 1
        ORDER BY 1
    """, (_REPORT_TZ, _REPORT_TZ))
    risk_trend = [
        {
            "hour":     _isoformat(row[0]),
            "NORISK":   _int(row[1]),
            "LOW":      _int(row[2]),
            "MEDIUM":   _int(row[3]),
            "HIGH":     _int(row[4]),
            "CRITICAL": _int(row[5]),
        }
        for row in cur.fetchall()
    ]

    cur.execute("""
    SELECT
        DATE_TRUNC('hour', created_at AT TIME ZONE %s) AT TIME ZONE %s AS hour,
        SUM(CASE WHEN source = 'API'   THEN 1 ELSE 0 END),
        SUM(CASE WHEN source = 'KAFKA' THEN 1 ELSE 0 END)
        FROM fraud_decisions
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY 1
        ORDER BY 1
    """, (_REPORT_TZ, _REPORT_TZ))
    source_volume = [
        {"hour": _isoformat(row[0]), "api": _int(row[1]), "kafka": _int(row[2])}
        for row in cur.fetchall()
    ]

    return {
        "total_action_outcomes_received": total_action_outcomes_received,
        "risk_trend":        risk_trend,
        "source_volume":     source_volume,
    }


# =============================================================================
# 3. SCORE DISTRIBUTION
# =============================================================================

def fetch_score_distribution(db) -> dict:
    """
    Returns:
      histogram        — [{bucket: "0-9", count}] in 10-point bands
      avg_score        — overall average final score
      avg_score_by_service — {AUTH, LOGIN, CONSENT, WALLET: avg_score}
    """
    cur = db.cursor()

    # histogram in 10-point bands
    cur.execute("""
        SELECT
            FLOOR(score / 10) * 10 AS bucket_start,
            COUNT(*) AS cnt
        FROM fraud_decisions
        GROUP BY bucket_start
        ORDER BY bucket_start
    """)
    histogram = [
        {
            "bucket": f"{_int(row[0])}-{_int(row[0]) + 9}",
            "count":  _int(row[1]),
        }
        for row in cur.fetchall()
    ]

    # overall avg
    cur.execute("SELECT AVG(score) FROM fraud_decisions")
    avg_score = round(_float(cur.fetchone()[0]), 2)

    # avg by service
    cur.execute("""
        SELECT fraud_type, AVG(score)
        FROM fraud_decisions
        GROUP BY fraud_type
    """)
    avg_score_by_service = {row[0]: round(_float(row[1]), 2) for row in cur.fetchall()}

    return {
        "histogram":            histogram,
        "avg_score":            avg_score,
        "avg_score_by_service": avg_score_by_service,
    }


# =============================================================================
# 4. RISK BAND ANALYTICS
# =============================================================================

def fetch_risk_band_stats(db) -> dict:
    """
    Returns:
      risk_counts          — {NORISK, LOW, MEDIUM, HIGH, CRITICAL: count}
      risk_by_service      — [{service, NORISK, LOW, MEDIUM, HIGH, CRITICAL}]
    """
    cur = db.cursor()

    cur.execute("""
        SELECT risk_level, COUNT(*)
        FROM fraud_decisions
        GROUP BY risk_level
    """)
    risk_counts = {row[0]: _int(row[1]) for row in cur.fetchall()}

    cur.execute("""
        SELECT
            fraud_type,
            SUM(CASE WHEN risk_level = 'NORISK'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'LOW'      THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'MEDIUM'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'HIGH'     THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END)
        FROM fraud_decisions
        GROUP BY fraud_type
    """)
    risk_by_service = [
        {
            "service":  row[0],
            "NORISK":   _int(row[1]),
            "LOW":      _int(row[2]),
            "MEDIUM":   _int(row[3]),
            "HIGH":     _int(row[4]),
            "CRITICAL": _int(row[5]),
        }
        for row in cur.fetchall()
    ]

    return {
        "risk_counts":     risk_counts,
        "risk_by_service": risk_by_service,
    }


# =============================================================================
# 5. RULES & CHAINS ANALYTICS
# =============================================================================

def fetch_rules_stats(db) -> dict:
    """
    Unnests triggered_rules array and rule_weights JSONB to compute:
      top_rules          — [{rule_id, trigger_count}] top 15, desc
      chain_activations  — [{chain_reason, count}] — from rule_weights JSONB
                           where a key has chain_reason set (stored as
                           rule_weights->'RULE_ID'->>'chain_reason' pattern
                           — we look for any decision where rule_weights
                           contains a chain_reason marker)
      total_chain_applications — sum of all chain fires ever
    """
    cur = db.cursor()

    # top triggered rules — unnest the text[] array
    cur.execute("""
        SELECT rule_id, COUNT(*) AS cnt
        FROM (
            SELECT UNNEST(triggered_rules) AS rule_id
            FROM fraud_decisions
        ) t
        GROUP BY rule_id
        ORDER BY cnt DESC
        LIMIT 15
    """)
    top_rules = [
        {"rule_id": row[0], "trigger_count": _int(row[1])}
        for row in cur.fetchall()
    ]

    # Chain reasons are not stored separately in the current decision schema.
    # Dashboard chain analytics therefore use known rule co-occurrences.
    chain_definitions = [
        ("NEW_DEVICE_WITH_FAILURES",         ["DEVICE_NEW_DEVICE_ALLOWANCE", "AUTH_CONSECUTIVE_FAILURES"]),
        ("SHARED_DEVICE_BURST_WITH_FAILURES", ["DEVICE_SHARED_ACCOUNTS_BURST", "AUTH_CONSECUTIVE_FAILURES"]),
        ("GEO_JUMP_NEW_DEVICE_WITH_IP_FAILURES", ["GEO_VELOCITY", "DEVICE_NEW_DEVICE_ALLOWANCE", "AUTH_IP_BRUTE_FORCE"]),
        ("FLAGGED_IP_WITH_FAILURES",         ["IP_BLOCKLIST_MATCH", "AUTH_CONSECUTIVE_FAILURES"]),
        ("FLAGGED_IP_NEW_DEVICE_GEO_JUMP",   ["IP_BLOCKLIST_MATCH", "DEVICE_NEW_DEVICE_ALLOWANCE", "GEO_VELOCITY"]),
        ("LIVENESS_SPOOF_NEW_DEVICE",        ["BIOMETRIC_SPOOF_DETECTED", "DEVICE_NEW_DEVICE_ALLOWANCE", "AUTH_CONSECUTIVE_FAILURES"]),
        ("SHARED_DEVICE_CONSENT_SPIKE",      ["DEVICE_SHARED_ACCOUNTS", "CONSENT_GRANT_VELOCITY"]),
        ("FLAGGED_IP_CONSENT_SPIKE",         ["IP_BLOCKLIST_MATCH", "CONSENT_GRANT_VELOCITY"]),
        ("SHARED_DEVICE_DOC_FAILURES",       ["DEVICE_SHARED_ACCOUNTS", "LOGIN_DOCUMENT_UDB_MISMATCH"]),
        ("FLAGGED_IP_FACE_MISMATCH",         ["IP_BLOCKLIST_MATCH", "UDB_FACE_MISMATCH"]),
        ("SHARED_DEVICE_PROVISION_BURST",    ["DEVICE_SHARED_ACCOUNTS", "WALLET_PROVISION_VELOCITY"]),
        ("FLAGGED_IP_SHARE_BURST",           ["IP_BLOCKLIST_MATCH", "WALLET_SHARE_VELOCITY"]),
        ("FLAGGED_IP_SHARED_DEVICE_COMBINED_BURST", ["IP_BLOCKLIST_MATCH", "DEVICE_SHARED_ACCOUNTS", "WALLET_PROVISION_SHARE_BURST"]),
        ("BASELINE_DEVIATION_WITH_FAILURES", ["BASELINE_BEHAVIOR_ANOMALY", "AUTH_CONSECUTIVE_FAILURES"]),
        ("BASELINE_DEVIATION_NEW_DEVICE",    ["BASELINE_BEHAVIOR_ANOMALY", "DEVICE_NEW_DEVICE_ALLOWANCE"]),
        ("BASELINE_DEVIATION_CONSENT_SPIKE",  ["BASELINE_BEHAVIOR_ANOMALY", "CONSENT_GRANT_VELOCITY"]),
        ("BASELINE_DEVIATION_DOC_FAILURES",   ["BASELINE_BEHAVIOR_ANOMALY", "LOGIN_DOCUMENT_UDB_MISMATCH"]),
        ("BASELINE_DEVIATION_PROVISION_BURST",["BASELINE_BEHAVIOR_ANOMALY", "WALLET_PROVISION_VELOCITY"]),
        ("SHARED_DEVICE_BURST_CONSENT_SPIKE",   ["DEVICE_SHARED_ACCOUNTS_BURST", "CONSENT_GRANT_VELOCITY"]),
        ("SHARED_DEVICE_BURST_DOC_FAILURES",    ["DEVICE_SHARED_ACCOUNTS_BURST", "LOGIN_DOCUMENT_UDB_MISMATCH"]),
        ("SHARED_DEVICE_BURST_PROVISION_BURST", ["DEVICE_SHARED_ACCOUNTS_BURST", "WALLET_PROVISION_VELOCITY"]),
        ("FLAGGED_IP_SHARED_DEVICE_BURST_COMBINED_BURST", ["IP_BLOCKLIST_MATCH", "DEVICE_SHARED_ACCOUNTS_BURST", "WALLET_PROVISION_SHARE_BURST"]),
    ]

    chain_activations = []
    total_chain_applications = 0

    for chain_name, rule_ids in chain_definitions:
        # count decisions where ALL rules in the chain fired
        placeholders = " AND ".join([
            f"triggered_rules @> ARRAY[%s]::text[]" for _ in rule_ids
        ])
        cur.execute(
            f"SELECT COUNT(*) FROM fraud_decisions WHERE {placeholders}",
            rule_ids,
        )
        count = _int(cur.fetchone()[0])
        chain_activations.append({"chain": chain_name, "count": count})
        total_chain_applications += count

    chain_activations.sort(key=lambda x: x["count"], reverse=True)

    return {
        "top_rules":                top_rules,
        "chain_activations":        chain_activations,
        "total_chain_applications": total_chain_applications,
    }


# =============================================================================
# 6. IP FLAGS
# =============================================================================

def fetch_ip_threat_stats(db) -> dict:
    """
    Returns:
      total_flagged_ips          — active rows in ip_reputation
      events_from_flagged_ips    — decisions where features->ip_is_flagged = '1'
      flagged_ip_list            — [{src_ip, flag_reason, flagged_at, flagged_by}]
    """
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM ip_reputation WHERE is_active = TRUE")
    total_flagged_ips = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT COUNT(*) FROM fraud_decisions
        WHERE COALESCE(features->>'ip_is_flagged', '0') = '1'
    """)
    events_from_flagged_ips = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT src_ip, flag_reason, flagged_at, flagged_by
        FROM ip_reputation
        WHERE is_active = TRUE
        ORDER BY flagged_at DESC
    """)
    flagged_ip_list = [
        {
            "src_ip":      row[0],
            "flag_reason": row[1],
            "flagged_at":  _isoformat(row[2]),
            "flagged_by":  row[3],
        }
        for row in cur.fetchall()
    ]

    return {
        "total_flagged_ips":       total_flagged_ips,
        "events_from_flagged_ips": events_from_flagged_ips,
        "flagged_ip_list":         flagged_ip_list,
    }

# =============================================================================
# 7. SESSIONS PANEL
# =============================================================================

def fetch_sessions(db, page: int = 1, limit: int = 20) -> dict:
    """
    Paginated list of fraud_sessions rows plus aggregate summary.

    Returns:
      summary:
        total_sessions
        sessions_with_critical   — has_critical = true
        sessions_amplified       — high_event_count >= 2 OR has_critical
        avg_events_per_session
      data: [{session_id, subject_id, event_count, high_event_count,
               has_critical, max_score, session_risk_level,
               first_event_at, last_event_at}]
      page / limit / total / total_pages
    """
    cur = db.cursor()
    offset = (page - 1) * limit

    cur.execute("SELECT COUNT(*) FROM fraud_sessions")
    total = _int(cur.fetchone()[0])

    cur.execute("SELECT COUNT(*) FROM fraud_sessions WHERE has_critical = TRUE")
    sessions_with_critical = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT COUNT(*) FROM fraud_sessions
        WHERE high_event_count >= 2 OR has_critical = TRUE
    """)
    sessions_amplified = _int(cur.fetchone()[0])

    cur.execute("SELECT AVG(event_count) FROM fraud_sessions")
    avg_events = round(_float(cur.fetchone()[0]), 2)

    cur.execute("""
        SELECT
            session_id, subject_id, event_count, high_event_count,
            has_critical, max_score, session_risk_level,
            first_event_at, last_event_at
        FROM fraud_sessions
        ORDER BY last_event_at DESC NULLS LAST
        LIMIT %s OFFSET %s
    """, (limit, offset))

    data = [
        {
            "session_id":        row[0],
            "subject_id":        row[1],
            "event_count":       _int(row[2]),
            "high_event_count":  _int(row[3]),
            "has_critical":      bool(row[4]),
            "max_score":         _int(row[5]),
            "session_risk_level": row[6],
            "first_event_at":    _isoformat(row[7]),
            "last_event_at":     _isoformat(row[8]),
        }
        for row in cur.fetchall()
    ]

    return {
        "summary": {
            "total_sessions":        total,
            "sessions_with_critical": sessions_with_critical,
            "sessions_amplified":    sessions_amplified,
            "avg_events_per_session": avg_events,
        },
        "data":        data,
        "page":        page,
        "limit":       limit,
        "total":       total,
        "total_pages": (total + limit - 1) // limit,
    }


# =============================================================================
# 8. CROSS-SERVICE FLAGS (global)
# =============================================================================

def fetch_cross_service_flag_stats(db) -> dict:
    """
    Returns:
      total_flagged_users      — users with cross_service_flag = true
      reason_breakdown         — [{reason, count}]
      flagged_users            — [{subject_id, composite_score, reason, flagged_at}]
    """
    cur = db.cursor()

    cur.execute("""
        SELECT COUNT(*) FROM user_identity_risk_profile
        WHERE cross_service_flag = TRUE
    """)
    total_flagged_users = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT cross_service_flag_reason, COUNT(*) AS cnt
        FROM user_identity_risk_profile
        WHERE cross_service_flag = TRUE
        GROUP BY cross_service_flag_reason
        ORDER BY cnt DESC
    """)
    reason_breakdown = [
        {"reason": row[0], "count": _int(row[1])}
        for row in cur.fetchall()
    ]

    cur.execute("""
        SELECT subject_id, composite_score,
               cross_service_flag_reason, cross_service_flag_at
        FROM user_identity_risk_profile
        WHERE cross_service_flag = TRUE
        ORDER BY composite_score DESC
    """)
    flagged_users = [
        {
            "subject_id":      row[0],
            "composite_score": _float(row[1]),
            "reason":          row[2],
            "flagged_at":      _isoformat(row[3]),
        }
        for row in cur.fetchall()
    ]

    return {
        "total_flagged_users": total_flagged_users,
        "reason_breakdown":    reason_breakdown,
        "flagged_users":       flagged_users,
    }



# =============================================================================
# 9. PER-USER ACTION OUTCOMES
# =============================================================================

def fetch_user_action_outcomes(db, subject_id: str, page: int = 1, limit: int = 20) -> dict:
    """
    Paginated list of every action actually applied for a subject, newest
    first. Queries fraud_action_outcomes directly by subject_id — no join
    back through fraud_events/fraud_decisions needed now that subject_id is
    stored on the outcomes row itself.

    Returns:
      data — [{id, event_id, service, action, created_at}]
      page / limit / total / total_pages
    """
    cur = db.cursor()
    offset = (page - 1) * limit

    cur.execute(
        "SELECT COUNT(*) FROM fraud_action_outcomes WHERE subject_id = %s",
        (subject_id,),
    )
    total = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT id, event_id, service, action, created_at, updated_at
        FROM fraud_action_outcomes
        WHERE subject_id = %s
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """, (subject_id, limit, offset))

    data = [
        {
            "id":         str(row[0]),
            "event_id":   str(row[1]),
            "service":    row[2],
            "action":     row[3],
            "created_at": _isoformat(row[4]),
            "updated_at": _isoformat(row[5]),
        }
        for row in cur.fetchall()
    ]

    return {
        "subject_id":  subject_id,
        "data":        data,
        "page":        page,
        "limit":       limit,
        "total":       total,
        "total_pages": (total + limit - 1) // limit,
    }

# =============================================================================
# 10. TRANSACTION LIST (paginated)
# =============================================================================

def fetch_transactions(
    db,
    page: int = 1,
    limit: int = 20,
    risk_level: Optional[str] = None,
    service: Optional[str] = None,
    subject_id: Optional[str] = None,   # search — exact match
    date_from: Optional[datetime] = None,    # ISO date/datetime string
    date_to: Optional[datetime] = None,
) -> dict:
    """
    Paginated + filterable list of fraud decisions, plus a summary block
    that reflects the SAME filters (so the KPI tiles match what's on screen).

    subject_id is a search-style filter, exact match.
    """
    cur = db.cursor()
    offset = (page - 1) * limit

    # ---- Build WHERE clause once, reused for summary + count + page query ----
    where_clauses = []
    params: list = []

    if risk_level:
        where_clauses.append("d.risk_level = %s")
        params.append(risk_level.upper())

    if service:
        where_clauses.append("d.fraud_type = %s")
        params.append(service.upper())

    if subject_id:
        where_clauses.append("d.subject_id = %s")
        params.append(subject_id)

    if date_from:
        where_clauses.append("d.created_at >= %s")
        params.append(date_from)

    if date_to:
        where_clauses.append("d.created_at <= %s")
        params.append(date_to)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    # ---- Total count (filtered) ----
    cur.execute(f"""
        SELECT COUNT(*)
        FROM fraud_decisions d
        {where_sql}
    """, params)
    total = _int(cur.fetchone()[0])

    # ---- Summary (filtered, independent of pagination) ----
    cur.execute(f"""
        SELECT d.risk_level, COUNT(*)
        FROM fraud_decisions d
        {where_sql}
        GROUP BY d.risk_level
    """, params)
    risk_counts = {row[0]: _int(row[1]) for row in cur.fetchall()}

    cur.execute(f"""
        SELECT COUNT(DISTINCT d.subject_id)
        FROM fraud_decisions d
        {where_sql}
    """, params)
    unique_users = _int(cur.fetchone()[0])

    summary = {
        "critical_risk_events": risk_counts.get("CRITICAL", 0),
        "high_risk_events":     risk_counts.get("HIGH", 0),
        "medium_risk_events":   risk_counts.get("MEDIUM", 0),
        "low_risk_events":      risk_counts.get("LOW", 0),
        "norisk_events":        risk_counts.get("NORISK", 0),
        "unique_users":         unique_users,
    }

    # ---- Paginated rows (filtered) ----
    cur.execute(f"""
        SELECT
            d.event_id, d.subject_id, d.created_at,
            d.fraud_type, d.source, d.score, d.risk_level,
            COALESCE(a.action, 'UNKNOWN')
        FROM fraud_decisions d
        LEFT JOIN fraud_action_outcomes a ON a.event_id = d.event_id
        {where_sql}
        ORDER BY d.created_at DESC
        LIMIT %s OFFSET %s
    """, params + [limit, offset])

    data = [
        {
            "event_id":   str(row[0]),
            "subject_id": row[1],
            "created_at": row[2],
            "service":    row[3],
            "source":     row[4],
            "score":      _int(row[5]),
            "risk_level": row[6],
            "action":     row[7],
        }
        for row in cur.fetchall()
    ]

    return {
        "summary":     summary,
        "data":        data,
        "page":        page,
        "limit":       limit,
        "total":       total,
        "total_pages": (total + limit - 1) // limit,
        "filters_applied": {
            "risk_level": risk_level,
            "service":    service,
            "subject_id": subject_id,
            "date_from":  date_from,
            "date_to":    date_to,
        },
    }

# =============================================================================
# 11. TRANSACTION DRILL-DOWN (full journey for one event_id)
# =============================================================================

def fetch_transaction_detail(db, event_id: str) -> dict:
    """
    Full scoring pipeline for a single event:
      1. event_context      — everything received for this event
      2. features_extracted — every feature computed, and how many
      3. rules_triggered    — each rule: base_weight -> chain (if any,
                               with reason) -> role_modifier -> final
                               weight contribution
      4. scoring_breakdown  — raw_score -> + exception_score ->
                               capped score -> x session_amplifier ->
                               final_score -> risk_level
      5. active_liveness_suggestion — only present when applicable
      6. action_outcome     — action actually applied, if recorded
    """
    cur = db.cursor()

    cur.execute("""
        SELECT
            d.event_id,                          
            e.subject_id,                         
            d.fraud_type,                         
            d.score,                              
            d.risk_level,                         
            d.triggered_rules,                    
            d.rule_weights,                        
            d.features,                           
            d.exception_score,                     
            d.session_amplifier,                  
            d.active_liveness_suggestion,         
            d.source,                              
            d.config_version,                      
            d.created_at,                          
            d.role,                                
            d.exception_code,                     
            e.correlation_id,                     
            e.transaction_id,                      
            e.request_id,                          
            e.emirates_id_hash,                    
            e.actor_type,                          
            e.actor_id,                            
            e.action_taxonomy,                            
            e.event_time,                          
            e.session_id,                        
            e.environment,                        
            e.security_payload,                    
            e.biometric_payload,                   
            e.document_payload,                    
            e.consent_payload,                     
            e.wallet_payload,                      
            a.action,                              
            a.created_at,
            a.updated_at,
            e.biometric_method,
            d.pre_profile_score,
            d.profile_amplifier,
            e.action_taxonomy_sub_method                           
        FROM fraud_events e
        LEFT JOIN fraud_decisions d ON d.event_id = e.event_id
        LEFT JOIN fraud_action_outcomes a ON a.event_id = e.event_id
        WHERE e.event_id = %s
    """, (event_id,))

    row = cur.fetchone()
    if not row:
        return {"status": "EVENT_NOT_FOUND"}

    decision_exists = row[0] is not None
    subject_id       = row[1]
    service          = row[22]
    triggered        = row[5] or []
    rule_weights     = row[6] or {}
    features         = row[7] or {}
    security         = row[26] or {}

    # ---- 1. Event context ----
    event_context = {
        "event_id":          str(row[0]) if row[0] else event_id,
        "correlation_id":    row[16],
        "transaction_id":    row[17],
        "request_id":        row[18],
        "subject_id":        subject_id,
        "emirates_id_hash":  row[19],
        "role":              row[14],
        "exception_code":    row[15],
        "actor_type":        row[20],
        "actor_id":          row[21],
        "action_taxonomy":   row[22],
        "action_taxonomy_sub_method": row[37],
        "service":           service,
        "event_time":        _isoformat(row[23]),
        "session_id":        row[24],
        "environment":       row[25],
        "source":            row[11],
        "config_version":    row[12],
        "security_payload":  security,
        "biometric_payload": row[27],
        "document_payload":  row[28],
        "consent_payload":   row[29],
        "wallet_payload":    row[30],
        "biometric_method":  row[34],
    }

    if not decision_exists:
        return {"status": "DECISION_NOT_YET_AVAILABLE", "event_context": event_context}

    # ---- 2. Features extracted ----
    features_extracted = {"count": len(features), "values": features}

    # ---- 3. Rules triggered: base -> chain -> role modifier -> final ----
    rules_triggered = []
    for rule_id in triggered:
        w = rule_weights.get(rule_id, {})
        base_weight      = w.get("base_weight", w.get("weight", 0))
        chain_multiplier = w.get("chain_multiplier")
        chain_reason     = w.get("chain_reason")
        role_modifier    = w.get("role_modifier", 1.0)
        final_weight     = w.get("weight", 0)
        chain_applied    = chain_multiplier is not None
        weight_after_chain = (
            int(base_weight * chain_multiplier) if chain_applied else base_weight
        )

        rules_triggered.append({
            "rule_id":     rule_id,
            "base_weight": base_weight,
            "chain": (
                {
                    "applied":            True,
                    "multiplier":         chain_multiplier,
                    "reason":             chain_reason,
                    "weight_after_chain": weight_after_chain,
                } if chain_applied else {"applied": False}
            ),
            "role_modifier": {
                "role":                       row[14],
                "modifier":                   role_modifier,
                "weight_after_role_modifier": final_weight,
            },
            "final_weight_contribution": final_weight,
        })

    # ---- 4. Scoring breakdown, in pipeline order ----
    raw_score          = sum(w.get("weight", 0) for w in rule_weights.values())
    exception_score    = _float(row[8]) if row[8] is not None else None
    session_amplifier  = _float(row[9]) if row[9] is not None else None
    final_score        = _int(row[3])
    score_after_exception = (
        max(0, min(100, int(raw_score + exception_score)))
        if exception_score is not None else None
    )
    pre_profile_score = row[35]
    profile_amp       = _float(row[36]) if row[36] is not None else None

    scoring_breakdown = {
        "sum_of_rule_weights_raw_score": raw_score,
        "exception_code":                row[15],
        "exception_score_added":         exception_score,
        "score_after_exception":         score_after_exception,
        "session_amplifier":             session_amplifier,
        "score_before_profile":          pre_profile_score,
        "profile_amplifier":             profile_amp,
        "final_score":                   final_score,
        "risk_level":                    row[4],
    }

    if exception_score is None or session_amplifier is None:
        scoring_breakdown["note"] = (
            "exception_score and/or session_amplifier were not recorded for "
            "this event (scored before this field was tracked) — "
            "sum_of_rule_weights_raw_score and final_score remain exact."
        )

    result = {
        "status":             "OK",
        "event_context":      event_context,
        "features_extracted": features_extracted,
        "rules_triggered":    rules_triggered,
        "scoring_breakdown":  scoring_breakdown,
    }

    # ---- 5. Active liveness suggestion — only when present ----
    if row[10]:
        result["active_liveness_suggestion"] = row[10]

    # ---- 6. Action outcome — attached if recorded ----
    result["action_outcome"] = (
        {"action": row[31], "recorded_at": _isoformat(row[32]), "updated_at": _isoformat(row[33],)}
        if row[31] else None
    )

    return result

# =============================================================================
# 12. ROLE ANALYTICS
# =============================================================================

def fetch_role_stats(db) -> dict:
    """
    Returns:
      role_event_counts     — {USER, AGENT, ADMIN, SYSTEM, null: count}
      role_score_averages   — {role: avg_score}
      role_risk_breakdown   — [{role, NORISK, LOW, MEDIUM, HIGH, CRITICAL}]
      role_action_breakdown — [{role, ALLOW, MONITOR, FLAG, STEP_UP, BLOCK}]
      role_block_rates      — [{role, total, blocked, block_rate_pct}]
    """
    cur = db.cursor()

    # event counts per role
    cur.execute("""
        SELECT
            COALESCE(role, 'UNKNOWN') AS role,
            COUNT(*) AS cnt
        FROM fraud_decisions
        GROUP BY role
        ORDER BY cnt DESC
    """)
    role_event_counts = {row[0]: _int(row[1]) for row in cur.fetchall()}

    # avg score per role
    cur.execute("""
        SELECT
            COALESCE(role, 'UNKNOWN') AS role,
            ROUND(AVG(score)::numeric, 2) AS avg_score
        FROM fraud_decisions
        GROUP BY role
    """)
    role_score_averages = {row[0]: _float(row[1]) for row in cur.fetchall()}

    # risk level breakdown per role
    cur.execute("""
        SELECT
            COALESCE(role, 'UNKNOWN') AS role,
            SUM(CASE WHEN risk_level = 'NORISK'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'LOW'      THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'MEDIUM'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'HIGH'     THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END)
        FROM fraud_decisions
        GROUP BY role
        ORDER BY role
    """)
    role_risk_breakdown = [
        {
            "role":     row[0],
            "NORISK":   _int(row[1]),
            "LOW":      _int(row[2]),
            "MEDIUM":   _int(row[3]),
            "HIGH":     _int(row[4]),
            "CRITICAL": _int(row[5]),
        }
        for row in cur.fetchall()
    ]

    # action breakdown per role
    cur.execute("""
        SELECT
            COALESCE(role, 'UNKNOWN') AS role,
            SUM(CASE WHEN a.action = 'ALLOW'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN a.action = 'MONITOR' THEN 1 ELSE 0 END),
            SUM(CASE WHEN a.action = 'FLAG'    THEN 1 ELSE 0 END),
            SUM(CASE WHEN a.action = 'STEP_UP' THEN 1 ELSE 0 END),
            SUM(CASE WHEN a.action = 'BLOCK'   THEN 1 ELSE 0 END)
        FROM fraud_decisions d
        LEFT JOIN fraud_action_outcomes a ON a.event_id = d.event_id
        GROUP BY d.role
        ORDER BY role
    """)
    role_action_breakdown = [
        {
            "role":    row[0],
            "ALLOW":   _int(row[1]),
            "MONITOR": _int(row[2]),
            "FLAG":    _int(row[3]),
            "STEP_UP": _int(row[4]),
            "BLOCK":   _int(row[5]),
        }
        for row in cur.fetchall()
    ]

    # block rates per role
    cur.execute("""
        SELECT
            COALESCE(role, 'UNKNOWN') AS role,
            COUNT(*) AS total,
            SUM(CASE WHEN a.action = 'BLOCK' THEN 1 ELSE 0 END) AS blocked
        FROM fraud_decisions d
        LEFT JOIN fraud_action_outcomes a ON a.event_id = d.event_id
        GROUP BY d.role
        ORDER BY role
    """)
    role_block_rates = [
        {
            "role":           row[0],
            "total":          _int(row[1]),
            "blocked":        _int(row[2]),
            "block_rate_pct": round(_int(row[2]) / max(_int(row[1]), 1) * 100, 2),
        }
        for row in cur.fetchall()
    ]


    return {
        "role_event_counts":     role_event_counts,
        "role_score_averages":   role_score_averages,
        "role_risk_breakdown":   role_risk_breakdown,
        "role_action_breakdown": role_action_breakdown,
        "role_block_rates":      role_block_rates,
    }


# =============================================================================
# legacy aliases kept for backward compatibility with existing router
# =============================================================================

def fetch_kpis(db) -> dict:
    """Alias — returns the event KPI block (used by existing /fraud/kpis route)."""
    return fetch_event_kpis(db)


def risk_trend_over_time(db) -> list:
    return fetch_action_stats(db)["risk_trend"]


def fraud_type_stats(db) -> list:
    cur = db.cursor()
    cur.execute("SELECT fraud_type, COUNT(*) FROM fraud_decisions GROUP BY fraud_type")
    return [{"name": row[0], "value": _int(row[1])} for row in cur.fetchall()]


def risk_classification_stats(db) -> list:
    cur = db.cursor()
    cur.execute("SELECT risk_level, COUNT(*) FROM fraud_decisions GROUP BY risk_level")
    return [{"name": row[0], "value": _int(row[1])} for row in cur.fetchall()]


def source_volume_stats(db) -> list:
    return fetch_action_stats(db)["source_volume"]