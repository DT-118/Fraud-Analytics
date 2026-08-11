"""
dashboard_repo.py

All DB queries for the fraud dashboard.

Sections:
  1.  Event Intelligence KPIs
  2.  Actions & Decisions
  3.  Score Distribution
  4.  Risk Band Analytics
  5.  Rules & Chains Analytics
  6.  IP & Device Flags
  7.  Sessions Panel
  8.  Per-User Risk Profile  (identity + service + activity log)
  9.  Cross-Service Flags (global)
  10. Transaction List (paginated)
  11. Transaction Drill-Down (full journey)
"""

from dotenv import load_dotenv

load_dotenv()

import os
from typing import Optional

_REPORT_TZ = os.environ.get("REPORT_TIMEZONE", "UTC")

_ALLOW_ACTIONS = {"ALLOW", "MONITOR"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _isoformat(val) -> Optional[str]:
    return val.isoformat() if val else None


def _int(val, default=0) -> int:
    return int(val) if val is not None else default


def _float(val, default=0.0) -> float:
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
      events_today               — fraud_events since midnight UTC
      events_last_1h             — fraud_events in last 60 min
      events_per_minute          — decisions in last 60s / 60
      unique_users               — distinct subject_ids in fraud_events
      events_by_service          — {AUTH, ENROLL, CONSENT, WALLET: count}
      events_by_environment      — {prod, staging, sandbox: count}
      events_by_source           — {API, KAFKA: count}
      events_with_exception_code — count where exception_code IS NOT NULL
      exception_code_breakdown   — [{code, count}]
      events_in_session          — events that have a non-null session_id
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
        WHERE created_at >= DATE_TRUNC('day', NOW() AT TIME ZONE %s AT TIME ZONE 'UTC')
    """, (_REPORT_TZ,))
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
    events_per_minute = round(recent / 60.0, 4)

    # unique users
    cur.execute("SELECT COUNT(DISTINCT subject_id) FROM fraud_events")
    unique_users = _int(cur.fetchone()[0])

    # by service (action column in fraud_events maps to taxonomy)
    cur.execute("""
        SELECT UPPER(action), COUNT(*)
        FROM fraud_events
        GROUP BY UPPER(action)
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
    events_in_session = _int(cur.fetchone()[0])

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
        "events_per_minute":          events_per_minute,
        "unique_users":               unique_users,
        "events_by_service":          events_by_service,
        "events_by_environment":      events_by_environment,
        "events_by_source":           events_by_source,
        "events_with_exception_code": events_with_exception_code,
        "exception_code_breakdown":   exception_code_breakdown,
        "events_in_session":          events_in_session,
        "unique_sessions":            unique_sessions,
    }


# =============================================================================
# 2. ACTIONS & DECISIONS
# =============================================================================

def fetch_action_stats(db) -> dict:
    """
    Returns:
      action_counts          — {ALLOW, MONITOR, FLAG, STEP_UP, BLOCK: count}
      action_by_service      — [{service, ALLOW, MONITOR, FLAG, STEP_UP, BLOCK}]
      block_rate_pct         — BLOCK / total * 100
      stepup_rate_pct        — STEP_UP / total * 100
      risk_trend             — [{hour, NORISK, LOW, MEDIUM, HIGH, CRITICAL}] last 24h
      source_volume          — [{hour, api, kafka}] last 24h
    """
    cur = db.cursor()

    cur.execute("""
        SELECT policy_action, COUNT(*) AS cnt
        FROM fraud_decisions
        GROUP BY policy_action
    """)
    action_counts = {row[0]: _int(row[1]) for row in cur.fetchall()}
    total = sum(action_counts.values()) or 1

    # by service
    cur.execute("""
        SELECT
            fraud_type,
            SUM(CASE WHEN policy_action = 'ALLOW'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'MONITOR' THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'FLAG'    THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'STEP_UP' THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'BLOCK'   THEN 1 ELSE 0 END)
        FROM fraud_decisions
        GROUP BY fraud_type
    """)
    action_by_service = [
        {
            "service":  row[0],
            "ALLOW":    _int(row[1]),
            "MONITOR":  _int(row[2]),
            "FLAG":     _int(row[3]),
            "STEP_UP":  _int(row[4]),
            "BLOCK":    _int(row[5]),
        }
        for row in cur.fetchall()
    ]

    # risk trend last 24h (hourly)
    cur.execute("""
        SELECT
            DATE_TRUNC('hour', created_at AT TIME ZONE %s) AS hour,
            SUM(CASE WHEN risk_level = 'NORISK'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'LOW'      THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'MEDIUM'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'HIGH'     THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END)
        FROM fraud_decisions
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY 1
        ORDER BY 1
    """, (_REPORT_TZ,))
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

    # source volume last 24h (hourly)
    cur.execute("""
        SELECT
            TO_CHAR(DATE_TRUNC('hour', created_at AT TIME ZONE %s), 'HH24:MI') AS hour_label,
            SUM(CASE WHEN source = 'API'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN source = 'KAFKA' THEN 1 ELSE 0 END)
        FROM fraud_decisions
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY DATE_TRUNC('hour', created_at AT TIME ZONE %s), hour_label
        ORDER BY DATE_TRUNC('hour', created_at AT TIME ZONE %s)
    """, (_REPORT_TZ, _REPORT_TZ, _REPORT_TZ))
    source_volume = [
        {"hour": row[0], "api": _int(row[1]), "kafka": _int(row[2])}
        for row in cur.fetchall()
    ]

    return {
        "action_counts":     action_counts,
        "action_by_service": action_by_service,
        "block_rate_pct":    round(action_counts.get("BLOCK", 0) / total * 100, 2),
        "stepup_rate_pct":   round(action_counts.get("STEP_UP", 0) / total * 100, 2),
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
      avg_score_by_service — {AUTH, ENROLL, CONSENT, WALLET: avg_score}
      avg_score_by_action  — {ALLOW, MONITOR, FLAG, STEP_UP, BLOCK: avg_score}
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

    # avg by action
    cur.execute("""
        SELECT policy_action, AVG(score)
        FROM fraud_decisions
        GROUP BY policy_action
    """)
    avg_score_by_action = {row[0]: round(_float(row[1]), 2) for row in cur.fetchall()}

    return {
        "histogram":            histogram,
        "avg_score":            avg_score,
        "avg_score_by_service": avg_score_by_service,
        "avg_score_by_action":  avg_score_by_action,
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

    # chain activations — rule_weights JSONB stores chain_reason per rule
    # shape: {"AUTH-01": 90, "AUTH-04": 60}  (plain weights after chain boost)
    # fraud_service stores decision["rule_weights"] = scoring_output["role_adjusted_weights"]
    # which is {rule_id: int_weight} — chain info lives in triggered_rules items
    # that had chain_reason set. We stored triggered_rules as text[] of rule_ids only,
    # but rule_weights JSONB has the boosted weight. We can detect chain fires by
    # looking for decisions where a rule appears in triggered_rules AND its weight
    # in rule_weights is higher than the base weight defined in YAML.
    # Practical approach: store chain_reason in a separate JSONB column (future),
    # for now count decisions where ANY rule weight exceeds typical base values (>100
    # after boost). Instead, we surface the raw count of decisions that had at least
    # one chained boost — detectable because rule_weights jsonb values differ from
    # the sum of raw weights stored in features.
    # Best available signal: count of decisions where triggered_rules has 2+ entries
    # that are known chain pairs. We'll query chain co-occurrences instead.

    # chain co-occurrence: AUTH-04 + AUTH-01 (NEW_DEVICE_WITH_FAILURES)
    chain_definitions = [
        ("NEW_DEVICE_WITH_FAILURES",         ["AUTH-04", "AUTH-01"]),
        ("GEO_JUMP_NEW_DEVICE_WITH_IP_FAILURES", ["AUTH-05", "AUTH-04", "AUTH-02"]),
        ("FLAGGED_IP_WITH_FAILURES",         ["IP-01", "AUTH-01"]),
        ("FLAGGED_IP_NEW_DEVICE_GEO_JUMP",   ["IP-01", "AUTH-04", "AUTH-05"]),
        ("LIVENESS_SPOOF_NEW_DEVICE",        ["LIVE-01", "AUTH-04", "AUTH-01"]),
        ("SHARED_DEVICE_CONSENT_SPIKE",      ["DEVICE-01", "CONS-01"]),
        ("FLAGGED_IP_CONSENT_SPIKE",         ["IP-01", "CONS-01"]),
        ("SHARED_DEVICE_DOC_FAILURES",       ["DEVICE-01", "ENR-01"]),
        ("FLAGGED_IP_FACE_MISMATCH",         ["IP-01", "ENR-02"]),
        ("FLAGGED_IP_SHARED_DEVICE_ENROLL",  ["IP-01", "DEVICE-01", "ENR-03"]),
        ("SHARED_DEVICE_PROVISION_BURST",    ["DEVICE-01", "WAL-01"]),
        ("FLAGGED_IP_SHARE_BURST",           ["IP-01", "WAL-02"]),
        ("FLAGGED_IP_SHARED_DEVICE_COMBINED_BURST", ["IP-01", "DEVICE-01", "WAL-03"]),
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
# 6. IP & DEVICE FLAGS
# =============================================================================

def fetch_ip_device_stats(db) -> dict:
    """
    Returns:
      total_flagged_ips          — active rows in ip_reputation
      events_from_flagged_ips    — decisions where features->ip_is_flagged = '1'
      flagged_ip_list            — [{src_ip, flag_reason, flagged_at, flagged_by}]
      total_flagged_devices      — device_trust rows where is_flagged=true
      events_from_shared_devices — decisions where features->device_subject_count >= 5
      flagged_device_list        — [{device_id, subject_count, flag_reason, last_seen_at}]
    """
    cur = db.cursor()

    # flagged IPs
    cur.execute("SELECT COUNT(*) FROM ip_reputation WHERE is_active = TRUE")
    total_flagged_ips = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT COUNT(*) FROM fraud_decisions
        WHERE (features->>'ip_is_flagged')::int = 1
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

    # flagged devices
    cur.execute("SELECT COUNT(*) FROM device_trust WHERE is_flagged = TRUE")
    total_flagged_devices = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT COUNT(*) FROM fraud_decisions
        WHERE (features->>'device_subject_count')::int >= 5
    """)
    events_from_shared_devices = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT device_id, subject_count, flag_reason, last_seen_at
        FROM device_trust
        WHERE is_flagged = TRUE
        ORDER BY subject_count DESC
    """)
    flagged_device_list = [
        {
            "device_id":     row[0],
            "subject_count": _int(row[1]),
            "flag_reason":   row[2],
            "last_seen_at":  _isoformat(row[3]),
        }
        for row in cur.fetchall()
    ]

    return {
        "total_flagged_ips":          total_flagged_ips,
        "events_from_flagged_ips":    events_from_flagged_ips,
        "flagged_ip_list":            flagged_ip_list,
        "total_flagged_devices":      total_flagged_devices,
        "events_from_shared_devices": events_from_shared_devices,
        "flagged_device_list":        flagged_device_list,
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
# 9. PER-USER RISK PROFILE
# =============================================================================

def fetch_user_profile(db, subject_id: str) -> Optional[dict]:
    """
    Full risk profile for one subject_id.

    Returns:
      identity         — composite score, service scores, cross-service flag,
                         total_events, highest_risk_level, updated_at
      service_profiles — [{service, rolling_score, event_count, last_event_id,
                           last_event_time, last_risk_level, last_action_taken}]
      activity_log     — every past decision for this user, newest first
                         [{event_id, service, score, risk_level, action,
                           triggered_rules, features, created_at, log_line}]
      session_summary  — all sessions this user has had
    """
    cur = db.cursor()

    # identity profile
    cur.execute("""
        SELECT composite_score, auth_score, enroll_score, consent_score, wallet_score,
               cross_service_flag, cross_service_flag_reason, cross_service_flag_at,
               total_events, highest_risk_level, updated_at
        FROM user_identity_risk_profile
        WHERE subject_id = %s
    """, (subject_id,))
    row = cur.fetchone()
    if not row:
        return None

    identity = {
        "composite_score":           _float(row[0]),
        "service_scores": {
            "AUTH":    _float(row[1]),
            "ENROLL":  _float(row[2]),
            "CONSENT": _float(row[3]),
            "WALLET":  _float(row[4]),
        },
        "cross_service_flag":         bool(row[5]),
        "cross_service_flag_reason":  row[6],
        "cross_service_flag_at":      _isoformat(row[7]),
        "total_events":               _int(row[8]),
        "highest_risk_level":         row[9],
        "updated_at":                 _isoformat(row[10]),
    }

    # per-service profiles
    cur.execute("""
        SELECT service, rolling_score, event_count,
               last_event_id, last_event_time,
               last_risk_level, last_action_taken, updated_at
        FROM user_service_risk_profile
        WHERE subject_id = %s
        ORDER BY service
    """, (subject_id,))
    service_profiles = [
        {
            "service":           row[0],
            "rolling_score":     _float(row[1]),
            "event_count":       _int(row[2]),
            "last_event_id":     str(row[3]) if row[3] else None,
            "last_event_time":   _isoformat(row[4]),
            "last_risk_level":   row[5],
            "last_action_taken": row[6],
            "updated_at":        _isoformat(row[7]),
        }
        for row in cur.fetchall()
    ]

    # full activity log from fraud_decisions — every past score
    cur.execute("""
        SELECT
            d.event_id,
            d.fraud_type,
            d.score,
            d.risk_level,
            d.policy_action,
            d.triggered_rules,
            d.features,
            d.rule_weights,
            d.source,
            d.config_version,
            d.created_at,
            e.event_time,
            e.session_id,
            e.security_payload,
            e.exception_code
        FROM fraud_decisions d
        LEFT JOIN fraud_events e ON e.event_id = d.event_id
        WHERE d.subject_id = %s
        ORDER BY d.created_at DESC
    """, (subject_id,))

    activity_log = []
    for r in cur.fetchall():
        event_id       = str(r[0]) if r[0] else None
        service        = r[1]
        score          = _int(r[2])
        risk_level     = r[3]
        action         = r[4]
        triggered      = r[5] or []
        features       = r[6] or {}
        rule_weights   = r[7] or {}
        source         = r[8]
        config_version = r[9]
        created_at     = _isoformat(r[10])
        event_time     = _isoformat(r[11])
        session_id     = r[12]
        security       = r[13] or {}
        exception_code = r[14]

        log_line = _build_user_log_line(
            service=service,
            score=score,
            risk_level=risk_level,
            action=action,
            triggered_rules=triggered,
            features=features,
            security=security,
            exception_code=exception_code,
        )

        activity_log.append({
            "event_id":       event_id,
            "service":        service,
            "score":          score,
            "risk_level":     risk_level,
            "action":         action,
            "triggered_rules": triggered,
            "features":       features,
            "rule_weights":   rule_weights,
            "source":         source,
            "config_version": config_version,
            "created_at":     created_at,
            "event_time":     event_time,
            "session_id":     session_id,
            "exception_code": exception_code,
            "log_line":       log_line,
        })

    # sessions for this user
    cur.execute("""
        SELECT session_id, event_count, high_event_count,
               has_critical, max_score, session_risk_level,
               first_event_at, last_event_at
        FROM fraud_sessions
        WHERE subject_id = %s
        ORDER BY last_event_at DESC NULLS LAST
    """, (subject_id,))
    session_summary = [
        {
            "session_id":        row[0],
            "event_count":       _int(row[1]),
            "high_event_count":  _int(row[2]),
            "has_critical":      bool(row[3]),
            "max_score":         _int(row[4]),
            "session_risk_level": row[5],
            "first_event_at":    _isoformat(row[6]),
            "last_event_at":     _isoformat(row[7]),
        }
        for row in cur.fetchall()
    ]

    return {
        "subject_id":       subject_id,
        "identity":         identity,
        "service_profiles": service_profiles,
        "activity_log":     activity_log,
        "session_summary":  session_summary,
    }


def _build_user_log_line(
    service: str,
    score: int,
    risk_level: str,
    action: str,
    triggered_rules: list,
    features: dict,
    security: dict,
    exception_code: Optional[str],
) -> str:
    """
    Build a single human-readable log sentence for the user activity log.

    Example outputs:
      "AUTH event scored 72 (HIGH) — STEP_UP triggered. Rules fired: AUTH-01, AUTH-04.
       Device change detected, 3 login failures preceding."
      "ENROLL event scored 30 (MEDIUM) — FLAG. Document scan failed twice."
      "WALLET event scored 0 (NORISK) — ALLOW. No signals detected."
    """
    parts = [f"{service} event scored {score} ({risk_level}) — {action}."]

    if triggered_rules:
        parts.append(f"Rules fired: {', '.join(triggered_rules)}.")

    # human signals from features
    signals = []

    # AUTH signals
    fail_count = int(features.get("user_fail_count", 0) or 0)
    if fail_count > 0:
        signals.append(f"{fail_count} consecutive login failure(s)")

    fbs = int(features.get("fail_before_success", 0) or 0)
    if fbs > 0:
        signals.append(f"success after {fbs} prior failure(s) — credential stuffing signal")

    if int(features.get("is_new_device", 0) or 0) > 0:
        signals.append("new device detected")

    if int(features.get("geo_mismatch", 0) or 0) == 1:
        geo = security.get("geo_loc", "unknown location")
        signals.append(f"geo location change (now: {geo})")

    if int(features.get("is_old_browser", 0) or 0) == 1:
        signals.append("browser version downgrade detected")

    if int(features.get("suspicious_resolution", 0) or 0) > 0:
        signals.append("emulator-like screen resolution")

    if int(features.get("odd_login_hour", 0) or 0) == 1:
        signals.append("login at unusual hour")

    if int(features.get("language_flip_on_success", 0) or 0) > 0:
        signals.append("language changed on successful login")

    # liveness
    spoof = int(features.get("spoof_detected", 0) or 0)
    if spoof > 0:
        signals.append(f"biometric spoof detected ({spoof} attempt(s))")

    if int(features.get("missing_liveness", 0) or 0) == 1:
        signals.append("liveness check required but not provided")

    # enroll
    doc_fails = int(features.get("document_failures", 0) or 0)
    if doc_fails > 0:
        signals.append(f"document scan failed {doc_fails} time(s)")

    face_mismatch = int(features.get("face_doc_mismatch", 0) or 0)
    if face_mismatch > 0:
        signals.append(f"face-document mismatch {face_mismatch} time(s)")

    enroll_count = int(features.get("device_enroll_count", 0) or 0)
    if enroll_count > 1:
        signals.append(f"{enroll_count} identities enrolled from same device")

    # consent
    grant_count = int(features.get("consent_grant_count", 0) or 0)
    if grant_count > 0:
        signals.append(f"{grant_count} consent grant(s) in window")

    # wallet
    prov = int(features.get("provision_count", 0) or 0)
    share = int(features.get("share_count", 0) or 0)
    if prov > 0:
        signals.append(f"{prov} wallet provision(s) in window")
    if share > 0:
        signals.append(f"{share} wallet share(s) in window")

    # device/ip
    dev_count = int(features.get("device_subject_count", 0) or 0)
    if dev_count >= 5:
        signals.append(f"shared device used by {dev_count} subjects")

    if int(features.get("ip_is_flagged", 0) or 0) == 1:
        ip = security.get("src_ip", "unknown IP")
        signals.append(f"source IP {ip} is on fraud blocklist")

    # exception
    if exception_code:
        signals.append(f"exception code: {exception_code}")

    if signals:
        parts.append(" | ".join(signals).capitalize() + ".")
    elif not triggered_rules:
        parts.append("No fraud signals detected.")

    return " ".join(parts)


# =============================================================================
# 10. PER-SERVICE ACTIVITY LOG
# =============================================================================

def fetch_service_activity_log(db, service: str, page: int = 1, limit: int = 50) -> dict:
    """
    All decisions for a given service (AUTH/ENROLL/CONSENT/WALLET)
    with a human-readable log line per event.

    Useful for the 'service drill-down' panel showing past activity
    and trends for that service across all users.

    Returns:
      service_summary — {total_events, avg_score, top_risk_level,
                          action_breakdown, top_triggered_rules}
      data            — [{event_id, subject_id, score, risk_level, action,
                           triggered_rules, features, created_at, log_line}]
    """
    cur = db.cursor()
    offset = (page - 1) * limit

    cur.execute(
        "SELECT COUNT(*) FROM fraud_decisions WHERE fraud_type = %s",
        (service,),
    )
    total = _int(cur.fetchone()[0])

    cur.execute(
        "SELECT AVG(score) FROM fraud_decisions WHERE fraud_type = %s",
        (service,),
    )
    avg_score = round(_float(cur.fetchone()[0]), 2)

    cur.execute("""
        SELECT risk_level, COUNT(*) AS cnt
        FROM fraud_decisions
        WHERE fraud_type = %s
        GROUP BY risk_level
        ORDER BY cnt DESC
        LIMIT 1
    """, (service,))
    row = cur.fetchone()
    top_risk_level = row[0] if row else None

    cur.execute("""
        SELECT policy_action, COUNT(*) AS cnt
        FROM fraud_decisions
        WHERE fraud_type = %s
        GROUP BY policy_action
    """, (service,))
    action_breakdown = {r[0]: _int(r[1]) for r in cur.fetchall()}

    cur.execute("""
        SELECT rule_id, COUNT(*) AS cnt
        FROM (
            SELECT UNNEST(triggered_rules) AS rule_id
            FROM fraud_decisions
            WHERE fraud_type = %s
        ) t
        GROUP BY rule_id
        ORDER BY cnt DESC
        LIMIT 10
    """, (service,))
    top_triggered_rules = [
        {"rule_id": r[0], "count": _int(r[1])} for r in cur.fetchall()
    ]

    cur.execute("""
        SELECT
            d.event_id, d.subject_id, d.score, d.risk_level,
            d.policy_action, d.triggered_rules, d.features,
            d.created_at, e.security_payload, e.exception_code
        FROM fraud_decisions d
        LEFT JOIN fraud_events e ON e.event_id = d.event_id
        WHERE d.fraud_type = %s
        ORDER BY d.created_at DESC
        LIMIT %s OFFSET %s
    """, (service, limit, offset))

    data = []
    for r in cur.fetchall():
        features  = r[6] or {}
        security  = r[8] or {}
        triggered = r[5] or []
        log_line  = _build_user_log_line(
            service=service,
            score=_int(r[2]),
            risk_level=r[3],
            action=r[4],
            triggered_rules=triggered,
            features=features,
            security=security,
            exception_code=r[9],
        )
        data.append({
            "event_id":       str(r[0]) if r[0] else None,
            "subject_id":     r[1],
            "score":          _int(r[2]),
            "risk_level":     r[3],
            "action":         r[4],
            "triggered_rules": triggered,
            "features":       features,
            "created_at":     _isoformat(r[7]),
            "log_line":       log_line,
        })

    return {
        "service": service,
        "service_summary": {
            "total_events":        total,
            "avg_score":           avg_score,
            "top_risk_level":      top_risk_level,
            "action_breakdown":    action_breakdown,
            "top_triggered_rules": top_triggered_rules,
        },
        "data":        data,
        "page":        page,
        "limit":       limit,
        "total":       total,
        "total_pages": (total + limit - 1) // limit,
    }


# =============================================================================
# 11. TRANSACTION LIST (paginated)
# =============================================================================

def fetch_transactions(db, page: int = 1, limit: int = 20) -> dict:
    cur = db.cursor()
    offset = (page - 1) * limit

    cur.execute("SELECT COUNT(*) FROM fraud_decisions")
    total = _int(cur.fetchone()[0])

    cur.execute("""
        SELECT
            event_id, subject_id, created_at,
            fraud_type, source, score, risk_level, policy_action
        FROM fraud_decisions
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """, (limit, offset))

    data = [
        {
            "event_id":   str(row[0]),
            "subject_id": row[1],
            "created_at": _isoformat(row[2]),
            "service":    row[3],
            "source":     row[4],
            "score":      _int(row[5]),
            "risk_level": row[6],
            "action":     row[7],
            "status":     "ALLOWED" if row[7] in _ALLOW_ACTIONS else "REVIEWED",
        }
        for row in cur.fetchall()
    ]

    return {
        "data":        data,
        "page":        page,
        "limit":       limit,
        "total":       total,
        "total_pages": (total + limit - 1) // limit,
    }


# =============================================================================
# 12. TRANSACTION DRILL-DOWN (full journey for one event_id)
# =============================================================================

def fetch_transaction_detail(db, event_id: str) -> dict:
    """
    Full journey for a single event:
      decision   — score, risk, action, rules, weights, features
      event      — raw payloads (security, biometric, document, consent, wallet)
      session    — session state at time of this event
      user_state — composite profile score just before this event
      log_line   — human-readable summary sentence
    """
    cur = db.cursor()

    cur.execute("""
        SELECT
            d.event_id, d.subject_id, d.fraud_type,
            d.score, d.risk_level, d.policy_action,
            d.triggered_rules, d.rule_weights, d.features,
            d.source, d.config_version, d.created_at,
            d.role, d.exception_code,
            e.action, e.event_time, e.session_id,
            e.security_payload, e.biometric_payload,
            e.document_payload, e.consent_payload, e.wallet_payload,
            e.environment
        FROM fraud_events e
        LEFT JOIN fraud_decisions d ON d.event_id = e.event_id
        WHERE e.event_id = %s
    """, (event_id,))

    row = cur.fetchone()
    if not row:
        return {"status": "EVENT_NOT_FOUND"}

    decision_exists = row[0] is not None
    subject_id      = row[1]
    service         = row[2]
    session_id      = row[16]
    security        = row[17] or {}
    triggered       = row[6] or []
    features        = row[8] or {}

    decision_block = {}
    if decision_exists:
        log_line = _build_user_log_line(
            service=service,
            score=_int(row[3]),
            risk_level=row[4],
            action=row[5],
            triggered_rules=triggered,
            features=features,
            security=security,
            exception_code=row[13],
        )
        decision_block = {
            "event_id":        str(row[0]),
            "subject_id":      subject_id,
            "service":         service,
            "score":           _int(row[3]),
            "risk_level":      row[4],
            "action":          row[5],
            "status":          "ALLOWED" if row[5] in _ALLOW_ACTIONS else "REVIEWED",
            "triggered_rules": triggered,
            "rule_weights":    row[7] or {},
            "features":        features,
            "source":          row[9],
            "config_version":  row[10],
            "created_at":      _isoformat(row[11]),
            "role":            row[12],
            "exception_code":  row[13],
            "log_line":        log_line,
        }
    else:
        decision_block = {"status": "DECISION_NOT_YET_AVAILABLE"}

    event_block = {
        "action":            row[14],
        "event_time":        _isoformat(row[15]),
        "session_id":        session_id,
        "environment":       row[22],
        "security_payload":  security,
        "biometric_payload": row[18],
        "document_payload":  row[19],
        "consent_payload":   row[20],
        "wallet_payload":    row[21],
    }

    # session context
    session_block = None
    if session_id:
        cur.execute("""
            SELECT session_id, event_count, high_event_count,
                   has_critical, max_score, session_risk_level
            FROM fraud_sessions
            WHERE session_id = %s
        """, (session_id,))
        s = cur.fetchone()
        if s:
            session_block = {
                "session_id":        s[0],
                "event_count":       _int(s[1]),
                "high_event_count":  _int(s[2]),
                "has_critical":      bool(s[3]),
                "max_score":         _int(s[4]),
                "session_risk_level": s[5],
            }

    # user composite profile at time of this event
    # = the decision immediately before this one for the same subject
    user_state_block = None
    if subject_id and decision_exists:
        cur.execute("""
            SELECT score, risk_level, policy_action, created_at
            FROM fraud_decisions
            WHERE subject_id = %s
              AND created_at < %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (subject_id, row[11]))
        prev = cur.fetchone()
        if prev:
            user_state_block = {
                "previous_score":      _int(prev[0]),
                "previous_risk_level": prev[1],
                "previous_action":     prev[2],
                "previous_event_at":   _isoformat(prev[3]),
            }

        # current identity profile
        cur.execute("""
            SELECT composite_score, highest_risk_level, cross_service_flag
            FROM user_identity_risk_profile
            WHERE subject_id = %s
        """, (subject_id,))
        prof = cur.fetchone()
        if prof:
            user_state_block = {
                **(user_state_block or {}),
                "current_composite_score": _float(prof[0]),
                "highest_risk_level":      prof[1],
                "cross_service_flag":      bool(prof[2]),
            }

    return {
        "decision":   decision_block,
        "event":      event_block,
        "session":    session_block,
        "user_state": user_state_block,
    }


# =============================================================================
# 13. ROLE ANALYTICS
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
            SUM(CASE WHEN policy_action = 'ALLOW'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'MONITOR' THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'FLAG'    THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'STEP_UP' THEN 1 ELSE 0 END),
            SUM(CASE WHEN policy_action = 'BLOCK'   THEN 1 ELSE 0 END)
        FROM fraud_decisions
        GROUP BY role
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
            SUM(CASE WHEN policy_action = 'BLOCK' THEN 1 ELSE 0 END) AS blocked
        FROM fraud_decisions
        GROUP BY role
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