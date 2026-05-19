# app/storage/dashboard_repo.py

from typing import List, Dict, Any

# kpi cards row-1
def fetch_kpis(db):
    executor = db.cursor()
    executor.execute("""
        SELECT
            (SELECT COUNT(*) FROM fraud_events) AS total_events,

            (SELECT COUNT(*) FROM fraud_decisions) AS successful
    """)
    total, success = executor.fetchone()

    failed = total - success
    # throughput based on last 1 minute
    executor.execute("""
        SELECT COUNT(*)
        FROM fraud_decisions
        WHERE created_at > now() - interval '1 minute'
    """)
    recent = executor.fetchone()[0]
    throughput = recent / 60.0 if recent else 0

    return {
        "total": total,
        "success": success,
        "failed": failed,
        "throughput": round(throughput,4),
    }

#risk trend over time row-2
def risk_trend_over_time(db):
    executor = db.cursor()
    executor.execute("""
        SELECT
            DATE_TRUNC(
                'hour',
                created_at AT TIME ZONE 'Asia/Kolkata'
            ) AS time,
            SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical
            
        FROM fraud_decisions
        WHERE created_at > now() - interval '24 hours'
        GROUP BY 1
        ORDER BY 1

    """)
    return [
        {
            "time": row[0],
            "low": row[1],
            "medium": row[2],
            "high": row[3],
            "critical": row[4]
        }
        for row in executor.fetchall()
    ]





#        SELECT
#            TO_CHAR(DATE_TRUNC('hour', created_at), 'HH24:MI') AS time,
#            SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) AS low,
#            SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
#            SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) AS high
#        FROM fraud_decisions
#        WHERE created_at > now() - interval '24 hours'
#        GROUP BY time
#        ORDER BY time



#pie chart based on fraud type row-3
def fraud_type_stats(db):
    executor = db.cursor()
    executor.execute("""
        SELECT fraud_type, COUNT(*)
        FROM fraud_decisions
        GROUP BY fraud_type
    """)
    return [
        {"name": row[0], "value": row[1]}
        for row in executor.fetchall()
    ]

#pie chart based on risk classification row-3
def risk_classification_stats(db):
    executor = db.cursor()
    executor.execute("""
        SELECT risk_level, COUNT(*)
        FROM fraud_decisions
        GROUP BY risk_level
    """)
    return [
        {"name": row[0], "value": row[1]}
        for row in executor.fetchall()
    ]


#source volume line chart row-4
#def source_volume_stats(db):
#    executor = db.cursor()
##    executor.execute("""
##        SELECT
##            TO_CHAR(DATE_TRUNC('hour', created_at), 'HH24:MI') AS hour,
##            source,
##            COUNT(*)
##        FROM fraud_decisions
##        GROUP BY hour, source
##        ORDER BY hour
##    """)
##    
#    
##    executor.execute("""
##        SELECT
##            TO_CHAR(
##                DATE_TRUNC('hour', created_at AT TIME ZONE 'Asia/Kolkata'),
##                'HH24:MI'
##            ) AS hour,
##            source,
##            COUNT(*)
##        FROM fraud_decisions
##        WHERE created_at > now() - interval '24 hours'
##        GROUP BY hour, source
##        ORDER BY hour
##    """)
#
#    executor.execute("""
#          SELECT
#              DATE_TRUNC('hour', created_at AT TIME ZONE 'Asia/Kolkata') AS hour_ts,
#              TO_CHAR(
#                  DATE_TRUNC('hour', created_at AT TIME ZONE 'Asia/Kolkata'),
#                  'DD HH24:MI'
#              ) AS hour_label,
#              source,
#              COUNT(*)
#          FROM fraud_decisions
#          WHERE created_at > now() - interval '24 hours'
#          GROUP BY hour_ts, hour_label, source
#          ORDER BY hour_ts ASC;
#      """)
#
#    rows = executor.fetchall()
#    result = {}
#
##    for hour, source, count in rows:
##        result.setdefault(hour, {"time": hour, "api": 0, "kafka": 0})
##        result[hour][source.lower()] = count
##
##    return list(result.values())
#
#    for hour_ts, hour_label, source, count in rows:
#          result.setdefault(hour_label, {
#              "time": hour_label,
#              "api": 0,
#              "kafka": 0
#          })
#          result[hour_label][source.lower()] = count
# 
#          return list(result. Values())

def source_volume_stats(db):
    executor = db.cursor()
 
    executor.execute("""
        SELECT
            DATE_TRUNC('hour', created_at AT TIME ZONE 'Asia/Kolkata') AS hour_ts,
            TO_CHAR(
                DATE_TRUNC('hour', created_at AT TIME ZONE 'Asia/Kolkata'),
                'HH24:MI'
            ) AS hour_label,
            source,
            COUNT(*)
        FROM fraud_decisions
        WHERE created_at > now() - interval '24 hours'
        GROUP BY hour_ts, hour_label, source
        ORDER BY hour_ts ASC;
    """)
 
    rows = executor.fetchall()
 
    result = {}
 
    for hour_ts, hour_label, source, count in rows:
        result.setdefault(hour_label, {
            "time": hour_label,
            "api": 0,
            "kafka": 0
        })
 
        result[hour_label][source.lower()] = count
 
    # ? return AFTER loop
    return list(result.values())



#transaction table row-5
def fetch_transactions(db, page, limit):
    offset = (page - 1) * limit
    executor = db.cursor()

    # Get total count
    executor.execute("SELECT COUNT(*) FROM fraud_decisions")
    total = executor.fetchone()[0]

    # Get paginated rows
    executor.execute("""
        SELECT
            event_id,
            subject_id,
            created_at,
            fraud_type,
            source,
            score,
            risk_level,
            policy_action
        FROM fraud_decisions
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """, (limit, offset))

    rows = executor.fetchall()

    data = [
        {
            "id": str(row[0]),
            "subject_id": row[1],
            "time": row[2].isoformat(),
            "type": row[3],
            "source": row[4],
            "score": row[5],
            "risk": row[6],
            "status": "SUCCESS" if row[7] == "ALLOW" else "FAILED",
        }
        for row in rows
    ]

    return {
        "data": data,
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": (total + limit - 1) // limit,
    }



# #transaction in detail with id for row-5 table
# def fetch_transaction_detail(db, event_id):
#     executor = db.cursor()
#     executor.execute("""
#         SELECT
#             event_id,
#             subject_id,
#             fraud_type,
#             score,
#             risk_level,
#             policy_action,
#             triggered_rules,
#             features,
#             source,
#             config_version,
#             created_at
#         FROM fraud_decisions
#         WHERE event_id = %s
#     """, (event_id,))

#     row = executor.fetchone()
#     if not row:
#         return {}

#     return {
#         "id": str(row[0]),
#         "subject_id": row[1],
#         "fraud_type": row[2],
#         "score": row[3],
#         "risk": row[4],
#         "status": "SUCCESS" if row[5] == "ALLOW" else "FAILED",
#         "policy_action": row[5],
#         "triggered_rules": row[6],
#         "features": row[7],
#         "source": row[8],
#         "config_version": row[9],
#         "created_at": row[10].isoformat(),
#     }




#def fetch_transaction_detail(db, event_id):
#    executor = db.cursor()
#    executor.execute("""
#        SELECT
#            d.event_id,
#            d.subject_id,
#            d.fraud_type,
#            d.score,
#            d.risk_level,
#            d.policy_action,
#            d.triggered_rules,
#            d.features,
#            d.source,
#            d.config_version,
#            d.created_at,
#
#            e.action,
#            e.event_time,
#            e.security_payload,
#            e.biometric_payload,
#            e.document_payload,
#            e.consent_payload,
#            e.wallet_payload
#
#        FROM fraud_decisions d
#        JOIN fraud_events e
#          ON d.event_id = e.event_id
#        WHERE d.event_id = %s
#    """, (event_id,))
#
#    row = executor.fetchone()
#    if not row:
#        return {}
#
#    return {
#        "decision": {
#            "id": str(row[0]),
#            "subject_id": row[1],
#            "fraud_type": row[2],
#            "score": row[3],
#            "risk": row[4],
#            "status": "SUCCESS" if row[5] == "ALLOW" else "FAILED",
#            "policy_action": row[5],
#            "triggered_rules": row[6],
#            "features": row[7],
#            "source": row[8],
#            "config_version": row[9],
#            "created_at": row[10].isoformat(),
#        },
#        "event": {
#            "action": row[11],
#            "event_time": row[12].isoformat(),
#            "security_payload": row[13],
#            "biometric_payload": row[14],
#            "document_payload": row[15],
#            "consent_payload": row[16],
#            "wallet_payload": row[17],
#        },
#    }


def fetch_transaction_detail(db, event_id):
    executor = db.cursor()

    executor.execute("""
        SELECT
            -- Decision fields
            d.event_id,
            d.subject_id,
            d.fraud_type,
            d.score,
            d.risk_level,
            d.policy_action,
            d.triggered_rules,
            d.features,
            d.source,
            d.config_version,
            d.created_at,

            -- Event fields
            e.action,
            e.event_time,
            e.security_payload,
            e.biometric_payload,
            e.document_payload,
            e.consent_payload,
            e.wallet_payload

        FROM fraud_events e
        LEFT JOIN fraud_decisions d
          ON d.event_id = e.event_id
        WHERE e.event_id = %s
    """, (event_id,))

    row = executor.fetchone()

    # ?? Event not found
    if not row:
        return {"status": "EVENT_NOT_FOUND"}

    decision_exists = row[0] is not None

    if decision_exists:
        decision_block = {
            "id": str(row[0]),
            "subject_id": row[1],
            "fraud_type": row[2],
            "score": row[3],
            "risk": row[4],
            "status": "SUCCESS" if row[5] == "ALLOW" else "FAILED",
            "policy_action": row[5],
            "triggered_rules": row[6],
            "features": row[7],
            "source": row[8],
            "config_version": row[9],
            "created_at": row[10].isoformat() if row[10] else None,
        }
    else:
        # ?? PAD EVERYTHING
        decision_block = {
            "id": "NOT_AVAILABLE",
            "subject_id": "NOT_AVAILABLE",
            "fraud_type": "NOT_AVAILABLE",
            "score": "NOT_AVAILABLE",
            "risk": "NOT_AVAILABLE",
            "status": "NOT_AVAILABLE",
            "policy_action": "NOT_AVAILABLE",
            "triggered_rules": "NOT_AVAILABLE",
            "features": "NOT_AVAILABLE",
            "source": "NOT_AVAILABLE",
            "config_version": "NOT_AVAILABLE",
            "created_at": "NOT_AVAILABLE",
        }

    return {
        "decision": decision_block,
        "event": {
            "action": row[11],
            "event_time": row[12].isoformat() if row[12] else None,
            "security_payload": row[13],
            "biometric_payload": row[14],
            "document_payload": row[15],
            "consent_payload": row[16],
            "wallet_payload": row[17],
        },
    }
