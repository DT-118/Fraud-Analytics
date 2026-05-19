from fastapi import APIRouter
from storage.db import get_db_connection
from storage.dashboard_repo import (
    fetch_kpis,
    fetch_transactions,
    fetch_transaction_detail,
    fraud_type_stats,
    risk_classification_stats,
    source_volume_stats,
    risk_trend_over_time,   
)

router = APIRouter(prefix="/fraud", tags=["Fraud Dashboard"])


@router.get("/kpis")
def get_kpis():
    db = get_db_connection()
    return fetch_kpis(db)


@router.get("/transactions")
def get_transactions(page: int = 1,limit: int = 5):
    db = get_db_connection()
    try:
        data = fetch_transactions(db, page, limit)
        return data
    finally:
        db.close()


@router.get("/transactions/{tx_id}")
def get_transaction(tx_id: str):
    db = get_db_connection()
    return fetch_transaction_detail(db, tx_id)


@router.get("/charts/risk-trend")   
def risk_trend():
    db = get_db_connection()
    return risk_trend_over_time(db)


@router.get("/charts/fraud-type")
def fraud_type():
    db = get_db_connection()
    return fraud_type_stats(db)


@router.get("/charts/risk-classification")
def risk_classification():
    db = get_db_connection()
    return risk_classification_stats(db)


@router.get("/charts/source-volume")
def source_volume():
    db = get_db_connection()
    return source_volume_stats(db)
