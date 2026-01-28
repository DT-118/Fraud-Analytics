"""
api.py

HTTP API layer for Fraud Engine.
"""

from fastapi import FastAPI, HTTPException
from core.context import Context
from storage.db import get_db_connection
from services.fraud_service import handle_fraud_event
from core.responses import success_response, error_response
from core.errors import ErrorCode
from core.logger import logger

app = FastAPI()


@app.post("/v1/score")
def score_event(request_context: Context):
    """
    HTTP endpoint to score a fraud-related event.
    """
    db_connection = get_db_connection()

    try:
        fraud_decision = handle_fraud_event(
            request_context,
            db_connection=db_connection,
            source="API",
            config_version="rules_v1",
        )

        db_connection.commit()
        return success_response(fraud_decision)

    except RuntimeError as exc:
        db_connection.rollback()

        error_code = ErrorCode(str(exc))
        logger.error(f"{error_code}: API request failed")

        return error_response(error_code)

    except Exception:
        db_connection.rollback()
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: API failure")
        raise HTTPException(status_code=500)

    finally:
        db_connection.close()
