"""
api.py

HTTP API layer for Fraud Engine.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.responses import error_response, success_response
from service.fraud_service import handle_fraud_event
from storage.db import get_db_connection


from dashboard_api import router as fraud_router



app = FastAPI()

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# ) "http://84.46.255.66:3000",

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # only your frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(fraud_router)


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

    except Exception as err:
        db_connection.rollback()
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: API failure")
        raise HTTPException(status_code=500) from err

    finally:
        db_connection.close()
