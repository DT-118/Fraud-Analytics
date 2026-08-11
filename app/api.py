"""
api.py

HTTP API layer for Fraud Engine.
"""

from dotenv import load_dotenv
load_dotenv()

import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.auth import require_api_key
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.rate_limiter import check_rate_limit, check_service_rate_limit
from core.responses import error_response, success_response
from service.fraud_service import handle_fraud_event
from service.ip_reputation import seed_ip_blocklist_from_db, seed_ip_blocklist_from_file
from storage.db import get_db_connection, release_db_connection
from storage.redis_client import redis_client

from admin_api import router as admin_router
from dashboard_api import router as fraud_router
from profile_api import router as profile_router
from portal_auth_api import router as auth_router

# _CONFIG_VERSION  = os.environ.get("CONFIG_VERSION", "rules_v2")
# _ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:5173","http://localhost:5174").split(",")

_CONFIG_VERSION = os.environ.get("CONFIG_VERSION", "rules_v2")

_ALLOWED_ORIGINS = os.environ.get(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:5174"
).split(",")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast if critical env vars are missing — better to crash on startup
    # than to serve 500s to every caller and confuse monitoring.
    if not os.environ.get("FRAUD_API_KEY"):
        raise RuntimeError("FRAUD_API_KEY env var is required — refusing to start")
    if not os.environ.get("FRAUD_ADMIN_KEY"):
        raise RuntimeError("FRAUD_ADMIN_KEY env var is required — refusing to start")
    if not os.environ.get("JWT_SECRET"):
        raise RuntimeError("JWT_SECRET env var is required — refusing to start")

    seed_ip_blocklist_from_file()
    db = get_db_connection()
    try:
        seed_ip_blocklist_from_db(db)
    finally:
        release_db_connection(db)

    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)
app.include_router(fraud_router)
app.include_router(profile_router)
app.include_router(auth_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/deep")
def health_deep():
    """
    Dependency health check — returns 503 if any critical dependency is unhealthy.
    Suitable for Kubernetes readiness probes and on-call dashboards.
    """
    issues: list[str] = []

    # Redis
    try:
        redis_client.ping()
    except Exception as exc:
        issues.append(f"redis: {exc}")

    # Database
    db = None
    try:
        db = get_db_connection()
        with db.cursor() as cur:
            cur.execute("SELECT 1")
    except Exception as exc:
        issues.append(f"database: {exc}")
    finally:
        if db:
            release_db_connection(db)

    if issues:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "issues": issues},
        )
    return {"status": "ok"}


@app.post(
    "/v2/score",
    dependencies=[Depends(require_api_key), Depends(check_rate_limit)],
)
def score_event(request_context: Context, request: Request):
    """
    HTTP endpoint to score a fraud-related event.
    """
    check_service_rate_limit(
        request.headers.get("X-API-Key", "anon"),
        request_context.action_taxonomy,
    )
    db_connection = get_db_connection()

    try:
        fraud_decision = handle_fraud_event(
            request_context,
            db_connection=db_connection,
            source="API",
            config_version=_CONFIG_VERSION,
        )

        db_connection.commit()
        return success_response(fraud_decision)

    except RuntimeError as exc:
        db_connection.rollback()

        # Guard against non-ErrorCode RuntimeErrors (e.g. from third-party code)
        try:
            error_code = ErrorCode(str(exc))
        except ValueError:
            logger.error("%s: Unexpected RuntimeError: %s", ErrorCode.INTERNAL_ERROR, exc)
            raise HTTPException(status_code=500) from exc

        logger.error(f"{error_code}: API request failed")
        return error_response(error_code)

    except Exception as err:
        db_connection.rollback()
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: API failure")
        raise HTTPException(status_code=500) from err

    finally:
        release_db_connection(db_connection)
