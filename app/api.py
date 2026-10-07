"""
api.py

HTTP API layer for Fraud Engine.
"""

from dotenv import load_dotenv
load_dotenv()

import os
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request
from fastapi.exception_handlers import (
    http_exception_handler as default_http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
import time
from core.idempotency import release_idempotency
from core.auth import require_api_key
from core.context import Context
from core.errors import ErrorCode
from core.logger import logger
from core.rate_limiter import check_rate_limit, check_service_rate_limit
from core.responses import error_response, success_response
from service.fraud_service import handle_fraud_event, shutdown_async_executor, run_post_commit_tasks
from service.ip_reputation import seed_ip_blocklist_from_db
from storage.db import get_db_connection, release_db_connection, close_pool
from storage.redis_client import redis_client


from admin_api import router as admin_router
from dashboard_api import router as fraud_router
from profile_api import router as profile_router
from portal_auth_api import router as auth_router
from action_storing_api import router as action_router


_raw_cors = os.environ.get("CORS_ALLOWED_ORIGINS", "")
_ALLOWED_ORIGINS = [o.strip() for o in _raw_cors.split(",") if o.strip()]
_CONFIG_VERSION = os.environ.get("CONFIG_VERSION", "rules_v2")

# Routes under these prefixes return the {success, message, result} envelope
# for every error. /auth/* is left out on purpose: the login frontend likely
# reads FastAPI's default {"detail": ...}. Add "/auth/" here if it can handle
# the envelope.
_ENVELOPE_PREFIXES = ("/fraud-analytics-backend/", "/fraud/", "/v2/")

# HTTP statuses that keep their own status and get their own error code.
_HTTP_TO_ERROR_CODE = {
    401: ErrorCode.UNAUTHORIZED,
    404: ErrorCode.NOT_FOUND,
    429: ErrorCode.RATE_LIMITED,
}

# HTTP status for handled RuntimeErrors raised inside /score.
_ERROR_HTTP_STATUS = {
    ErrorCode.INVALID_REQUEST:   400,
    ErrorCode.INTERNAL_ERROR:    500,
    ErrorCode.RULE_ENGINE_ERROR: 500,
    ErrorCode.DATABASE_ERROR:    503,
    ErrorCode.REDIS_ERROR:       503,
    ErrorCode.KAFKA_ERROR:       503,
}


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
    if not _ALLOWED_ORIGINS:
        raise RuntimeError("CORS_ALLOWED_ORIGINS env var is required — refusing to start")

    db = get_db_connection()
    try:
        seed_ip_blocklist_from_db(db)
    finally:
        release_db_connection(db)

    yield

    shutdown_async_executor()
    close_pool()

app = FastAPI(lifespan=lifespan)


# ---------------------------------------------------------------------------
# Exception handlers — one error envelope for every route under
# _ENVELOPE_PREFIXES, with an HTTP status that matches the FE code.
# ---------------------------------------------------------------------------

def _uses_envelope(path: str) -> bool:
    return path.startswith(_ENVELOPE_PREFIXES)

def _error_entry(e: dict) -> dict:
    if e.get("type") == "json_invalid":
        return {"field": "body", "message": "Request body is not valid JSON"}
    return {
        "field": ".".join(str(p) for p in e["loc"] if p != "body") or "body",
        "message": e["msg"],
    }

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    if not _uses_envelope(request.url.path):
        return await request_validation_exception_handler(request, exc)

    errors = [_error_entry(e) for e in exc.errors()]
    logger.warning(
        "%s: %s %s rejected: %s",
        ErrorCode.INVALID_REQUEST.value, request.method, request.url.path, errors,
    )
    return JSONResponse(
        status_code=400,
        content=error_response(ErrorCode.INVALID_REQUEST, {"errors": errors}),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if not _uses_envelope(request.url.path):
        return await default_http_exception_handler(request, exc)

    if exc.status_code in _HTTP_TO_ERROR_CODE:
        status_code, code = exc.status_code, _HTTP_TO_ERROR_CODE[exc.status_code]
    elif exc.status_code >= 500:
        status_code, code = exc.status_code, ErrorCode.INTERNAL_ERROR
    else:
        # Any other 4xx (400, 405, 409, 422, ...) is reported as FE-400 with
        # HTTP 400 so the status and the code always agree.
        status_code, code = 400, ErrorCode.INVALID_REQUEST

    # Never expose detail text for 5xx; it can contain internal error strings.
    detail = exc.detail if (isinstance(exc.detail, str) and exc.status_code < 500) else None

    # Starlette's built-in route errors have no useful detail. Say what was called.
    if exc.status_code == 404 and detail == "Not Found":
        detail = (
            f"No route matches {request.method} {request.url.path}. "
            "Check the URL path and HTTP method."
        )
    elif exc.status_code == 405:
        detail = f"{request.method} is not allowed on {request.url.path}."
    errors = [{"field": None, "message": detail}] if detail else None
    return JSONResponse(
        status_code=status_code,
        headers=exc.headers,   # keeps Retry-After on 429
        content=error_response(code, {"errors": errors} if errors else None),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("%s: unhandled error on %s", ErrorCode.INTERNAL_ERROR.value, request.url.path)
    if _uses_envelope(request.url.path):
        return JSONResponse(status_code=500, content=error_response(ErrorCode.INTERNAL_ERROR))
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=_ALLOWED_ORIGINS,
#     allow_credentials=True,
#     allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
#     allow_headers=["X-API-Key", "Authorization", "Content-Type"],
# )

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
app.include_router(action_router)

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
    "/fraud-analytics-backend/v2/score",
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
    post_commit_tasks: list = []
    fraud_decision = None

    def _release_claim():
        # handle_fraud_event releases on its own failures; this covers a failed COMMIT.
        if fraud_decision is not None and not fraud_decision.get("duplicate"):
            release_idempotency(request_context.event_id)

    try:
        start_time = time.perf_counter()
        fraud_decision = handle_fraud_event(
            request_context,
            db_connection=db_connection,
            source="API",
            config_version=_CONFIG_VERSION,
            post_commit_tasks=post_commit_tasks,
        )

        # Duplicate: either caught by Redis (minimal body) or found already
        # stored in the DB after the Redis key expired (full stored decision).
        if fraud_decision.get("duplicate"):
            db_connection.rollback()
            return JSONResponse(
                status_code=409,
                content=error_response(ErrorCode.DUPLICATE_EVENT, fraud_decision),
            )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        fraud_decision["processing_time_ms"] = elapsed_ms

        db_connection.commit()
        run_post_commit_tasks(post_commit_tasks)   # only after a successful commit
        return success_response(fraud_decision)

    except RuntimeError as exc:
        db_connection.rollback()
        _release_claim()
        try:
            error_code = ErrorCode(exc.args[0] if exc.args else "")
        except ValueError:
            logger.error("%s: Unexpected RuntimeError: %s", ErrorCode.INTERNAL_ERROR, exc)
            return JSONResponse(
                status_code=500,
                content=error_response(ErrorCode.INTERNAL_ERROR),
            )
        logger.error(f"{error_code}: API request failed")
        return JSONResponse(
            status_code=_ERROR_HTTP_STATUS.get(error_code, 500),
            content=error_response(error_code),
        )

    except Exception:
        db_connection.rollback()
        _release_claim()
        logger.exception(f"{ErrorCode.INTERNAL_ERROR}: API failure")
        return JSONResponse(
            status_code=500,
            content=error_response(ErrorCode.INTERNAL_ERROR),
        )

    finally:
        release_db_connection(db_connection)