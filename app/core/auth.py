"""
API key authentication dependency for FastAPI routes.

Reads FRAUD_API_KEY from environment.  All protected routes must depend on
require_api_key.  If the env var is unset the engine refuses to start.
"""

from dotenv import load_dotenv

load_dotenv()
import os

from fastapi import Header, HTTPException, status

_API_KEY = os.environ.get("FRAUD_API_KEY", "")


def require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    if not _API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="FRAUD_API_KEY env var is not configured",
        )
    if x_api_key != _API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
