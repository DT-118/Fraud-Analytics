"""
API-key authentication dependency for protected FastAPI routes.

The scoring API uses FRAUD_API_KEY. Administrative routes use their own
FRAUD_ADMIN_KEY in admin_api.py and must not reuse the scoring key.
    - The API key is read when the application process starts.
    - A missing key is a startup/configuration error, not a per-request error.
    - Supplied keys are compared with secrets.compare_digest().
    - Missing or invalid request keys return HTTP 401.
"""

from __future__ import annotations
import os
import secrets
from fastapi import Header, HTTPException, status


_API_KEY = os.environ.get("FRAUD_API_KEY")

# Fail fast during application startup. Running a protected API without an
# authentication secret is a deployment/configuration error.
if not _API_KEY:
    raise RuntimeError(
        "FRAUD_API_KEY environment variable is required for the fraud API."
    )


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """
    Validate the scoring API key supplied in the X-API-Key header.

    Raises:
        HTTPException: 401 when the header is missing, empty, or invalid.
    """
    if not x_api_key or not x_api_key.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    if not secrets.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )