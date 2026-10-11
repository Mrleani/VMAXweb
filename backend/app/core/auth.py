"""Supabase JWT authentication.

The frontend obtains an access token from Supabase Auth and sends it as
``Authorization: Bearer <token>``. Tokens are verified with the project's
JWT secret (HS256). When ``auth_required`` is false the engine falls back to
a synthetic development user so the API is usable locally.
"""

from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Header, HTTPException, status

from app.core.config import get_settings
from app.db.account_store import account_store

_DEV_USER_ID = "00000000-0000-0000-0000-000000000000"


@dataclass(slots=True)
class CurrentUser:
    id: str
    email: str | None = None
    is_anonymous: bool = False


DEV_USER = CurrentUser(id=_DEV_USER_ID, email="dev@vmaxweb.local", is_anonymous=True)


async def get_current_user(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> CurrentUser:
    settings = get_settings()

    # API keys (Pro) take precedence when supplied.
    candidate_key = x_api_key
    if candidate_key is None and authorization and authorization.lower().startswith("bearer "):
        maybe = authorization.split(" ", 1)[1].strip()
        if maybe.startswith("vmax_"):
            candidate_key = maybe

    if candidate_key:
        user_id = account_store.resolve_api_key(candidate_key)
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return CurrentUser(id=user_id, email=None)

    if not authorization or not authorization.lower().startswith("bearer "):
        if settings.auth_required:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return DEV_USER

    token = authorization.split(" ", 1)[1].strip()

    if not settings.supabase_jwt_secret:
        if settings.auth_required:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication is not configured",
            )
        return DEV_USER

    try:
        payload = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
        )

    return CurrentUser(id=subject, email=payload.get("email"))
