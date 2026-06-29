from __future__ import annotations

from typing import Annotated, Any, cast

import httpx
import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..database import get_db
from ..deps import current_user, ui_user
from ..integration import local_ad_login_configured, microsoft_login_configured
from ..models import IntegrationSettings, User
from ..security import random_token, utc_now, verify_secret
from ..security.rate_limit import apply_rate_limit
from ..security.secrets import decrypt_secret
from ..services.auth_service import (
    create_user_session,
    session_from_request,
    set_session_cookie,
    upsert_external_user,
)
from ..services.common import clean_optional
from ..services.local_ad_auth import authenticate_local_ad_user
from ..services.microsoft_auth import (
    exchange_microsoft_authorization_code,
    microsoft_access_scope,
    microsoft_authority_url,
    microsoft_login_authorize_url,
    microsoft_pkce_verifier,
    microsoft_role_from_groups,
    microsoft_user_identity,
    validate_microsoft_access_token,
)
from ..web import render_template, settings

router = APIRouter()


def render_login_template(
    db: Session, request: Request, *, error: str | None = None, status_code: int = 200
):
    integration_settings = db.get(IntegrationSettings, 1)
    return render_template(
        db,
        "login.html",
        {
            "request": request,
            "error": error,
            "microsoft_login_enabled": microsoft_login_configured(integration_settings),
            "local_ad_login_enabled": local_ad_login_configured(integration_settings),
            "microsoft_client_id": integration_settings.microsoft_client_id
            if integration_settings
            else None,
            "microsoft_authority_url": microsoft_authority_url(integration_settings),
            "microsoft_access_scope": microsoft_access_scope(integration_settings),
        },
        status_code=status_code,
    )


@router.get("/", response_class=HTMLResponse)
def index(request: Request, db: Annotated[Session, Depends(get_db)]):
    user = ui_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Annotated[Session, Depends(get_db)]):
    return render_login_template(db, request)


@router.post("/api/v1/auth/login")
def login(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    email: str = Form(...),
    password: str = Form(...),
):
    normalized_email = email.lower().strip()
    apply_rate_limit(
        request,
        "login",
        normalized_email,
        settings.rate_limit_login_attempts,
        settings.rate_limit_login_window_seconds,
    )
    user = db.scalar(select(User).where(User.email == normalized_email))
    if not user or not verify_secret(password, user.password_hash):
        return render_login_template(
            db, request, error="Invalid email or password", status_code=401
        )
    token = create_user_session(db, user)
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, token)
    write_audit(db, request, "auth.login", user=user)
    db.commit()
    return response


@router.get("/auth/microsoft/start")
def microsoft_login_start(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    login_hint: str | None = None,
):
    integration_settings = db.get(IntegrationSettings, 1)
    if not microsoft_login_configured(integration_settings):
        raise HTTPException(
            status_code=501, detail="Microsoft sign-in is not configured"
        )
    assert integration_settings is not None
    state = clean_optional(login_hint) or "start"
    apply_rate_limit(
        request,
        "microsoft-login-start",
        state,
        settings.rate_limit_microsoft_login_attempts,
        settings.rate_limit_microsoft_login_window_seconds,
    )
    state = random_token(32)
    verifier = microsoft_pkce_verifier()
    response = RedirectResponse(
        microsoft_login_authorize_url(
            integration_settings, request, state, verifier, login_hint=login_hint
        ),
        status_code=303,
    )
    response.set_cookie(
        "opnhub_ms_state",
        state,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        max_age=600,
    )
    response.set_cookie(
        "opnhub_ms_verifier",
        verifier,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        max_age=600,
    )
    return response


@router.get("/auth/microsoft/callback", name="microsoft_callback")
def microsoft_callback(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    apply_rate_limit(
        request,
        "microsoft-callback",
        "callback",
        settings.rate_limit_microsoft_login_attempts,
        settings.rate_limit_microsoft_login_window_seconds,
    )
    integration_settings = db.get(IntegrationSettings, 1)
    if not microsoft_login_configured(integration_settings):
        raise HTTPException(
            status_code=501, detail="Microsoft sign-in is not configured"
        )
    assert integration_settings is not None
    if error:
        message = (
            clean_optional(error_description)
            or clean_optional(error)
            or "Microsoft sign-in failed"
        )
        return render_login_template(db, request, error=message, status_code=401)
    expected_state = request.cookies.get("opnhub_ms_state")
    verifier = request.cookies.get("opnhub_ms_verifier")
    if (
        not code
        or not state
        or not expected_state
        or state != expected_state
        or not verifier
    ):
        response = render_login_template(
            db,
            request,
            error="Microsoft sign-in session is invalid or has expired. Please try again.",
            status_code=401,
        )
        response.delete_cookie("opnhub_ms_state")
        response.delete_cookie("opnhub_ms_verifier")
        return response
    try:
        token_payload = exchange_microsoft_authorization_code(
            integration_settings,
            request,
            code,
            verifier,
            decrypt_secret(integration_settings.microsoft_client_secret),
        )
        access_token = clean_optional(
            cast(str | None, token_payload.get("access_token"))
        )
        if not access_token:
            raise RuntimeError("Microsoft sign-in did not return an access token")
        claims = validate_microsoft_access_token(integration_settings, access_token)
    except (RuntimeError, httpx.HTTPError, jwt.PyJWTError) as exc:
        response = render_login_template(
            db, request, error=f"Microsoft sign-in failed: {exc}", status_code=401
        )
        response.delete_cookie("opnhub_ms_state")
        response.delete_cookie("opnhub_ms_verifier")
        return response
    email, first_name, last_name, groups = microsoft_user_identity(claims)
    existing = db.scalar(select(User).where(User.email == email.lower()))
    role, allowed = microsoft_role_from_groups(
        integration_settings, groups, existing.role if existing else None
    )
    if not allowed:
        response = render_login_template(
            db,
            request,
            error="Microsoft account is not mapped to an allowed Entra group",
            status_code=403,
        )
        response.delete_cookie("opnhub_ms_state")
        response.delete_cookie("opnhub_ms_verifier")
        return response
    user = upsert_external_user(
        db, email, first_name=first_name, last_name=last_name, role=role
    )
    session_token = create_user_session(db, user)
    write_audit(db, request, "auth.microsoft.login", user=user)
    db.commit()
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, session_token)
    response.delete_cookie("opnhub_ms_state")
    response.delete_cookie("opnhub_ms_verifier")
    return response


@router.post("/auth/microsoft")
def microsoft_login(
    request: Request, db: Annotated[Session, Depends(get_db)], token: str = Form(...)
):
    apply_rate_limit(
        request,
        "microsoft-login",
        "token",
        settings.rate_limit_microsoft_login_attempts,
        settings.rate_limit_microsoft_login_window_seconds,
    )
    integration_settings = db.get(IntegrationSettings, 1)
    if not microsoft_login_configured(integration_settings):
        raise HTTPException(
            status_code=501, detail="Microsoft sign-in is not configured"
        )
    assert integration_settings is not None
    claims = validate_microsoft_access_token(integration_settings, token)
    email, first_name, last_name, groups = microsoft_user_identity(claims)
    existing = db.scalar(select(User).where(User.email == email.lower()))
    role, allowed = microsoft_role_from_groups(
        integration_settings, groups, existing.role if existing else None
    )
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail="Microsoft account is not mapped to an allowed Entra group",
        )
    user = upsert_external_user(
        db, email, first_name=first_name, last_name=last_name, role=role
    )
    session_token = create_user_session(db, user)
    write_audit(db, request, "auth.microsoft.login", user=user)
    db.commit()
    response = JSONResponse({"ok": True, "redirect": "/dashboard"})
    set_session_cookie(response, session_token)
    return response


@router.post("/auth/local-ad")
def local_ad_login(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    email: str = Form(...),
    password: str = Form(...),
):
    normalized_email = email.lower().strip()
    apply_rate_limit(
        request,
        "local-ad-login",
        normalized_email,
        settings.rate_limit_local_ad_login_attempts,
        settings.rate_limit_local_ad_login_window_seconds,
    )
    integration_settings = db.get(IntegrationSettings, 1)
    if not local_ad_login_configured(integration_settings):
        raise HTTPException(
            status_code=501, detail="Local AD sign-in is not configured"
        )
    assert integration_settings is not None
    try:
        resolved_email, first_name, last_name = authenticate_local_ad_user(
            integration_settings, email, password
        )
    except RuntimeError as exc:
        return render_login_template(db, request, error=str(exc), status_code=401)
    existing = db.scalar(select(User).where(User.email == resolved_email.lower()))
    role = existing.role if existing else "user"
    user = upsert_external_user(
        db, resolved_email, first_name=first_name, last_name=last_name, role=role
    )
    session_token = create_user_session(db, user)
    write_audit(db, request, "auth.local_ad.login", user=user)
    db.commit()
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, session_token)
    return response


@router.post("/api/v1/auth/logout")
def logout(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    session = session_from_request(request, db)
    session.revoked_at = utc_now()
    write_audit(db, request, "auth.logout", user=user)
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie_name)
    return response


@router.get("/api/v1/auth/me")
def me(user: Annotated[User, Depends(current_user)]):
    return {"id": str(user.id), "email": user.email, "mfa_enabled": user.mfa_enabled}
