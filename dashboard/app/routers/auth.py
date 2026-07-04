from __future__ import annotations

from typing import Annotated, cast

import httpx
import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import log_security_warning, write_audit
from ..database import get_db
from ..deps import current_user, ui_user
from ..integration import local_ad_login_configured, microsoft_login_configured
from ..models import IntegrationSettings, User
from ..security import (
    generate_totp_secret,
    random_token,
    utc_now,
    verify_secret,
    verify_totp_code,
)
from ..security.rate_limit import apply_rate_limit
from ..security.secrets import decrypt_secret, encrypt_secret
from ..services.auth_service import (
    create_user_session,
    session_from_request,
    set_session_cookie,
    upsert_external_user,
)
from ..services.common import clean_optional
from ..services.local_ad_auth import authenticate_local_ad_user
from ..services.mfa_service import (
    clear_pending_mfa_cookie,
    local_user_supports_hub_mfa,
    pending_mfa_user_id_from_request,
    set_pending_mfa_cookie,
    totp_qr_code_data_url,
)
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
from ..services.notification_service import (
    maybe_notify_for_repeated_auth_failures,
    send_security_alert_email,
)
from ..web import render_template, settings

router = APIRouter()


def audit_failure(
    db: Session,
    request: Request,
    action: str,
    *,
    user: User | None = None,
    detail: str | None = None,
    notify: bool = False,
) -> None:
    write_audit(db, request, action, user=user)
    log_security_warning(action, detail=detail)
    if notify:
        send_security_alert_email(
            db,
            f"[OPNsense Hub] Security event: {action}",
            detail or action,
        )
    else:
        maybe_notify_for_repeated_auth_failures(db, action, detail, utc_now())
    db.commit()


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


def render_mfa_login_template(
    db: Session,
    request: Request,
    pending_user: User,
    *,
    error: str | None = None,
    status_code: int = 200,
):
    return render_template(
        db,
        "login_mfa.html",
        {"request": request, "error": error, "pending_user": pending_user},
        status_code=status_code,
    )


def pending_mfa_user(db: Session, request: Request) -> User:
    pending_user_id = pending_mfa_user_id_from_request(request)
    user = db.get(User, pending_user_id)
    if not user or not local_user_supports_hub_mfa(user) or not user.mfa_enabled:
        raise HTTPException(status_code=401, detail="invalid MFA sign-in state")
    return user


def render_account_security_template(
    db: Session,
    request: Request,
    user: User,
    *,
    status_code: int = 200,
    error: str | None = None,
    setup_secret: str | None = None,
):
    effective_setup_secret = setup_secret
    if effective_setup_secret is None and not user.mfa_enabled:
        effective_setup_secret = decrypt_secret(user.mfa_secret)
    return render_template(
        db,
        "account_security.html",
        {
            "request": request,
            "user": user,
            "active_page": "account-security",
            "status": request.query_params.get("status"),
            "error": error,
            "local_mfa_available": local_user_supports_hub_mfa(user),
            "setup_secret": effective_setup_secret,
            "qr_code_data_url": totp_qr_code_data_url(
                effective_setup_secret, user.email
            )
            if effective_setup_secret
            else None,
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


@router.get("/auth/mfa", response_class=HTMLResponse)
def mfa_login_page(request: Request, db: Annotated[Session, Depends(get_db)]):
    try:
        user = pending_mfa_user(db, request)
    except HTTPException:
        response = render_login_template(
            db,
            request,
            error="Your MFA sign-in session is invalid or has expired. Please sign in again.",
            status_code=401,
        )
        clear_pending_mfa_cookie(response)
        return response
    return render_mfa_login_template(db, request, user)


@router.post("/auth/mfa")
def complete_mfa_login(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    code: str = Form(...),
):
    try:
        user = pending_mfa_user(db, request)
    except HTTPException:
        response = render_login_template(
            db,
            request,
            error="Your MFA sign-in session is invalid or has expired. Please sign in again.",
            status_code=401,
        )
        clear_pending_mfa_cookie(response)
        return response
    try:
        apply_rate_limit(
            request,
            "mfa-login",
            str(user.id),
            settings.rate_limit_mfa_attempts,
            settings.rate_limit_mfa_window_seconds,
        )
    except HTTPException as exc:
        audit_failure(
            db,
            request,
            "auth.mfa.rate_limited",
            user=user,
            detail="too many MFA attempts",
            notify=True,
        )
        raise exc
    secret = decrypt_secret(user.mfa_secret)
    if not secret or not verify_totp_code(secret, code):
        audit_failure(
            db,
            request,
            "auth.mfa.failed",
            user=user,
            detail="invalid authenticator code",
        )
        return render_mfa_login_template(
            db,
            request,
            user,
            error="Invalid authenticator code",
            status_code=401,
        )
    token = create_user_session(db, user)
    write_audit(db, request, "auth.login", user=user)
    db.commit()
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, token)
    clear_pending_mfa_cookie(response)
    return response


@router.get("/account/security", response_class=HTMLResponse)
def account_security_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    return render_account_security_template(db, request, user)


@router.post("/account/security/mfa/begin")
def begin_account_mfa_setup(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    if not local_user_supports_hub_mfa(user):
        raise HTTPException(
            status_code=400,
            detail="externally managed users must configure MFA with their identity provider",
        )
    if user.mfa_enabled:
        return RedirectResponse("/account/security", status_code=303)
    return render_account_security_template(
        db, request, user, setup_secret=generate_totp_secret()
    )


@router.post("/account/security/mfa/enable")
def enable_account_mfa(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    secret: str = Form(...),
    code: str = Form(...),
):
    if not local_user_supports_hub_mfa(user):
        raise HTTPException(
            status_code=400,
            detail="externally managed users must configure MFA with their identity provider",
        )
    if user.mfa_enabled:
        return RedirectResponse("/account/security", status_code=303)
    normalized_secret = clean_optional(secret)
    if not normalized_secret or not verify_totp_code(normalized_secret, code):
        return render_account_security_template(
            db,
            request,
            user,
            status_code=400,
            error="Invalid authenticator code",
            setup_secret=normalized_secret,
        )
    user.mfa_secret = encrypt_secret(normalized_secret)
    user.mfa_enabled = True
    write_audit(db, request, "auth.mfa.enable", user=user)
    db.commit()
    return RedirectResponse("/account/security?status=mfa-enabled", status_code=303)


@router.post("/account/security/mfa/disable")
def disable_account_mfa(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    password: str = Form(...),
    code: str = Form(...),
):
    if not local_user_supports_hub_mfa(user):
        raise HTTPException(
            status_code=400,
            detail="externally managed users must configure MFA with their identity provider",
        )
    secret = decrypt_secret(user.mfa_secret)
    if (
        not user.mfa_enabled
        or not secret
        or not verify_secret(password, user.password_hash)
        or not verify_totp_code(secret, code)
    ):
        return render_account_security_template(
            db,
            request,
            user,
            status_code=400,
            error="Password or authenticator code was invalid",
        )
    user.mfa_secret = None
    user.mfa_enabled = False
    write_audit(db, request, "auth.mfa.disable", user=user)
    db.commit()
    return RedirectResponse("/account/security?status=mfa-disabled", status_code=303)


@router.post("/api/v1/auth/login")
def login(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    email: str = Form(...),
    password: str = Form(...),
):
    normalized_email = email.lower().strip()
    try:
        apply_rate_limit(
            request,
            "login",
            normalized_email,
            settings.rate_limit_login_attempts,
            settings.rate_limit_login_window_seconds,
        )
    except HTTPException as exc:
        audit_failure(
            db,
            request,
            "auth.login.rate_limited",
            detail=f"too many login attempts for {normalized_email}",
            notify=True,
        )
        raise exc
    user = db.scalar(select(User).where(User.email == normalized_email))
    if not user or not verify_secret(password, user.password_hash):
        audit_failure(
            db,
            request,
            "auth.login.failed",
            user=user,
            detail=f"invalid password for {normalized_email}",
        )
        return render_login_template(
            db, request, error="Invalid email or password", status_code=401
        )
    if user.mfa_enabled:
        if not local_user_supports_hub_mfa(user):
            return render_login_template(
                db,
                request,
                error="This account uses MFA through its external identity provider.",
                status_code=400,
            )
        if not decrypt_secret(user.mfa_secret):
            return render_login_template(
                db,
                request,
                error="MFA is enabled for this account but is not configured correctly.",
                status_code=401,
            )
        response = RedirectResponse("/auth/mfa", status_code=303)
        set_pending_mfa_cookie(response, user)
        return response
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
    try:
        apply_rate_limit(
            request,
            "microsoft-login-start",
            state,
            settings.rate_limit_microsoft_login_attempts,
            settings.rate_limit_microsoft_login_window_seconds,
        )
    except HTTPException as exc:
        audit_failure(
            db,
            request,
            "auth.microsoft.rate_limited",
            detail="too many Microsoft login start attempts",
            notify=True,
        )
        raise exc
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
    try:
        apply_rate_limit(
            request,
            "microsoft-callback",
            "callback",
            settings.rate_limit_microsoft_login_attempts,
            settings.rate_limit_microsoft_login_window_seconds,
        )
    except HTTPException as exc:
        audit_failure(
            db,
            request,
            "auth.microsoft.rate_limited",
            detail="too many Microsoft callback attempts",
            notify=True,
        )
        raise exc
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
        audit_failure(
            db,
            request,
            "auth.microsoft.failed",
            detail=message,
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
        audit_failure(
            db,
            request,
            "auth.microsoft.failed",
            detail="invalid or expired Microsoft sign-in state",
        )
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
        audit_failure(
            db,
            request,
            "auth.microsoft.failed",
            detail=f"Microsoft sign-in failed: {exc.__class__.__name__}",
            notify=True,
        )
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
        audit_failure(
            db,
            request,
            "auth.microsoft.failed",
            detail="Microsoft account is not mapped to an allowed Entra group",
        )
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
        db,
        email,
        first_name=first_name,
        last_name=last_name,
        role=role,
        auth_provider="microsoft",
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
    try:
        apply_rate_limit(
            request,
            "microsoft-login",
            "token",
            settings.rate_limit_microsoft_login_attempts,
            settings.rate_limit_microsoft_login_window_seconds,
        )
    except HTTPException as exc:
        audit_failure(
            db,
            request,
            "auth.microsoft.rate_limited",
            detail="too many Microsoft token login attempts",
            notify=True,
        )
        raise exc
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
        audit_failure(
            db,
            request,
            "auth.microsoft.failed",
            detail="Microsoft account is not mapped to an allowed Entra group",
        )
        raise HTTPException(
            status_code=403,
            detail="Microsoft account is not mapped to an allowed Entra group",
        )
    user = upsert_external_user(
        db,
        email,
        first_name=first_name,
        last_name=last_name,
        role=role,
        auth_provider="microsoft",
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
    try:
        apply_rate_limit(
            request,
            "local-ad-login",
            normalized_email,
            settings.rate_limit_local_ad_login_attempts,
            settings.rate_limit_local_ad_login_window_seconds,
        )
    except HTTPException as exc:
        audit_failure(
            db,
            request,
            "auth.local_ad.rate_limited",
            detail=f"too many Local AD login attempts for {normalized_email}",
            notify=True,
        )
        raise exc
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
        audit_failure(
            db,
            request,
            "auth.local_ad.failed",
            detail=f"Local AD authentication failed for {normalized_email}: {exc}",
        )
        return render_login_template(db, request, error=str(exc), status_code=401)
    existing = db.scalar(select(User).where(User.email == resolved_email.lower()))
    role = existing.role if existing else "user"
    user = upsert_external_user(
        db,
        resolved_email,
        first_name=first_name,
        last_name=last_name,
        role=role,
        auth_provider="local_ad",
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
    clear_pending_mfa_cookie(response)
    return response


@router.get("/api/v1/auth/me")
def me(user: Annotated[User, Depends(current_user)]):
    return {"id": str(user.id), "email": user.email, "mfa_enabled": user.mfa_enabled}
