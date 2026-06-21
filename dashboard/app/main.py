import uuid
from datetime import timedelta
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session, selectinload

from .audit import write_audit
from .config import get_settings
from .database import Base, SessionLocal, engine, get_db
from .models import (
    Company,
    CompanyUser,
    Device,
    DeviceEvent,
    EnrollmentCode,
    IntegrationSettings,
    User,
)
from .rbac import has_company_role
from .security import hash_secret, random_otp, random_token, utc_now, verify_secret
from .wireguard import (
    WireGuardError,
    add_peer,
    bootstrap_wireguard,
    client_allowed_ips,
    get_server_public_key,
    next_tunnel_ip,
    remove_peer,
)

settings = get_settings()
app = FastAPI(title=settings.app_name)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def ensure_schema_compat() -> None:
    with engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name text NULL")
        )
        conn.execute(
            text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name text NULL")
        )
        conn.execute(
            text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user'"
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS integration_settings (
                  id integer PRIMARY KEY DEFAULT 1,
                  smtp_enabled boolean NOT NULL DEFAULT false,
                  smtp_host text NULL,
                  smtp_port integer NULL,
                  smtp_username text NULL,
                  smtp_password text NULL,
                  smtp_from text NULL,
                  graph_enabled boolean NOT NULL DEFAULT false,
                  graph_tenant_id text NULL,
                  graph_client_id text NULL,
                  graph_client_secret text NULL,
                  graph_sender text NULL,
                  microsoft_enabled boolean NOT NULL DEFAULT false,
                  microsoft_tenant_id text NULL,
                  microsoft_client_id text NULL,
                  microsoft_audience text NULL,
                  microsoft_authority text NULL,
                  microsoft_admin_group text NULL,
                  microsoft_user_group text NULL,
                  ad_enabled boolean NOT NULL DEFAULT false,
                  ad_host text NULL,
                  ad_base_dn text NULL,
                  ad_bind_dn text NULL,
                  branding_logo_url text NULL,
                  updated_at timestamptz NOT NULL DEFAULT now()
                )
                """
            )
        )


def bootstrap() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schema_compat()
    with SessionLocal() as db:
        admin = db.scalar(
            select(User).where(User.email == settings.initial_admin_email.lower())
        )
        if not admin:
            db.add(
                User(
                    email=settings.initial_admin_email.lower(),
                    password_hash=hash_secret(settings.initial_admin_password),
                    role="administrator",
                )
            )
            db.commit()
        elif admin.role != "administrator":
            admin.role = "administrator"
            db.commit()
        bootstrap_wireguard(db)


@app.on_event("startup")
def on_startup() -> None:
    bootstrap()


def current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    user_id = request.cookies.get(settings.session_cookie_name)
    if not user_id:
        raise HTTPException(status_code=401)
    try:
        parsed = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=401) from None
    user = db.get(User, parsed)
    if not user:
        raise HTTPException(status_code=401)
    return user


def ui_user(request: Request, db: Session) -> User | None:
    try:
        return current_user(request, db)
    except HTTPException:
        return None


def require_company(
    db: Session, user: User, company_id: uuid.UUID, minimum: str = "viewer"
) -> Company:
    company = db.get(Company, company_id)
    if not company or not has_company_role(db, user, company_id, minimum):
        raise HTTPException(status_code=404, detail="company not found")
    return company


def require_admin(user: User) -> None:
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="administrator access required")


def get_or_create_integration_settings(db: Session) -> IntegrationSettings:
    integration_settings = db.get(IntegrationSettings, 1)
    if not integration_settings:
        integration_settings = IntegrationSettings(id=1)
        db.add(integration_settings)
        db.commit()
        db.refresh(integration_settings)
    return integration_settings


def clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Annotated[Session, Depends(get_db)]):
    user = ui_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/companies", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/api/v1/auth/login")
def login(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    email: str = Form(...),
    password: str = Form(...),
):
    user = db.scalar(select(User).where(User.email == email.lower().strip()))
    if not user or not verify_secret(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password"},
            status_code=401,
        )
    response = RedirectResponse("/companies", status_code=303)
    response.set_cookie(
        settings.session_cookie_name,
        str(user.id),
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
    )
    write_audit(db, request, "auth.login", user=user)
    db.commit()
    return response


@app.post("/api/v1/auth/logout")
def logout(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    write_audit(db, request, "auth.logout", user=user)
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie_name)
    return response


@app.get("/api/v1/auth/me")
def me(user: Annotated[User, Depends(current_user)]):
    return {"id": str(user.id), "email": user.email, "mfa_enabled": user.mfa_enabled}


@app.get("/companies", response_class=HTMLResponse)
def companies_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    companies = db.scalars(
        select(Company)
        .options(selectinload(Company.devices))
        .join(CompanyUser)
        .where(CompanyUser.user_id == user.id)
        .order_by(Company.name)
    ).all()
    return templates.TemplateResponse(
        "companies.html",
        {
            "request": request,
            "user": user,
            "companies": companies,
            "active_page": "companies",
        },
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_redirect(user: Annotated[User, Depends(current_user)]):
    require_admin(user)
    return RedirectResponse("/settings/manage-companies", status_code=303)


@app.get("/settings/{section}", response_class=HTMLResponse)
def settings_page(
    request: Request,
    section: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    allowed_sections = {
        "manage-companies",
        "manage-users",
        "email-settings",
        "microsoft-365",
        "local-ad",
        "branding",
    }
    if section not in allowed_sections:
        raise HTTPException(status_code=404)
    companies = db.scalars(select(Company).order_by(Company.name)).all()
    users = db.scalars(select(User).order_by(User.email)).all()
    integration_settings = get_or_create_integration_settings(db)
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "companies": companies,
            "users": users,
            "settings": integration_settings,
            "protected_admin_email": settings.initial_admin_email.lower(),
            "active_page": "settings",
            "active_settings": section,
            "status": request.query_params.get("status"),
        },
    )


@app.post("/settings/users")
def create_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    email: str = Form(...),
    password: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    role: str = Form("user"),
):
    require_admin(user)
    role = role if role in {"user", "administrator"} else "user"
    normalized_email = email.lower().strip()
    if not normalized_email or not password:
        raise HTTPException(status_code=400, detail="email and password are required")
    if db.scalar(select(User).where(User.email == normalized_email)):
        raise HTTPException(status_code=400, detail="email already exists")
    db.add(
        User(
            email=normalized_email,
            password_hash=hash_secret(password),
            first_name=clean_optional(first_name),
            last_name=clean_optional(last_name),
            role=role,
        )
    )
    write_audit(db, request, "settings.user.create", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/manage-users?status=user-created", status_code=303
    )


@app.post("/settings/users/{target_user_id}")
def update_user(
    request: Request,
    target_user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    email: str = Form(...),
    password: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    role: str = Form("user"),
):
    require_admin(user)
    target = db.get(User, target_user_id)
    if not target:
        raise HTTPException(status_code=404)
    role = role if role in {"user", "administrator"} else "user"
    normalized_email = email.lower().strip()
    duplicate = db.scalar(
        select(User).where(User.email == normalized_email, User.id != target.id)
    )
    if duplicate:
        raise HTTPException(status_code=400, detail="email already exists")
    target.email = normalized_email
    target.first_name = clean_optional(first_name)
    target.last_name = clean_optional(last_name)
    target.role = role
    if password.strip():
        target.password_hash = hash_secret(password)
    write_audit(db, request, "settings.user.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/manage-users?status=user-updated", status_code=303
    )


@app.post("/settings/users/{target_user_id}/delete")
def delete_user(
    request: Request,
    target_user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    if target_user_id == user.id:
        raise HTTPException(status_code=400, detail="you cannot delete your own user")
    target = db.get(User, target_user_id)
    if not target:
        raise HTTPException(status_code=404)
    if target.email == settings.initial_admin_email.lower():
        raise HTTPException(
            status_code=400, detail="the default administrator user cannot be deleted"
        )
    db.execute(delete(CompanyUser).where(CompanyUser.user_id == target.id))
    db.delete(target)
    write_audit(db, request, "settings.user.delete", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/manage-users?status=user-deleted", status_code=303
    )


@app.post("/settings/email")
def update_email_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    smtp_enabled: str | None = Form(None),
    smtp_host: str = Form(""),
    smtp_port: str = Form(""),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    graph_enabled: str | None = Form(None),
    graph_tenant_id: str = Form(""),
    graph_client_id: str = Form(""),
    graph_client_secret: str = Form(""),
    graph_sender: str = Form(""),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    use_smtp = smtp_enabled == "on"
    use_graph = graph_enabled == "on" and not use_smtp
    integration_settings.smtp_enabled = use_smtp
    integration_settings.graph_enabled = use_graph
    integration_settings.smtp_host = clean_optional(smtp_host)
    integration_settings.smtp_port = int(smtp_port) if smtp_port.strip() else None
    integration_settings.smtp_username = clean_optional(smtp_username)
    integration_settings.smtp_from = clean_optional(smtp_from)
    integration_settings.graph_tenant_id = clean_optional(graph_tenant_id)
    integration_settings.graph_client_id = clean_optional(graph_client_id)
    integration_settings.graph_sender = clean_optional(graph_sender)
    if smtp_password.strip():
        integration_settings.smtp_password = smtp_password
    if graph_client_secret.strip():
        integration_settings.graph_client_secret = graph_client_secret
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.email.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/email-settings?status=email-saved", status_code=303
    )


@app.post("/settings/microsoft")
def update_microsoft_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    microsoft_enabled: str | None = Form(None),
    microsoft_tenant_id: str = Form(""),
    microsoft_client_id: str = Form(""),
    microsoft_audience: str = Form(""),
    microsoft_authority: str = Form(""),
    microsoft_admin_group: str = Form(""),
    microsoft_user_group: str = Form(""),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.microsoft_enabled = microsoft_enabled == "on"
    integration_settings.microsoft_tenant_id = clean_optional(microsoft_tenant_id)
    integration_settings.microsoft_client_id = clean_optional(microsoft_client_id)
    integration_settings.microsoft_audience = clean_optional(microsoft_audience)
    integration_settings.microsoft_authority = clean_optional(microsoft_authority)
    integration_settings.microsoft_admin_group = clean_optional(microsoft_admin_group)
    integration_settings.microsoft_user_group = clean_optional(microsoft_user_group)
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.microsoft.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/microsoft-365?status=microsoft-saved", status_code=303
    )


@app.post("/settings/local-ad")
def update_local_ad_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    ad_enabled: str | None = Form(None),
    ad_host: str = Form(""),
    ad_base_dn: str = Form(""),
    ad_bind_dn: str = Form(""),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.ad_enabled = ad_enabled == "on"
    integration_settings.ad_host = clean_optional(ad_host)
    integration_settings.ad_base_dn = clean_optional(ad_base_dn)
    integration_settings.ad_bind_dn = clean_optional(ad_bind_dn)
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.local_ad.update", user=user)
    db.commit()
    return RedirectResponse("/settings/local-ad?status=local-ad-saved", status_code=303)


@app.post("/settings/branding")
def update_branding_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    branding_logo_url: str = Form(""),
    remove_logo: str | None = Form(None),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.branding_logo_url = (
        None if remove_logo == "on" else clean_optional(branding_logo_url)
    )
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.branding.update", user=user)
    db.commit()
    return RedirectResponse("/settings/branding?status=branding-saved", status_code=303)


@app.get("/api/v1/companies")
def list_companies(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    companies = db.scalars(
        select(Company)
        .join(CompanyUser)
        .where(CompanyUser.user_id == user.id)
        .order_by(Company.name)
    ).all()
    return [
        {"id": str(c.id), "name": c.name, "created_at": c.created_at.isoformat()}
        for c in companies
    ]


@app.post("/api/v1/companies")
def create_company(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
):
    company = Company(name=name.strip())
    db.add(company)
    db.flush()
    db.add(CompanyUser(company_id=company.id, user_id=user.id, role="owner"))
    write_audit(db, request, "company.create", user=user, company_id=company.id)
    db.commit()
    return RedirectResponse(f"/companies/{company.id}", status_code=303)


@app.post("/settings/companies")
def create_settings_company(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
):
    require_admin(user)
    normalized_name = name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="company name is required")
    company = Company(name=normalized_name)
    db.add(company)
    db.flush()
    db.add(CompanyUser(company_id=company.id, user_id=user.id, role="owner"))
    write_audit(
        db, request, "settings.company.create", user=user, company_id=company.id
    )
    db.commit()
    return RedirectResponse(
        "/settings/manage-companies?status=company-created", status_code=303
    )


@app.post("/settings/companies/{company_id}")
def update_company(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
):
    require_admin(user)
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404)
    normalized_name = name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="company name is required")
    company.name = normalized_name
    write_audit(
        db, request, "settings.company.update", user=user, company_id=company.id
    )
    db.commit()
    return RedirectResponse(
        "/settings/manage-companies?status=company-updated", status_code=303
    )


@app.post("/settings/companies/{company_id}/delete")
def delete_company(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404)
    devices = db.scalars(select(Device).where(Device.company_id == company.id)).all()
    for device in devices:
        if not device.revoked_at:
            remove_peer(device.wg_public_key)
    device_ids = [device.id for device in devices]
    if device_ids:
        db.execute(delete(DeviceEvent).where(DeviceEvent.device_id.in_(device_ids)))
    db.execute(delete(Device).where(Device.company_id == company.id))
    db.execute(delete(EnrollmentCode).where(EnrollmentCode.company_id == company.id))
    db.execute(delete(CompanyUser).where(CompanyUser.company_id == company.id))
    write_audit(
        db, request, "settings.company.delete", user=user, company_id=company.id
    )
    db.delete(company)
    db.commit()
    return RedirectResponse(
        "/settings/manage-companies?status=company-deleted", status_code=303
    )


@app.get("/companies/{company_id}", response_class=HTMLResponse)
def company_detail(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    devices = db.scalars(
        select(Device).where(Device.company_id == company.id).order_by(Device.hostname)
    ).all()
    codes = db.scalars(
        select(EnrollmentCode)
        .where(EnrollmentCode.company_id == company.id)
        .order_by(EnrollmentCode.created_at.desc())
        .limit(5)
    ).all()
    return templates.TemplateResponse(
        "company_detail.html",
        {
            "request": request,
            "user": user,
            "company": company,
            "devices": devices,
            "codes": codes,
            "now": utc_now(),
            "active_page": "companies",
        },
    )


@app.get("/api/v1/companies/{company_id}")
def get_company(
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    return {"id": str(company.id), "name": company.name}


@app.post("/api/v1/companies/{company_id}/enrollment-codes")
def create_enrollment_code(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id, "admin")
    code = random_otp()
    expires_at = utc_now() + timedelta(minutes=settings.otp_ttl_minutes)
    db.add(
        EnrollmentCode(
            company_id=company.id,
            code_hash=hash_secret(code),
            expires_at=expires_at,
            created_by=user.id,
        )
    )
    write_audit(db, request, "enrollment_code.create", user=user, company_id=company.id)
    db.commit()
    return templates.TemplateResponse(
        "otp.html",
        {
            "request": request,
            "company": company,
            "code": code,
            "expires_at": expires_at,
        },
    )


@app.post("/api/v1/enroll")
def enroll(
    payload: dict[str, object],
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    otp = str(payload.get("otp", "")).strip().upper()
    wg_public_key = str(payload.get("wg_public_key", "")).strip()
    hostname = str(payload.get("hostname", "")).strip()[:255]
    if not otp or not hostname or not wg_public_key:
        raise HTTPException(
            status_code=400, detail="otp, hostname and wg_public_key are required"
        )
    now = utc_now()
    codes = db.scalars(
        select(EnrollmentCode).where(
            EnrollmentCode.used_at.is_(None), EnrollmentCode.expires_at > now
        )
    ).all()
    matched = next((code for code in codes if verify_secret(otp, code.code_hash)), None)
    if not matched:
        raise HTTPException(
            status_code=401, detail="invalid or expired enrollment code"
        )
    tunnel_ip = next_tunnel_ip(db)
    token = random_token(48)
    device = Device(
        company_id=matched.company_id,
        hostname=hostname,
        opnsense_version=payload.get("opnsense_version"),
        plugin_version=payload.get("plugin_version"),
        wg_public_key=wg_public_key,
        wg_tunnel_ip=tunnel_ip,
        device_token_hash=hash_secret(token),
        status="online",
        last_seen_at=now,
    )
    try:
        add_peer(wg_public_key, tunnel_ip)
    except WireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    matched.used_at = now
    db.add(device)
    db.flush()
    db.add(
        DeviceEvent(
            device_id=device.id, event_type="enrolled", message="Device enrolled"
        )
    )
    write_audit(
        db, request, "device.enroll", company_id=device.company_id, device_id=device.id
    )
    db.commit()
    return {
        "device_id": str(device.id),
        "device_token": token,
        "wireguard": {
            "interface_address": f"{tunnel_ip}/32",
            "server_public_key": get_server_public_key(),
            "endpoint": settings.hub_wg_endpoint,
            "allowed_ips": client_allowed_ips(),
            "persistent_keepalive": 25,
        },
    }


def device_from_token(
    db: Session, device_id: uuid.UUID, authorization: str | None
) -> Device:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401)
    token = authorization.removeprefix("Bearer ").strip()
    device = db.get(Device, device_id)
    if (
        not device
        or device.revoked_at
        or not verify_secret(token, device.device_token_hash)
    ):
        raise HTTPException(status_code=401)
    return device


@app.post("/api/v1/devices/{device_id}/heartbeat")
def heartbeat(
    device_id: uuid.UUID,
    payload: dict[str, object],
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    device = device_from_token(db, device_id, authorization)
    device.status = str(payload.get("status", "online"))[:30]
    device.hostname = str(payload.get("hostname", device.hostname))[:255]
    device.opnsense_version = payload.get("opnsense_version", device.opnsense_version)
    device.last_seen_at = utc_now()
    db.add(
        DeviceEvent(device_id=device.id, event_type="heartbeat", message=device.status)
    )
    db.commit()
    return {"ok": True}


@app.get("/api/v1/companies/{company_id}/devices")
def list_devices(
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    devices = db.scalars(
        select(Device).where(Device.company_id == company.id).order_by(Device.hostname)
    ).all()
    return [
        {
            "id": str(d.id),
            "hostname": d.hostname,
            "status": d.status,
            "tunnel_ip": str(d.wg_tunnel_ip),
            "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
        }
        for d in devices
    ]


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_page(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_role(db, user, device.company_id):
        raise HTTPException(status_code=404)
    events = db.scalars(
        select(DeviceEvent)
        .where(DeviceEvent.device_id == device.id)
        .order_by(DeviceEvent.created_at.desc())
        .limit(25)
    ).all()
    return templates.TemplateResponse(
        "device.html",
        {
            "request": request,
            "user": user,
            "device": device,
            "events": events,
            "active_page": "companies",
        },
    )


@app.get("/api/v1/devices/{device_id}")
def get_device(
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_role(db, user, device.company_id):
        raise HTTPException(status_code=404)
    return {
        "id": str(device.id),
        "hostname": device.hostname,
        "opnsense_version": device.opnsense_version,
        "plugin_version": device.plugin_version,
        "tunnel_ip": str(device.wg_tunnel_ip),
        "status": device.status,
        "revoked_at": device.revoked_at.isoformat() if device.revoked_at else None,
    }


@app.post("/api/v1/devices/{device_id}/revoke")
def revoke_device(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_role(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    if not device.revoked_at:
        remove_peer(device.wg_public_key)
        device.revoked_at = utc_now()
        device.status = "revoked"
        device.device_token_hash = hash_secret(random_token(48))
        db.add(
            DeviceEvent(
                device_id=device.id, event_type="revoked", message="Device revoked"
            )
        )
        write_audit(
            db,
            request,
            "device.revoke",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
    return RedirectResponse(f"/companies/{device.company_id}", status_code=303)


@app.api_route(
    "/proxy/devices/{device_id}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy_device(
    request: Request,
    device_id: uuid.UUID,
    path: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if (
        not device
        or device.revoked_at
        or not has_company_role(db, user, device.company_id)
    ):
        raise HTTPException(status_code=404)
    write_audit(
        db,
        request,
        "device.proxy.open",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    url = f"https://{device.wg_tunnel_ip}:{settings.opnsense_gui_port}/{path}"
    async with httpx.AsyncClient(
        verify=settings.proxy_verify_tls, follow_redirects=False, timeout=30
    ) as client:
        proxied = await client.request(
            request.method,
            url,
            headers={
                k: v
                for k, v in request.headers.items()
                if k.lower() not in {"host", "cookie"}
            },
            content=await request.body(),
        )
    return Response(
        content=proxied.content,
        status_code=proxied.status_code,
        headers={
            k: v
            for k, v in proxied.headers.items()
            if k.lower() not in {"content-encoding", "transfer-encoding", "connection"}
        },
    )
