import uuid
from datetime import timedelta
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import write_audit
from .config import get_settings
from .database import Base, SessionLocal, engine, get_db
from .models import (
    AuditLog,
    Company,
    CompanyUser,
    Device,
    DeviceEvent,
    EnrollmentCode,
    User,
)
from .rbac import has_company_role
from .security import hash_secret, random_otp, random_token, utc_now, verify_secret
from .wireguard import WireGuardError, add_peer, next_tunnel_ip, remove_peer

settings = get_settings()
app = FastAPI(title=settings.app_name)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def bootstrap() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        admin = db.scalar(
            select(User).where(User.email == settings.initial_admin_email.lower())
        )
        if not admin:
            db.add(
                User(
                    email=settings.initial_admin_email.lower(),
                    password_hash=hash_secret(settings.initial_admin_password),
                )
            )
            db.commit()


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
        .join(CompanyUser)
        .where(CompanyUser.user_id == user.id)
        .order_by(Company.name)
    ).all()
    return templates.TemplateResponse(
        "companies.html", {"request": request, "user": user, "companies": companies}
    )


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
            "server_public_key": settings.wg_server_public_key,
            "endpoint": settings.hub_wg_endpoint,
            "allowed_ips": str(settings.hub_wg_address).split("/")[0] + "/32",
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
        {"request": request, "user": user, "device": device, "events": events},
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


@app.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company_ids = [cu.company_id for cu in user.companies]
    logs = db.scalars(
        select(AuditLog)
        .where(AuditLog.company_id.in_(company_ids) | AuditLog.company_id.is_(None))
        .order_by(AuditLog.created_at.desc())
        .limit(100)
    ).all()
    return templates.TemplateResponse(
        "audit.html", {"request": request, "user": user, "logs": logs}
    )


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
