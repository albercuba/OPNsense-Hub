import asyncio
import contextlib
import ipaddress
import logging
import re
import uuid
from datetime import timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session, selectinload

from .audit import write_audit
from .branding import (
    BrandingError,
    clear_uploaded_logo,
    save_uploaded_logo,
    uploaded_logo_path,
    validate_branding_upload,
)
from .config import get_settings
from .database import Base, SessionLocal, engine, get_db
from .hardening import apply_startup_hardening
from .health import HealthState, HealthThresholds, next_health_state
from .models import (
    Company,
    CompanyUser,
    Device,
    DeviceEvent,
    EnrollmentCode,
    IntegrationSettings,
    SessionToken,
    User,
)
from .rbac import has_company_role
from .security import (
    hash_secret,
    hash_session_token,
    random_otp,
    random_token,
    utc_now,
    verify_secret,
)
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
logger = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name)
APP_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


def tunnel_proxy_host(value: object) -> str:
    """Return a plain IP host for proxy URLs from an INET/CIDR value."""
    text_value = str(value)
    if "/" in text_value:
        return str(ipaddress.ip_interface(text_value).ip)
    return str(ipaddress.ip_address(text_value))


def device_webgui_url(device: Device) -> str:
    proxy_host = tunnel_proxy_host(device.wg_tunnel_ip)
    return f"https://{proxy_host}:{settings.opnsense_gui_port}/"


PROXY_REQUEST_HEADER_BLOCKLIST = {
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "origin",
    "proxy-authenticate",
    "proxy-authorization",
    "referer",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def proxy_request_headers(request: Request, device_id: uuid.UUID) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in PROXY_REQUEST_HEADER_BLOCKLIST
    }
    cookie_header = proxy_upstream_cookie_header(request, device_id)
    if cookie_header:
        headers["cookie"] = cookie_header
    return headers


def proxy_cookie_prefix(device_id: uuid.UUID) -> str:
    return f"opnhub_{device_id.hex}_"


def proxy_path_prefix(device_id: uuid.UUID) -> str:
    return f"/proxy/devices/{device_id}"


def proxy_upstream_cookie_header(request: Request, device_id: uuid.UUID) -> str:
    prefix = proxy_cookie_prefix(device_id)
    upstream_cookies = []
    for name, value in request.cookies.items():
        if name.startswith(prefix):
            upstream_cookies.append(f"{name[len(prefix) :]}={value}")
    return "; ".join(upstream_cookies)


def proxy_downstream_set_cookie_headers(
    set_cookie_headers: list[str], device_id: uuid.UUID
) -> list[str]:
    rewritten = []
    prefix = proxy_cookie_prefix(device_id)
    path_prefix = proxy_path_prefix(device_id)
    for header in set_cookie_headers:
        cookies = SimpleCookie()
        cookies.load(header)
        for name, morsel in cookies.items():
            morsel.set(prefix + name, morsel.value, morsel.coded_value)
            morsel["path"] = path_prefix
            morsel["domain"] = ""
            rewritten.append(morsel.OutputString())
    return rewritten


def proxy_rewrite_location(
    location: str, device_id: uuid.UUID, upstream_base: str
) -> str:
    path_prefix = proxy_path_prefix(device_id)
    if location.startswith(upstream_base):
        return path_prefix + "/" + location.removeprefix(upstream_base).lstrip("/")
    if location.startswith("/") and not location.startswith(path_prefix + "/"):
        return path_prefix + location
    return location


def proxy_rewrite_absolute_path(match: re.Match[str], path_prefix: str) -> str:
    prefix = match.group("prefix")
    path = match.group("path")
    if path.startswith(("/", "proxy/devices/")):
        return match.group(0)
    return f"{prefix}{path_prefix}/{path}"


def proxy_rewrite_body(
    content: bytes, content_type: str, device_id: uuid.UUID
) -> bytes:
    if not any(
        kind in content_type.lower() for kind in ("text/html", "text/css", "javascript")
    ):
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    path_prefix = proxy_path_prefix(device_id)
    text = re.sub(
        r'(?P<prefix>\b(?:href|src|action)=(["\']))/(?P<path>[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>url\((["\']?))/(?P<path>[^)"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>["\'])/(?P<path>(?!/|proxy/devices/)[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    return text.encode("utf-8")


async def probe_device_webgui(
    client: httpx.AsyncClient, device: Device
) -> tuple[bool, str]:
    try:
        url = device_webgui_url(device)
    except ValueError as exc:
        return (
            False,
            f"Stored WireGuard tunnel IP is invalid: {device.wg_tunnel_ip}: {exc}",
        )

    try:
        await client.get(url)
    except httpx.RequestError as exc:
        error_detail = str(exc) or repr(exc)
        return (
            False,
            f"WebGUI unreachable at {url}: {exc.__class__.__name__}: {error_detail}",
        )
    return True, f"WebGUI reachable at {url}"


def device_health_status(device: Device, healthy: bool) -> str:
    new_state = next_health_state(
        HealthState(
            status=device.status,
            missed_checks=device.health_missed_checks,
            success_checks=device.health_success_checks,
        ),
        healthy,
        HealthThresholds(
            warning_misses=settings.firewall_health_warning_misses,
            critical_misses=settings.firewall_health_critical_misses,
            warning_recovery_successes=settings.firewall_health_warning_recovery_successes,
            critical_recovery_successes=settings.firewall_health_critical_recovery_successes,
        ),
    )
    device.health_missed_checks = new_state.missed_checks
    device.health_success_checks = new_state.success_checks
    return new_state.status


async def run_device_health_checks_once() -> None:
    with SessionLocal() as db:
        devices = db.scalars(
            select(Device).where(Device.revoked_at.is_(None)).order_by(Device.hostname)
        ).all()
        if not devices:
            return

        now = utc_now()
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls,
            follow_redirects=False,
            timeout=settings.firewall_health_check_timeout_seconds,
        ) as client:
            for device in devices:
                healthy, message = await probe_device_webgui(client, device)
                new_status = device_health_status(device, healthy)
                if device.status != new_status:
                    device.status = new_status
                    db.add(
                        DeviceEvent(
                            device_id=device.id,
                            event_type="health_check",
                            message=(
                                f"{message}; missed={device.health_missed_checks}; "
                                f"successes={device.health_success_checks}"
                            )[:1000],
                        )
                    )
                if healthy:
                    device.last_seen_at = now
        db.commit()


async def device_health_check_loop() -> None:
    interval = max(1, settings.firewall_health_check_interval_seconds)
    while True:
        try:
            await run_device_health_checks_once()
        except Exception:
            logger.exception("Firewall health check failed")
        await asyncio.sleep(interval)


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
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_missed_checks integer NOT NULL DEFAULT 0"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_success_checks integer NOT NULL DEFAULT 0"
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                  id uuid PRIMARY KEY,
                  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  token_hash text NOT NULL UNIQUE,
                  created_at timestamptz NOT NULL DEFAULT now(),
                  expires_at timestamptz NOT NULL,
                  revoked_at timestamptz NULL
                )
                """
            )
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)"
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
async def on_startup() -> None:
    apply_startup_hardening(settings)
    bootstrap()
    app.state.health_check_task = asyncio.create_task(device_health_check_loop())


@app.on_event("shutdown")
async def on_shutdown() -> None:
    task = getattr(app.state, "health_check_task", None)
    if task is None:
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    session = session_from_request(request, db)
    user = db.get(User, session.user_id)
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


def current_brand_logo_url(db: Session | None = None) -> str | None:
    if uploaded_logo_path(settings.branding_upload_dir):
        return "/branding/logo"
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    try:
        integration_settings = db.get(IntegrationSettings, 1)
        return integration_settings.branding_logo_url if integration_settings else None
    finally:
        if close_db:
            db.close()


def render_template(
    db: Session | None, template_name: str, context: dict, status_code: int = 200
):
    payload = dict(context)
    payload.setdefault("brand_logo_url", current_brand_logo_url(db))
    return templates.TemplateResponse(
        template_name,
        payload,
        status_code=status_code,
    )


def create_user_session(db: Session, user: User) -> str:
    token = random_token(48)
    now = utc_now()
    db.add(
        SessionToken(
            user_id=user.id,
            token_hash=hash_session_token(settings.secret_key, token),
            created_at=now,
            expires_at=now + timedelta(hours=settings.session_ttl_hours),
        )
    )
    return token


def session_from_request(request: Request, db: Session) -> SessionToken:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401)
    token_hash = hash_session_token(settings.secret_key, token)
    session = db.scalar(
        select(SessionToken).where(SessionToken.token_hash == token_hash)
    )
    if not session or session.revoked_at or session.expires_at <= utc_now():
        raise HTTPException(status_code=401)
    return session


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Annotated[Session, Depends(get_db)]):
    user = ui_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/companies", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render_template(None, "login.html", {"request": request, "error": None})


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
        return render_template(
            db,
            "login.html",
            {"request": request, "error": "Invalid email or password"},
            status_code=401,
        )
    token = create_user_session(db, user)
    response = RedirectResponse("/companies", status_code=303)
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        max_age=settings.session_ttl_hours * 3600,
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
    session = session_from_request(request, db)
    session.revoked_at = utc_now()
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
    return render_template(
        db,
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
    return render_template(
        db,
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


@app.get("/branding/logo")
def branding_logo():
    logo_path = uploaded_logo_path(settings.branding_upload_dir)
    if not logo_path:
        raise HTTPException(status_code=404)
    media_type = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".webp": "image/webp",
    }[logo_path.suffix]
    return FileResponse(logo_path, media_type=media_type)


@app.post("/settings/branding")
async def update_branding_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    branding_logo_url: str = Form(""),
    remove_logo: str | None = Form(None),
    branding_logo_file: UploadFile | None = File(None),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.branding_logo_url = clean_optional(branding_logo_url)
    if remove_logo == "on":
        clear_uploaded_logo(settings.branding_upload_dir)
        integration_settings.branding_logo_url = None
    elif branding_logo_file and branding_logo_file.filename:
        content = await branding_logo_file.read()
        try:
            extension, _content_type = validate_branding_upload(
                branding_logo_file,
                content,
                settings.branding_logo_max_bytes,
            )
        except BrandingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        save_uploaded_logo(settings.branding_upload_dir, extension, content)
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
    return render_template(
        db,
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
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(
            {
                "code": code,
                "company": company.name,
                "expires_at": expires_at.isoformat(),
                "expires_at_display": expires_at.strftime("%Y-%m-%d %H:%M UTC"),
            }
        )
    return render_template(
        db,
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
    device.health_missed_checks = 0
    device.health_success_checks += 1
    device.hostname = str(payload.get("hostname", device.hostname))[:255]
    opnsense_version = payload.get("opnsense_version")
    if opnsense_version is not None:
        device.opnsense_version = str(opnsense_version)[:80]
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
    return render_template(
        db,
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


@app.post("/api/v1/devices/{device_id}/delete")
def delete_revoked_device(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    redirect_to: str = Form("/companies"),
):
    device = db.get(Device, device_id)
    if not device or not has_company_role(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    if not device.revoked_at:
        raise HTTPException(
            status_code=400, detail="only revoked firewalls can be removed"
        )
    company_id = device.company_id
    db.execute(delete(DeviceEvent).where(DeviceEvent.device_id == device.id))
    write_audit(
        db,
        request,
        "device.delete_revoked",
        user=user,
        company_id=company_id,
    )
    db.delete(device)
    db.commit()
    if not redirect_to.startswith("/") or redirect_to.startswith("//"):
        redirect_to = "/companies"
    return RedirectResponse(redirect_to, status_code=303)


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
    try:
        url = device_webgui_url(device) + path
        if request.url.query:
            url += "?" + request.url.query
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Stored WireGuard tunnel IP is invalid: {device.wg_tunnel_ip}",
        ) from exc
    try:
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls, follow_redirects=False, timeout=30
        ) as client:
            proxied = await client.request(
                request.method,
                url,
                headers=proxy_request_headers(request, device_id),
                content=await request.body(),
            )
    except httpx.RequestError as exc:
        error_detail = str(exc) or repr(exc)
        raise HTTPException(
            status_code=502,
            detail=(
                f"Could not reach OPNsense UI at {url}: "
                f"{exc.__class__.__name__}: {error_detail}. "
                "Verify WireGuard has a recent handshake, the firewall allows "
                "Hub tunnel traffic to the WebGUI port, and the WebGUI listens "
                "on the tunnel interface."
            ),
        ) from exc
    response_headers = {
        k: v
        for k, v in proxied.headers.items()
        if k.lower()
        not in {
            "content-encoding",
            "content-length",
            "connection",
            "location",
            "set-cookie",
            "transfer-encoding",
        }
    }
    if location := proxied.headers.get("location"):
        response_headers["location"] = proxy_rewrite_location(
            location, device_id, device_webgui_url(device)
        )
    response = Response(
        content=proxy_rewrite_body(
            proxied.content, proxied.headers.get("content-type", ""), device_id
        ),
        status_code=proxied.status_code,
        headers=response_headers,
    )
    for cookie in proxy_downstream_set_cookie_headers(
        proxied.headers.get_list("set-cookie"), device_id
    ):
        response.headers.append("set-cookie", cookie)
    return response
