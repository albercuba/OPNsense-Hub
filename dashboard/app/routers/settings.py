from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..branding import (
    BrandingError,
    clear_uploaded_logo,
    save_uploaded_logo,
    uploaded_logo_path,
    validate_branding_upload,
)
from ..database import get_db
from ..deps import current_user, require_admin
from ..models import (
    Company,
    CompanyUser,
    Device,
    DeviceEvent,
    EnrollmentCode,
    SessionToken,
    User,
)
from ..security import hash_secret, utc_now
from ..security.rate_limit import apply_rate_limit
from ..security.secrets import store_secret
from ..services.backup_service import (
    export_backup_bundle,
    parse_backup_bundle,
    restore_backup_bundle,
)
from ..services.common import clean_optional, get_or_create_integration_settings
from ..web import render_template, settings

router = APIRouter()


@router.get("/settings", response_class=HTMLResponse)
def settings_redirect(user: Annotated[User, Depends(current_user)]):
    require_admin(user)
    return RedirectResponse("/settings/manage-companies", status_code=303)


@router.get("/settings/{section}", response_class=HTMLResponse)
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
        "backup",
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


@router.post("/settings/users")
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


@router.post("/settings/users/{target_user_id}")
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


@router.post("/settings/users/{target_user_id}/delete")
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


@router.post("/settings/email")
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
    integration_settings.smtp_password = store_secret(
        integration_settings.smtp_password, smtp_password
    )
    integration_settings.graph_client_secret = store_secret(
        integration_settings.graph_client_secret, graph_client_secret
    )
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.email.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/email-settings?status=email-saved", status_code=303
    )


@router.post("/settings/microsoft")
def update_microsoft_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    microsoft_enabled: str | None = Form(None),
    microsoft_tenant_id: str = Form(""),
    microsoft_client_id: str = Form(""),
    microsoft_client_secret: str = Form(""),
    microsoft_audience: str = Form(""),
    microsoft_authority: str = Form(""),
    microsoft_admin_group_name: str = Form(""),
    microsoft_admin_group_id: str = Form(""),
    microsoft_user_group_name: str = Form(""),
    microsoft_user_group_id: str = Form(""),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.microsoft_enabled = microsoft_enabled == "on"
    integration_settings.microsoft_tenant_id = clean_optional(microsoft_tenant_id)
    integration_settings.microsoft_client_id = clean_optional(microsoft_client_id)
    integration_settings.microsoft_client_secret = store_secret(
        integration_settings.microsoft_client_secret, microsoft_client_secret
    )
    integration_settings.microsoft_audience = clean_optional(microsoft_audience)
    integration_settings.microsoft_authority = clean_optional(microsoft_authority)
    integration_settings.microsoft_admin_group_name = clean_optional(
        microsoft_admin_group_name
    )
    integration_settings.microsoft_admin_group_id = clean_optional(
        microsoft_admin_group_id
    )
    integration_settings.microsoft_user_group_name = clean_optional(
        microsoft_user_group_name
    )
    integration_settings.microsoft_user_group_id = clean_optional(
        microsoft_user_group_id
    )
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.microsoft.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/microsoft-365?status=microsoft-saved", status_code=303
    )


@router.post("/settings/local-ad")
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


@router.get("/branding/logo")
def branding_logo():
    logo_path = uploaded_logo_path(settings.branding_upload_dir)
    if not logo_path:
        raise HTTPException(status_code=404)
    media_type = {".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp"}[
        logo_path.suffix
    ]
    return FileResponse(logo_path, media_type=media_type)


@router.post("/settings/branding")
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
                branding_logo_file, content, settings.branding_logo_max_bytes
            )
        except BrandingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        save_uploaded_logo(settings.branding_upload_dir, extension, content)
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.branding.update", user=user)
    db.commit()
    return RedirectResponse("/settings/branding?status=branding-saved", status_code=303)


@router.post("/settings/backup/export")
def export_settings_backup(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    backup_passphrase: str = Form(""),
):
    require_admin(user)
    bundle, filename, media_type = export_backup_bundle(
        db, clean_optional(backup_passphrase)
    )
    write_audit(db, request, "settings.backup.export", user=user)
    db.commit()
    return Response(
        content=bundle,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/settings/backup/restore")
async def restore_settings_backup(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    backup_file: UploadFile = File(...),
    backup_passphrase: str = Form(""),
):
    require_admin(user)
    apply_rate_limit(
        request,
        "backup-restore",
        str(user.id),
        settings.rate_limit_backup_restore_attempts,
        settings.rate_limit_backup_restore_window_seconds,
    )
    content = await backup_file.read()
    if not content:
        raise HTTPException(status_code=400, detail="backup file is required")
    _manifest, data, logo_file, wireguard_private_key = parse_backup_bundle(
        content, clean_optional(backup_passphrase)
    )
    restore_backup_bundle(db, data, logo_file, wireguard_private_key)
    db.execute(delete(SessionToken))
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie_name)
    return response


@router.post("/settings/companies")
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


@router.post("/settings/companies/{company_id}")
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


@router.post("/settings/companies/{company_id}/delete")
def delete_company(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    from ..wireguard import remove_peer

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
