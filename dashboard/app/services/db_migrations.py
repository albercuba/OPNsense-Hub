from __future__ import annotations

from importlib import import_module
from pathlib import Path

from sqlalchemy import Engine, inspect, select, text

from ..config import get_settings
from ..database import Base, SessionLocal, engine
from ..models import User
from ..security import hash_secret
from ..wireguard import bootstrap_wireguard

settings = get_settings()
BASELINE_REVISION = "0001_current_schema_baseline"


def _alembic_modules():
    try:
        command = import_module("alembic.command")
        config_module = import_module("alembic.config")
    except ModuleNotFoundError:
        return None, None

    return command, config_module.Config


def _alembic_config():
    dashboard_dir = Path(__file__).resolve().parents[2]
    alembic_ini = dashboard_dir / "alembic.ini"
    _command, Config = _alembic_modules()
    if Config is None:
        raise RuntimeError("Alembic is not installed")
    if not alembic_ini.exists():
        return None
    config = Config(str(alembic_ini))
    config.set_main_option("script_location", str(dashboard_dir / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


def database_has_tables(target_engine: Engine) -> bool:
    inspector = inspect(target_engine)
    return bool(inspector.get_table_names())


def alembic_version_present(target_engine: Engine) -> bool:
    inspector = inspect(target_engine)
    return "alembic_version" in inspector.get_table_names()


def ensure_schema_compat_legacy(target_engine: Engine) -> None:
    with target_engine.begin() as conn:
        statements = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name text NULL",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name text NULL",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider text NULL",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user'",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_missed_checks integer NOT NULL DEFAULT 0",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_success_checks integer NOT NULL DEFAULT 0",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS license_type text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS license_expires_at timestamptz NULL",
            "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_client_secret text NULL",
            "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_admin_group_name text NULL",
            "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_admin_group_id text NULL",
            "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_user_group_name text NULL",
            "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_user_group_id text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_status text NOT NULL DEFAULT 'unknown'",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_update_available boolean NOT NULL DEFAULT false",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_update_type text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_current_version text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_available_version text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_update_count integer NOT NULL DEFAULT 0",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_reboot_required boolean NOT NULL DEFAULT false",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_status_message text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_checked_at timestamptz NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_check_requested_at timestamptz NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_check_request_reason text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_enabled boolean NOT NULL DEFAULT false",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_retention_count integer NOT NULL DEFAULT 3",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_interval_value integer NOT NULL DEFAULT 24",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_interval_unit text NOT NULL DEFAULT 'hours'",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_interval_hours integer NOT NULL DEFAULT 24",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_last_requested_at timestamptz NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_last_uploaded_at timestamptz NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notifications_enabled boolean NOT NULL DEFAULT false",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notification_recipient text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notify_on_warning boolean NOT NULL DEFAULT true",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notify_on_critical boolean NOT NULL DEFAULT true",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_last_notified_status text NULL",
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_last_notified_at timestamptz NULL",
            "UPDATE devices SET backup_interval_value = backup_interval_hours, backup_interval_unit = 'hours' WHERE backup_interval_hours IS NOT NULL",
            """
            CREATE TABLE IF NOT EXISTS sessions (
              id uuid PRIMARY KEY,
              user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              token_hash text NOT NULL UNIQUE,
              created_at timestamptz NOT NULL DEFAULT now(),
              expires_at timestamptz NOT NULL,
              revoked_at timestamptz NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
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
              microsoft_client_secret text NULL,
              microsoft_audience text NULL,
              microsoft_authority text NULL,
              microsoft_admin_group_name text NULL,
              microsoft_admin_group_id text NULL,
              microsoft_user_group_name text NULL,
              microsoft_user_group_id text NULL,
              ad_enabled boolean NOT NULL DEFAULT false,
              ad_host text NULL,
              ad_base_dn text NULL,
              ad_bind_dn text NULL,
              branding_logo_url text NULL,
              updated_at timestamptz NOT NULL DEFAULT now()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS device_backups (
              id uuid PRIMARY KEY,
              device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
              filename text NOT NULL,
              content text NOT NULL,
              created_at timestamptz NOT NULL DEFAULT now()
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_device_backups_device_id ON device_backups(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_device_events_created_at ON device_events(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_device_events_device_created_at ON device_events(device_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created_at ON audit_logs(action, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_device_created_at ON audit_logs(device_id, created_at DESC)",
        ]
        for statement in statements:
            conn.execute(text(statement))
        integration_columns = {
            column["name"]
            for column in inspect(conn).get_columns("integration_settings")
        }
        if "microsoft_admin_group" in integration_columns:
            conn.execute(
                text(
                    "UPDATE integration_settings SET microsoft_admin_group_name = COALESCE(microsoft_admin_group_name, microsoft_admin_group) WHERE microsoft_admin_group IS NOT NULL"
                )
            )
        if "microsoft_user_group" in integration_columns:
            conn.execute(
                text(
                    "UPDATE integration_settings SET microsoft_user_group_name = COALESCE(microsoft_user_group_name, microsoft_user_group) WHERE microsoft_user_group IS NOT NULL"
                )
            )


def run_startup_migrations(target_engine: Engine = engine) -> None:
    if not settings.run_db_migrations_on_startup:
        Base.metadata.create_all(bind=target_engine)
        return
    command, _Config = _alembic_modules()
    if command is None:
        Base.metadata.create_all(bind=target_engine)
        if settings.allow_legacy_schema_bootstrap:
            ensure_schema_compat_legacy(target_engine)
        return
    config = _alembic_config()
    if config is None:
        Base.metadata.create_all(bind=target_engine)
        if settings.allow_legacy_schema_bootstrap:
            ensure_schema_compat_legacy(target_engine)
        return
    has_tables = database_has_tables(target_engine)
    has_version = alembic_version_present(target_engine)
    if not has_tables:
        command.upgrade(config, "head")
        return
    if not has_version and settings.allow_legacy_schema_bootstrap:
        ensure_schema_compat_legacy(target_engine)
        command.stamp(config, BASELINE_REVISION)
        return
    command.upgrade(config, "head")


def bootstrap() -> None:
    run_startup_migrations()
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
