import importlib
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("WG_DRY_RUN", "true")
os.environ.setdefault("BRANDING_UPLOAD_DIR", "./test-branding")
os.environ.setdefault("PUBLIC_URL", "http://localhost:8083")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-bytes-long")

import pytest

from app.config import get_settings

# Clear settings before importing any application module that captures the
# cached object, so every module in the test process shares one instance.
get_settings.cache_clear()

from app.services import firmware_scheduler as firmware_scheduler_service
from app.services import notification_service as notification_service_module

_SETTINGS_SNAPSHOT_MODULES = (
    "app.audit",
    "app.dashboard",
    "app.database",
    "app.security.csrf",
    "app.security.rate_limit",
    "app.security.request_context",
    "app.security.secrets",
    "app.services.db_migrations",
    "app.services.network_diagnostics",
    "app.services.notification_service",
    "app.web",
    "app.wireguard_agent",
)


@pytest.fixture(scope="session", autouse=True)
def assert_settings_singleton():
    expected = get_settings()
    mismatches = []
    for module_name in _SETTINGS_SNAPSHOT_MODULES:
        module = importlib.import_module(module_name)
        if getattr(module, "settings", None) is not expected:
            mismatches.append(module_name)
    assert not mismatches, (
        "Application modules captured different Settings instances: "
        + ", ".join(mismatches)
    )


@pytest.fixture(autouse=True)
def restore_scheduler_compat_exports():
    snapshots = {
        "probe_device_webgui": firmware_scheduler_service.probe_device_webgui,
        "SessionLocal": firmware_scheduler_service.SessionLocal,
        "httpx": firmware_scheduler_service.httpx,
        "send_notification_email": notification_service_module.send_notification_email,
    }
    yield
    for name, value in snapshots.items():
        target = (
            notification_service_module
            if name == "send_notification_email"
            else firmware_scheduler_service
        )
        setattr(target, name, value)
