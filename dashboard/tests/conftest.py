import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("WG_DRY_RUN", "true")
os.environ.setdefault("BRANDING_UPLOAD_DIR", "./test-branding")
os.environ.setdefault("PUBLIC_URL", "http://localhost:8083")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-bytes-long")

import pytest

from app.config import get_settings
from app.services import firmware_scheduler as firmware_scheduler_service
from app.services import notification_service as notification_service_module

get_settings.cache_clear()


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
