from datetime import datetime, timezone

from app.main import format_datetime, firmware_status_local_date


def test_format_datetime_uses_configured_app_timezone(monkeypatch):
    monkeypatch.setattr("app.main.settings.app_timezone", "Europe/Berlin")

    rendered = format_datetime(datetime(2026, 6, 26, 8, 0, tzinfo=timezone.utc), True)

    assert rendered == "2026-06-26 10:00 CEST"


def test_firmware_status_local_date_uses_configured_app_timezone(monkeypatch):
    monkeypatch.setattr("app.main.settings.app_timezone", "America/New_York")

    local_date = firmware_status_local_date(
        datetime(2026, 6, 26, 1, 30, tzinfo=timezone.utc)
    )

    assert str(local_date) == "2026-06-25"
