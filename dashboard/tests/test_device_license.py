from datetime import datetime, timezone
from types import SimpleNamespace

from app.main import (
    device_license_expiration,
    device_license_label,
    normalize_device_license_payload,
    parse_license_expires_at,
)


def test_parse_license_expires_at_accepts_iso_date():
    parsed = parse_license_expires_at("2026-12-31")

    assert parsed == datetime(2026, 12, 31, tzinfo=timezone.utc)


def test_normalize_device_license_payload_normalizes_business_and_community():
    assert normalize_device_license_payload(
        {"license_type": "Business", "license_expires_at": "2026-12-31"}
    ) == ("business", datetime(2026, 12, 31, tzinfo=timezone.utc))
    assert normalize_device_license_payload({"license_type": "Community"}) == (
        "community",
        None,
    )


def test_device_license_display_formats_business_community_and_expired():
    business = SimpleNamespace(
        license_type="business",
        license_expires_at=datetime(2026, 12, 31, tzinfo=timezone.utc),
    )
    expired = SimpleNamespace(
        license_type="business",
        license_expires_at=datetime(2024, 1, 15, tzinfo=timezone.utc),
    )
    community = SimpleNamespace(license_type="community", license_expires_at=None)

    assert device_license_label(business) == "Business"
    assert (
        device_license_expiration(
            business, now=datetime(2026, 6, 25, tzinfo=timezone.utc)
        )
        == "12-31-2026"
    )
    assert (
        device_license_expiration(
            expired, now=datetime(2024, 1, 16, tzinfo=timezone.utc)
        )
        == "Expired"
    )
    assert device_license_label(community) == "Community"
    assert device_license_expiration(community) == "-"
