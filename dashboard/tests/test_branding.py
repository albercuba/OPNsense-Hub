from io import BytesIO
from types import SimpleNamespace
from typing import cast

import pytest
from app.branding import (
    BrandingError,
    clear_uploaded_logo,
    save_uploaded_logo,
    uploaded_logo_path,
    validate_branding_upload,
)
from app.main import current_brand_logo_url, settings
from fastapi import UploadFile
from sqlalchemy.orm import Session
from starlette.datastructures import Headers

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"0" * 32
JPEG_BYTES = b"\xff\xd8\xff" + b"0" * 32


class FakeDb:
    def __init__(self, branding_logo_url=None):
        self._settings = SimpleNamespace(branding_logo_url=branding_logo_url)

    def get(self, model, key):
        if key == 1:
            return self._settings
        return None


def make_upload(filename: str, content_type: str, content: bytes) -> UploadFile:
    return UploadFile(
        filename=filename,
        file=BytesIO(content),
        headers=Headers({"content-type": content_type}),
    )


def test_validate_branding_upload_accepts_png():
    upload = make_upload("logo.png", "image/png", PNG_BYTES)
    extension, content_type = validate_branding_upload(upload, PNG_BYTES, 1000)
    assert extension == ".png"
    assert content_type == "image/png"


def test_validate_branding_upload_rejects_invalid_type():
    upload = make_upload("logo.gif", "image/gif", b"GIF89a")
    with pytest.raises(BrandingError):
        validate_branding_upload(upload, b"GIF89a", 1000)


def test_validate_branding_upload_rejects_oversized_file():
    upload = make_upload("logo.jpg", "image/jpeg", JPEG_BYTES)
    with pytest.raises(BrandingError):
        validate_branding_upload(upload, JPEG_BYTES, 8)


def test_uploaded_logo_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "branding_upload_dir", str(tmp_path))
    save_uploaded_logo(str(tmp_path), ".png", PNG_BYTES)
    assert (
        current_brand_logo_url(
            cast(Session, FakeDb("https://example.com/fallback.png"))
        )
        == "/branding/logo"
    )


def test_remove_uploaded_logo_clears_file(tmp_path):
    save_uploaded_logo(str(tmp_path), ".png", PNG_BYTES)
    assert uploaded_logo_path(str(tmp_path)) is not None
    clear_uploaded_logo(str(tmp_path))
    assert uploaded_logo_path(str(tmp_path)) is None


def test_current_brand_logo_url_rejects_non_https_remote_logo():
    assert current_brand_logo_url(cast(Session, FakeDb("javascript:alert(1)"))) is None
    assert (
        current_brand_logo_url(cast(Session, FakeDb("http://example.com/logo.png")))
        is None
    )
