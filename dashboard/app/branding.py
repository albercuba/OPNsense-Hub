from pathlib import Path

from fastapi import UploadFile

ALLOWED_BRANDING_TYPES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
}


class BrandingError(ValueError):
    pass


def detect_image_extension(content: bytes) -> str:
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if content.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return ".webp"
    raise BrandingError("Only PNG, JPEG, and WebP logo uploads are allowed")


def validate_branding_upload(
    upload: UploadFile, content: bytes, max_bytes: int
) -> tuple[str, str]:
    if not content:
        raise BrandingError("Uploaded logo file is empty")
    if len(content) > max_bytes:
        raise BrandingError(f"Uploaded logo exceeds {max_bytes} bytes")
    if upload.content_type not in ALLOWED_BRANDING_TYPES:
        raise BrandingError("Logo content type must be PNG, JPEG, or WebP")
    extension = detect_image_extension(content)
    expected_extension = ALLOWED_BRANDING_TYPES[upload.content_type]
    if extension != expected_extension:
        raise BrandingError(
            "Uploaded logo file content does not match the declared content type"
        )
    return extension, upload.content_type


def clear_uploaded_logo(upload_dir: str) -> None:
    path = Path(upload_dir)
    for existing in path.glob("logo.*"):
        existing.unlink(missing_ok=True)


def save_uploaded_logo(upload_dir: str, extension: str, content: bytes) -> Path:
    path = Path(upload_dir)
    path.mkdir(parents=True, exist_ok=True)
    clear_uploaded_logo(upload_dir)
    logo_path = path / f"logo{extension}"
    logo_path.write_bytes(content)
    return logo_path


def uploaded_logo_path(upload_dir: str) -> Path | None:
    path = Path(upload_dir)
    for extension in (".png", ".jpg", ".webp"):
        candidate = path / f"logo{extension}"
        if candidate.exists():
            return candidate
    return None
