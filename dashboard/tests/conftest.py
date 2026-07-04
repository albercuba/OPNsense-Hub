import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("WG_DRY_RUN", "true")
os.environ.setdefault("BRANDING_UPLOAD_DIR", "./test-branding")
os.environ.setdefault("PUBLIC_URL", "http://localhost:8083")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-bytes-long")

from app.config import get_settings

get_settings.cache_clear()
