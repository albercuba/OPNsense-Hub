from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "OPNsense Hub"
    public_url: str = "http://localhost:8083"
    database_url: str = (
        "postgresql+psycopg://opnsensehub:opnsensehub@db:5432/opnsensehub"
    )
    secret_key: str = "change-me"
    initial_admin_email: str = "admin@example.com"
    initial_admin_password: str = "change-me"
    session_cookie_name: str = "opnsense_hub_session"
    session_secure: bool = False
    otp_ttl_minutes: int = 10
    hub_wg_endpoint: str = "localhost:51820"
    hub_wg_cidr: str = "100.96.0.0/16"
    hub_wg_address: str = "100.96.0.1/16"
    hub_wg_listen_port: int = 51820
    wg_interface: str = "wg0"
    wg_server_public_key: str = "replace-with-server-public-key"
    wg_dry_run: bool = True
    proxy_verify_tls: bool = False
    opnsense_gui_port: int = 443

    class Config:
        env_file = ".env"
        env_prefix = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
