from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "OPNsense Hub"
    app_env: str = "development"
    public_url: str = "http://localhost:8083"
    database_url: str = (
        "postgresql+psycopg://opnsensehub:opnsensehub@db:5432/opnsensehub"
    )
    secret_key: str = "change-me"
    initial_admin_email: str = "admin@example.com"
    initial_admin_password: str = "change-me"
    session_cookie_name: str = "opnsense_hub_session"
    session_secure: bool = False
    session_ttl_hours: int = 12
    otp_ttl_minutes: int = 10
    hub_wg_endpoint: str = "localhost:51820"
    hub_wg_cidr: str = "100.96.0.0/16"
    hub_wg_address: str = "100.96.0.1/16"
    hub_wg_listen_port: int = 51820
    allow_broad_wg_cidr: bool = False
    wg_interface: str = "wg0"
    wg_config_path: str = "/etc/wireguard/wg0.conf"
    wg_server_private_key_path: str = "/etc/wireguard/server.key"
    wg_server_public_key: str = "replace-with-server-public-key"
    wg_dry_run: bool = False
    hub_enable_ip_forwarding: bool = False
    hub_manage_firewall_rules: bool = True
    proxy_verify_tls: bool = False
    allow_insecure_proxy_tls_in_production: bool = False
    opnsense_gui_port: int = 443
    branding_upload_dir: str = "/var/lib/opnsense-hub/branding"
    branding_logo_max_bytes: int = 1_000_000
    firewall_health_check_interval_seconds: int = 60
    firewall_health_check_timeout_seconds: int = 15
    firewall_health_warning_misses: int = 3
    firewall_health_critical_misses: int = 3
    firewall_health_warning_recovery_successes: int = 1
    firewall_health_critical_recovery_successes: int = 2

    class Config:
        env_file = ".env"
        env_prefix = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
