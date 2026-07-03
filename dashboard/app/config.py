from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "OPNsense Hub"
    app_env: str = "development"
    app_timezone: str = "UTC"
    public_url: str = "http://localhost:8083"
    database_url: str = (
        "postgresql+psycopg://opnsensehub:opnsensehub@db:5432/opnsensehub"
    )
    secret_key: str = "change-me"
    secret_encryption_key: str | None = None
    csrf_cookie_name: str = "opnsense_hub_csrf"
    initial_admin_email: str = "admin@example.com"
    initial_admin_password: str = "change-me"
    session_cookie_name: str = "opnsense_hub_session"
    session_secure: bool = False
    session_ttl_hours: int = 12
    otp_ttl_minutes: int = 10
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    trusted_proxy_cidrs: str = ""
    security_headers_enabled: bool = True
    content_security_policy: str = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"
    rate_limit_backend: str = "memory"
    rate_limit_redis_url: str | None = None
    rate_limit_mfa_attempts: int = 5
    rate_limit_mfa_window_seconds: int = 300
    security_alert_email_enabled: bool = True
    max_proxy_request_bytes: int = 2_000_000
    max_proxy_response_bytes: int = 8_000_000
    max_backup_restore_bytes: int = 20_000_000
    max_backup_restore_entries: int = 16
    max_backup_restore_total_uncompressed_bytes: int = 25_000_000
    max_backup_restore_file_bytes: int = 20_000_000
    network_control_mode: str = "inline"
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
    proxy_verify_tls: bool = True
    allow_insecure_proxy_tls_in_production: bool = False
    opnsense_gui_port: int = 443
    branding_upload_dir: str = "/var/lib/opnsense-hub/branding"
    branding_logo_max_bytes: int = 1_000_000
    firewall_health_check_interval_seconds: int = 60
    firewall_health_check_timeout_seconds: int = 15
    rate_limit_login_attempts: int = 5
    rate_limit_login_window_seconds: int = 300
    rate_limit_local_ad_login_attempts: int = 5
    rate_limit_local_ad_login_window_seconds: int = 300
    rate_limit_microsoft_login_attempts: int = 10
    rate_limit_microsoft_login_window_seconds: int = 300
    rate_limit_enrollment_attempts: int = 10
    rate_limit_enrollment_window_seconds: int = 300
    rate_limit_enrollment_code_attempts: int = 10
    rate_limit_enrollment_code_window_seconds: int = 300
    rate_limit_device_heartbeat_attempts: int = 120
    rate_limit_device_heartbeat_window_seconds: int = 60
    rate_limit_device_backup_attempts: int = 20
    rate_limit_device_backup_window_seconds: int = 300
    rate_limit_backup_restore_attempts: int = 3
    rate_limit_backup_restore_window_seconds: int = 900
    audit_log_retention_days: int = 365
    device_event_retention_days: int = 90
    log_retention_sweep_interval_hours: int = 24
    log_retention_delete_batch_size: int = 5000
    audit_log_min_retention_days: int = 30
    device_event_min_retention_days: int = 7
    log_retention_run_on_startup: bool = True
    log_retention_enabled: bool = True
    audit_device_view_throttle_minutes: int = 15
    run_db_migrations_on_startup: bool = True
    allow_legacy_schema_bootstrap: bool = True
    firewall_health_warning_misses: int = 3
    firewall_health_critical_misses: int = 4
    firewall_health_warning_recovery_successes: int = 1
    firewall_health_critical_recovery_successes: int = 2

    class Config:
        env_file = ".env"
        env_prefix = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
