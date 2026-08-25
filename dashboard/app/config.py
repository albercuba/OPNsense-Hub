from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
    )

    app_name: str = "OPNsense Hub"
    app_env: str = "development"
    app_timezone: str = "UTC"
    public_url: str = "http://localhost:8083"
    proxy_public_url: str = "http://proxy.localhost:8083"
    proxy_grant_ttl_seconds: int = 60
    proxy_session_ttl_minutes: int = 15
    proxy_session_cookie_prefix: str = "opnsense_hub_proxy_"
    connector_session_ttl_minutes: int = 15
    connector_local_port: int = 8443
    connector_max_connections: int = 16
    connector_upstream_connect_timeout_seconds: int = 15
    connector_connection_max_seconds: int = 900
    connector_authorization_recheck_seconds: int = 5
    public_l4_relay_enabled: bool = False
    public_l4_relay_mtls_required: bool = False
    public_l4_relay_bind_host: str = "0.0.0.0"
    public_l4_relay_port_min: int = 55000
    public_l4_relay_port_max: int = 55099
    public_l4_relay_ttl_seconds: int = 600
    public_l4_relay_idle_timeout_seconds: int = 120
    public_l4_relay_max_connections: int = 16
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
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "script-src 'self' 'unsafe-inline'; "
        "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"
    rate_limit_backend: str = "memory"
    rate_limit_redis_url: str | None = None
    rate_limit_memory_max_buckets: int = 10_000
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
    wg_agent_url: str | None = None
    wg_agent_token: str | None = None
    wg_agent_mode: bool = False
    hub_enable_ip_forwarding: bool = False
    hub_manage_firewall_rules: bool = True
    hub_control_plane_port: int = 8083
    hub_external_isolation_policy_verified: bool = False
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
    device_token_ttl_days: int = 90
    device_token_rotation_window_days: int = 14
    rate_limit_backup_restore_attempts: int = 3
    rate_limit_backup_restore_window_seconds: int = 900
    rate_limit_device_access_attempts: int = 20
    rate_limit_device_access_window_seconds: int = 300
    audit_log_retention_days: int = 365
    device_event_retention_days: int = 90
    log_retention_sweep_interval_hours: int = 24
    log_retention_delete_batch_size: int = 5000
    audit_log_min_retention_days: int = 30
    device_event_min_retention_days: int = 7
    log_retention_run_on_startup: bool = True
    log_retention_enabled: bool = True
    scheduler_lock_poll_seconds: int = 30
    audit_device_view_throttle_minutes: int = 15
    run_db_migrations_on_startup: bool = True
    allow_legacy_schema_bootstrap: bool = True
    firewall_health_warning_misses: int = 3
    firewall_health_critical_misses: int = 5
    firewall_health_warning_recovery_successes: int = 1
    firewall_health_critical_recovery_successes: int = 2


@lru_cache
def get_settings() -> Settings:
    return Settings()
