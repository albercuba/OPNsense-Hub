import pytest
from app.config import Settings
from app.hardening import (
    MAX_PROXY_GRANT_TTL_SECONDS,
    MAX_PROXY_SESSION_TTL_MINUTES,
    CommandResult,
    StartupHardeningError,
    configure_ip_forwarding,
    install_firewall_rules,
    isolation_invariant_errors,
    runtime_validation_errors,
    validate_runtime_settings,
)


def production_settings(**overrides):
    values = {
        "app_env": "production",
        "public_url": "https://hub.example.com",
        "proxy_public_url": "https://proxy.example.com",
        "database_url": "sqlite:///test.db",
        "secret_key": "x" * 32,
        "initial_admin_email": "admin@hub.example.com",
        "initial_admin_password": "StrongPassword123",
        "session_secure": True,
        "proxy_verify_tls": True,
        "wg_dry_run": False,
        "allowed_hosts": "hub.example.com",
        "rate_limit_backend": "edge",
    }
    values.update(overrides)
    return Settings(**values)


def test_runtime_validation_errors_include_insecure_defaults():
    settings = production_settings(
        secret_key="change-me",
        initial_admin_email="admin@example.com",
        initial_admin_password="change-me",
        session_secure=False,
        public_url="http://localhost:8083",
        proxy_verify_tls=False,
        rate_limit_backend="memory",
    )
    errors = runtime_validation_errors(settings)
    assert any("SECRET_KEY" in error for error in errors)
    assert any("INITIAL_ADMIN_EMAIL" in error for error in errors)
    assert any("INITIAL_ADMIN_PASSWORD" in error for error in errors)
    assert any("SESSION_SECURE" in error for error in errors)
    assert any("PUBLIC_URL" in error for error in errors)
    assert any("PROXY_VERIFY_TLS" in error for error in errors)
    assert any("RATE_LIMIT_BACKEND" in error for error in errors)


def test_runtime_validation_accepts_secure_proxy_settings():
    assert runtime_validation_errors(production_settings()) == []


def test_runtime_validation_rejects_insecure_proxy_public_url():
    errors = runtime_validation_errors(
        production_settings(proxy_public_url="http://proxy.example.com")
    )

    assert any("PROXY_PUBLIC_URL" in error and "HTTPS" in error for error in errors)


def test_runtime_validation_rejects_proxy_hostname_matching_public_url():
    errors = runtime_validation_errors(
        production_settings(proxy_public_url="https://hub.example.com")
    )

    assert any("distinct from PUBLIC_URL" in error for error in errors)


@pytest.mark.parametrize(
    "proxy_public_url",
    [
        "https://user:password@proxy.example.com",
        "https://proxy.example.com/admin",
        "https://proxy.example.com?token=value",
        "https://proxy.example.com#fragment",
        "https://proxy.example.com:not-a-port",
    ],
)
def test_runtime_validation_rejects_invalid_proxy_public_url(proxy_public_url):
    errors = runtime_validation_errors(
        production_settings(proxy_public_url=proxy_public_url)
    )

    assert any("PROXY_PUBLIC_URL" in error for error in errors)


@pytest.mark.parametrize(
    ("overrides", "setting_name"),
    [
        ({"proxy_grant_ttl_seconds": 0}, "PROXY_GRANT_TTL_SECONDS"),
        (
            {"proxy_grant_ttl_seconds": MAX_PROXY_GRANT_TTL_SECONDS + 1},
            "PROXY_GRANT_TTL_SECONDS",
        ),
        ({"proxy_session_ttl_minutes": 0}, "PROXY_SESSION_TTL_MINUTES"),
        (
            {"proxy_session_ttl_minutes": MAX_PROXY_SESSION_TTL_MINUTES + 1},
            "PROXY_SESSION_TTL_MINUTES",
        ),
    ],
)
def test_runtime_validation_rejects_invalid_proxy_ttls(overrides, setting_name):
    errors = runtime_validation_errors(production_settings(**overrides))

    assert any(setting_name in error for error in errors)


@pytest.mark.parametrize(
    ("overrides", "setting_name"),
    [
        ({"connector_session_ttl_minutes": 0}, "CONNECTOR_SESSION_TTL_MINUTES"),
        ({"connector_local_port": 0}, "CONNECTOR_LOCAL_PORT"),
        ({"connector_max_connections": 0}, "CONNECTOR_MAX_CONNECTIONS"),
        (
            {"connector_connection_max_seconds": 0},
            "CONNECTOR_CONNECTION_MAX_SECONDS",
        ),
        (
            {"connector_authorization_recheck_seconds": 0},
            "CONNECTOR_AUTHORIZATION_RECHECK_SECONDS",
        ),
    ],
)
def test_runtime_validation_rejects_invalid_connector_settings(
    overrides, setting_name
):
    errors = runtime_validation_errors(production_settings(**overrides))

    assert any(setting_name in error for error in errors)


def test_public_l4_relay_requires_opnsense_side_mtls():
    errors = runtime_validation_errors(
        production_settings(
            public_l4_relay_enabled=True,
            public_l4_relay_mtls_required=False,
        )
    )

    assert any("PUBLIC_L4_RELAY_MTLS_REQUIRED" in error for error in errors)


def test_runtime_validation_accepts_explicit_hardened_public_l4_relay():
    assert (
        runtime_validation_errors(
            production_settings(
                public_l4_relay_enabled=True,
                public_l4_relay_mtls_required=True,
            )
        )
        == []
    )


def test_isolation_invariant_errors_reject_unsafe_forwarding_combinations():
    external = production_settings(
        network_control_mode="external",
        hub_enable_ip_forwarding=True,
    )
    inline_without_rules = production_settings(
        network_control_mode="inline",
        hub_enable_ip_forwarding=True,
        hub_manage_firewall_rules=False,
    )

    external_errors = isolation_invariant_errors(external)
    inline_errors = isolation_invariant_errors(inline_without_rules)

    assert any("NETWORK_CONTROL_MODE=external" in error for error in external_errors)
    assert any("HUB_MANAGE_FIREWALL_RULES=true" in error for error in inline_errors)


def test_validate_runtime_settings_rejects_insecure_production_defaults():
    settings = production_settings(secret_key="short")
    with pytest.raises(StartupHardeningError):
        validate_runtime_settings(settings)


def test_configure_ip_forwarding_warns_in_development():
    settings = Settings(app_env="development", database_url="sqlite:///test.db")

    def runner(_args):
        return CommandResult(returncode=1, stderr="permission denied")

    configure_ip_forwarding(settings, runner=runner)


def test_configure_ip_forwarding_fails_closed_in_production():
    settings = production_settings()

    def runner(_args):
        return CommandResult(returncode=1, stderr="permission denied")

    with pytest.raises(StartupHardeningError):
        configure_ip_forwarding(settings, runner=runner)


def test_install_firewall_rules_skips_when_disabled():
    settings = production_settings(hub_manage_firewall_rules=False)
    install_firewall_rules(settings, runner=lambda _args: CommandResult(returncode=0))


def test_network_control_mode_external_skips_runtime_network_changes():
    settings = production_settings(network_control_mode="external")
    calls = []

    def runner(args):
        calls.append(args)
        return CommandResult(returncode=0)

    configure_ip_forwarding(settings, runner=runner)
    install_firewall_rules(settings, runner=runner)
    assert calls == []


def test_install_firewall_rules_uses_iptables_idempotently_and_verifies_rule():
    settings = production_settings()
    calls = []

    def runner(args):
        calls.append(args)
        if args[:2] == ["iptables", "-C"]:
            return CommandResult(returncode=0)
        return CommandResult(returncode=0)

    install_firewall_rules(
        settings, runner=runner, which=lambda name: name == "iptables"
    )
    assert calls == [
        ["iptables", "-C", "FORWARD", "-i", "wg0", "-o", "wg0", "-j", "DROP"],
        ["iptables", "-C", "FORWARD", "-i", "wg0", "-o", "wg0", "-j", "DROP"],
    ]


def test_install_firewall_rules_fails_if_rule_cannot_be_verified():
    settings = production_settings()
    calls = []

    def runner(args):
        calls.append(args)
        if args[:2] == ["iptables", "-C"] and len(calls) == 1:
            return CommandResult(returncode=1, stderr="missing")
        if args[:2] == ["iptables", "-I"]:
            return CommandResult(returncode=0)
        if args[:2] == ["iptables", "-C"]:
            return CommandResult(returncode=1, stderr="still missing")
        return CommandResult(returncode=0)

    with pytest.raises(StartupHardeningError):
        install_firewall_rules(
            settings, runner=runner, which=lambda name: name == "iptables"
        )
