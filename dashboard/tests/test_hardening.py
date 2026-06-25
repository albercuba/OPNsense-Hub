import pytest
from app.config import Settings
from app.hardening import (
    CommandResult,
    StartupHardeningError,
    configure_ip_forwarding,
    install_firewall_rules,
    runtime_validation_errors,
    validate_runtime_settings,
)


def production_settings(**overrides):
    values = {
        "app_env": "production",
        "public_url": "https://hub.example.com",
        "database_url": "sqlite:///test.db",
        "secret_key": "x" * 32,
        "initial_admin_email": "admin@hub.example.com",
        "initial_admin_password": "StrongPassword123",
        "session_secure": True,
        "proxy_verify_tls": True,
        "wg_dry_run": False,
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
    )
    errors = runtime_validation_errors(settings)
    assert any("SECRET_KEY" in error for error in errors)
    assert any("INITIAL_ADMIN_EMAIL" in error for error in errors)
    assert any("INITIAL_ADMIN_PASSWORD" in error for error in errors)
    assert any("SESSION_SECURE" in error for error in errors)
    assert any("PUBLIC_URL" in error for error in errors)
    assert any("PROXY_VERIFY_TLS" in error for error in errors)


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


def test_install_firewall_rules_uses_iptables_idempotently():
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
        ["iptables", "-C", "FORWARD", "-i", "wg0", "-o", "wg0", "-j", "DROP"]
    ]
