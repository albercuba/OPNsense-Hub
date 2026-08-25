import pytest
from app.config import Settings
from app.hardening import (
    MAX_PROXY_GRANT_TTL_SECONDS,
    MAX_PROXY_SESSION_TTL_MINUTES,
    CommandResult,
    StartupHardeningError,
    apply_startup_hardening,
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
        "allowed_hosts": "hub.example.com,proxy.example.com",
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


def test_runtime_validation_requires_strong_wireguard_agent_token():
    errors = runtime_validation_errors(
        production_settings(
            wg_agent_url="http://opnsense-hub-wireguard:8084",
            wg_agent_token="development-only-wireguard-agent-token-change-me",
        )
    )

    assert any("WG_AGENT_TOKEN" in error for error in errors)


def test_web_startup_hardening_delegates_privileged_network_changes(monkeypatch):
    settings = production_settings(
        wg_agent_url="http://opnsense-hub-wireguard:8084",
        wg_agent_token="a" * 32,
    )
    calls = []

    monkeypatch.setattr(
        "app.hardening.configure_ip_forwarding",
        lambda _settings: calls.append("ip_forwarding"),
    )
    monkeypatch.setattr(
        "app.hardening.install_firewall_rules",
        lambda _settings: calls.append("firewall"),
    )

    apply_startup_hardening(settings)

    assert calls == []


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


def test_isolation_invariant_errors_require_managed_or_verified_external_policy():
    external = production_settings(network_control_mode="external")
    inline_without_rules = production_settings(hub_manage_firewall_rules=False)

    external_errors = isolation_invariant_errors(external)
    inline_errors = isolation_invariant_errors(inline_without_rules)

    assert any("HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED" in error for error in external_errors)
    assert any(
        "HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED" in error
        for error in inline_errors
    )


def test_isolation_invariant_accepts_managed_forwarding_or_verified_external_policy():
    managed = production_settings(hub_enable_ip_forwarding=True)
    external = production_settings(
        network_control_mode="external",
        hub_enable_ip_forwarding=True,
        hub_external_isolation_policy_verified=True,
    )
    inline_external = production_settings(
        hub_manage_firewall_rules=False,
        hub_external_isolation_policy_verified=True,
    )

    assert isolation_invariant_errors(managed) == []
    assert isolation_invariant_errors(external) == []
    assert isolation_invariant_errors(inline_external) == []


def test_isolation_invariant_rejects_invalid_control_plane_port():
    errors = isolation_invariant_errors(
        production_settings(hub_control_plane_port=0)
    )

    assert any("HUB_CONTROL_PLANE_PORT" in error for error in errors)


def test_validate_runtime_settings_fails_production_without_verified_external_isolation():
    with pytest.raises(StartupHardeningError) as exc_info:
        validate_runtime_settings(
            production_settings(network_control_mode="external")
        )

    assert "HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED" in str(exc_info.value)


def test_validate_runtime_settings_accepts_verified_external_isolation():
    validate_runtime_settings(
        production_settings(
            network_control_mode="external",
            hub_external_isolation_policy_verified=True,
        )
    )


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
    settings = production_settings(
        hub_manage_firewall_rules=False,
        hub_external_isolation_policy_verified=True,
    )
    install_firewall_rules(settings, runner=lambda _args: CommandResult(returncode=0))


def test_network_control_mode_external_skips_runtime_network_changes():
    settings = production_settings(
        network_control_mode="external",
        hub_external_isolation_policy_verified=True,
    )
    calls = []

    def runner(args):
        calls.append(args)
        return CommandResult(returncode=0)

    configure_ip_forwarding(settings, runner=runner)
    install_firewall_rules(settings, runner=runner)
    assert calls == []


def test_install_firewall_rules_uses_complete_nftables_policy_and_verifies_it():
    settings = production_settings()
    calls = []
    input_policy = (
        'iifname "wg0" ct state established,related counter packets 2 bytes 120 accept\n'
        'iifname "wg0" ip saddr 100.96.0.0/16 ip daddr 100.96.0.1 '
        'tcp dport 8083 ct state new counter packets 1 bytes 60 accept\n'
        'iifname "wg0" counter packets 0 bytes 0 drop'
    )
    forward_policy = 'iifname "wg0" counter packets 0 bytes 0 drop'

    def runner(args):
        calls.append(args)
        if args == ["nft", "list", "table", "inet", "opnsense_hub"]:
            return CommandResult(returncode=1)
        if args == ["nft", "list", "chain", "inet", "opnsense_hub", "input"]:
            return CommandResult(returncode=0, stdout=input_policy)
        if args == ["nft", "list", "chain", "inet", "opnsense_hub", "forward"]:
            return CommandResult(returncode=0, stdout=forward_policy)
        return CommandResult(returncode=0)

    install_firewall_rules(
        settings, runner=runner, which=lambda name: name == "nft"
    )

    assert [
        "nft",
        "add",
        "rule",
        "inet",
        "opnsense_hub",
        "forward",
        "iifname",
        "wg0",
        "counter",
        "drop",
    ] in calls
    assert [
        "nft",
        "add",
        "rule",
        "inet",
        "opnsense_hub",
        "input",
        "iifname",
        "wg0",
        "counter",
        "drop",
    ] in calls
    assert any(
        args[:7] == [
            "nft",
            "add",
            "rule",
            "inet",
            "opnsense_hub",
            "input",
            "iifname",
        ]
        and "established,related" in args
        and "accept" in args
        for args in calls
    )
    assert any(
        "100.96.0.0/16" in args
        and "100.96.0.1" in args
        and "8083" in args
        and "new" in args
        and "accept" in args
        for args in calls
    )


class StatefulIptablesRunner:
    def __init__(self):
        self.calls = []
        self.chains = set()
        self.rules = set()

    @staticmethod
    def _rule_key(args):
        command, operation, chain, *rule = args
        if operation == "-I" and rule and rule[0] == "1":
            rule = rule[1:]
        return command, chain, tuple(rule)

    def __call__(self, args):
        self.calls.append(args)
        command, operation = args[:2]
        if operation == "-L":
            return CommandResult(
                returncode=0 if (command, args[2]) in self.chains else 1
            )
        if operation == "-N":
            self.chains.add((command, args[2]))
            return CommandResult(returncode=0)
        if operation == "-F":
            self.rules = {
                rule
                for rule in self.rules
                if not (rule[0] == command and rule[1] == args[2])
            }
            return CommandResult(returncode=0)
        if operation == "-C":
            return CommandResult(
                returncode=0 if self._rule_key(args) in self.rules else 1
            )
        if operation in {"-A", "-I"}:
            self.rules.add(self._rule_key(args))
            return CommandResult(returncode=0)
        if operation == "-D":
            self.rules.discard(self._rule_key(args))
            return CommandResult(returncode=0)
        return CommandResult(returncode=0)


def test_install_firewall_rules_uses_complete_iptables_policy_and_verifies_it():
    settings = production_settings()
    runner = StatefulIptablesRunner()

    install_firewall_rules(
        settings,
        runner=runner,
        which=lambda name: name in {"iptables", "ip6tables"},
    )

    assert (
        "iptables",
        "OPNHUB_FORWARD",
        ("-j", "DROP"),
    ) in runner.rules
    assert (
        "iptables",
        "OPNHUB_INPUT",
        ("-i", "wg0", "-j", "DROP"),
    ) in runner.rules
    assert any(
        rule[0:2] == ("iptables", "OPNHUB_INPUT")
        and "ESTABLISHED,RELATED" in rule[2]
        and "ACCEPT" in rule[2]
        for rule in runner.rules
    )
    assert any(
        rule[0:2] == ("iptables", "OPNHUB_INPUT")
        and "100.96.0.0/16" in rule[2]
        and "100.96.0.1/32" in rule[2]
        and "8083" in rule[2]
        and "NEW" in rule[2]
        and "ACCEPT" in rule[2]
        for rule in runner.rules
    )
    input_appends = [
        args
        for args in runner.calls
        if args[:3] == ["iptables", "-A", "OPNHUB_INPUT"]
    ]
    assert "ESTABLISHED,RELATED" in input_appends[0]
    assert "NEW" in input_appends[1]
    assert input_appends[2][-2:] == ["-j", "DROP"]
    assert (
        "ip6tables",
        "OPNHUB_INPUT6",
        (
            "-i",
            "wg0",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ),
    ) in runner.rules
    assert (
        "ip6tables",
        "OPNHUB_INPUT6",
        ("-i", "wg0", "-j", "DROP"),
    ) in runner.rules
    assert (
        "ip6tables",
        "INPUT",
        ("-i", "wg0", "-j", "OPNHUB_INPUT6"),
    ) in runner.rules
    assert (
        "ip6tables",
        "FORWARD",
        ("-i", "wg0", "-j", "DROP"),
    ) in runner.rules


def test_install_firewall_rules_fails_if_complete_policy_cannot_be_verified():
    settings = production_settings()
    stateful_runner = StatefulIptablesRunner()

    def runner(args):
        if args == ["iptables", "-C", "OPNHUB_FORWARD", "-j", "DROP"]:
            return CommandResult(returncode=1, stderr="still missing")
        return stateful_runner(args)

    with pytest.raises(StartupHardeningError):
        install_firewall_rules(
            settings,
            runner=runner,
            which=lambda name: name in {"iptables", "ip6tables"},
        )
