import ipaddress
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse

from .config import Settings
from .security import password_is_strong_enough

MAX_LOG_RETENTION_DELETE_BATCH_SIZE = 20000
MAX_LOG_RETENTION_SWEEP_INTERVAL_HOURS = 720
MAX_PROXY_GRANT_TTL_SECONDS = 300
MAX_PROXY_SESSION_TTL_MINUTES = 60
MAX_CONNECTOR_SESSION_TTL_MINUTES = 60
MAX_CONNECTOR_CONNECTION_SECONDS = 3600
MAX_PUBLIC_L4_RELAY_TTL_SECONDS = 900

logger = logging.getLogger(__name__)


class StartupHardeningError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def is_production(settings: Settings) -> bool:
    return settings.app_env.strip().lower() == "production"


def _configured_allowed_hosts(settings: Settings) -> set[str]:
    configured = {
        item.strip().lower()
        for item in settings.allowed_hosts.split(",")
        if item.strip()
    }
    for configured_url in (settings.public_url, settings.proxy_public_url):
        try:
            configured_host = (urlparse(configured_url).hostname or "").strip().lower()
        except ValueError:
            configured_host = ""
        if configured_host:
            configured.add(configured_host)
    return configured


def _trusted_proxy_networks(
    settings: Settings,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in settings.trusted_proxy_cidrs.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return ()
    return tuple(networks)


def isolation_invariant_errors(settings: Settings) -> list[str]:
    errors: list[str] = []
    mode = settings.network_control_mode.strip().lower()
    app_manages_isolation = mode == "inline" and settings.hub_manage_firewall_rules
    if (
        not app_manages_isolation
        and not settings.hub_external_isolation_policy_verified
    ):
        errors.append(
            "Set HUB_EXTERNAL_ISOLATION_POLICY_VERIFIED=true only after an external policy has been verified to default-drop forwarding from the WireGuard interface and restrict tunnel input to the Hub control plane"
        )
    if not 1 <= settings.hub_control_plane_port <= 65535:
        errors.append("Set HUB_CONTROL_PLANE_PORT to a valid TCP port")
    return errors


def runtime_validation_errors(settings: Settings) -> list[str]:
    errors: list[str] = []
    try:
        public_url = urlparse(settings.public_url)
        _ = public_url.port
    except ValueError:
        public_url = urlparse("")
    try:
        proxy_public_url = urlparse(settings.proxy_public_url)
        _ = proxy_public_url.port
    except ValueError:
        proxy_public_url = urlparse("")

    if settings.secret_key == "change-me" or len(settings.secret_key) < 32:
        errors.append("Set SECRET_KEY to a random value at least 32 characters long")
    if settings.initial_admin_email.lower() == "admin@example.com":
        errors.append("Set INITIAL_ADMIN_EMAIL to a real administrator email address")
    if settings.initial_admin_password == "change-me" or not password_is_strong_enough(
        settings.initial_admin_password
    ):
        errors.append(
            "Set INITIAL_ADMIN_PASSWORD to a strong password with at least 12 characters including letters and numbers"
        )
    if not settings.session_secure:
        errors.append("Set SESSION_SECURE=true in production")
    if (
        public_url.scheme != "https"
        or not public_url.netloc
        or public_url.hostname
        in {
            "localhost",
            "127.0.0.1",
        }
    ):
        errors.append("Set PUBLIC_URL to an HTTPS URL reachable by users in production")
    if (
        proxy_public_url.scheme != "https"
        or not proxy_public_url.netloc
        or not proxy_public_url.hostname
    ):
        errors.append("Set PROXY_PUBLIC_URL to a valid HTTPS URL in production")
    if (
        proxy_public_url.hostname
        and public_url.hostname
        and proxy_public_url.hostname.lower() == public_url.hostname.lower()
    ):
        errors.append("Set PROXY_PUBLIC_URL to a hostname distinct from PUBLIC_URL")
    if proxy_public_url.username is not None or proxy_public_url.password is not None:
        errors.append("Remove credentials from PROXY_PUBLIC_URL")
    if proxy_public_url.path not in {"", "/"} or proxy_public_url.params:
        errors.append("Remove the path from PROXY_PUBLIC_URL")
    if proxy_public_url.query:
        errors.append("Remove the query string from PROXY_PUBLIC_URL")
    if proxy_public_url.fragment:
        errors.append("Remove the fragment from PROXY_PUBLIC_URL")
    if settings.proxy_grant_ttl_seconds <= 0:
        errors.append("Set PROXY_GRANT_TTL_SECONDS to a positive value")
    elif settings.proxy_grant_ttl_seconds > MAX_PROXY_GRANT_TTL_SECONDS:
        errors.append(
            f"Set PROXY_GRANT_TTL_SECONDS to {MAX_PROXY_GRANT_TTL_SECONDS} or less"
        )
    if settings.proxy_session_ttl_minutes <= 0:
        errors.append("Set PROXY_SESSION_TTL_MINUTES to a positive value")
    elif settings.proxy_session_ttl_minutes > MAX_PROXY_SESSION_TTL_MINUTES:
        errors.append(
            f"Set PROXY_SESSION_TTL_MINUTES to {MAX_PROXY_SESSION_TTL_MINUTES} or less"
        )
    if settings.connector_session_ttl_minutes <= 0:
        errors.append("Set CONNECTOR_SESSION_TTL_MINUTES to a positive value")
    elif (
        settings.connector_session_ttl_minutes
        > MAX_CONNECTOR_SESSION_TTL_MINUTES
    ):
        errors.append(
            f"Set CONNECTOR_SESSION_TTL_MINUTES to {MAX_CONNECTOR_SESSION_TTL_MINUTES} or less"
        )
    if not 1 <= settings.connector_local_port <= 65535:
        errors.append("Set CONNECTOR_LOCAL_PORT to a valid TCP port")
    if not 1 <= settings.connector_max_connections <= 64:
        errors.append("Set CONNECTOR_MAX_CONNECTIONS between 1 and 64")
    if not 1 <= settings.connector_upstream_connect_timeout_seconds <= 60:
        errors.append(
            "Set CONNECTOR_UPSTREAM_CONNECT_TIMEOUT_SECONDS between 1 and 60"
        )
    if not (
        1
        <= settings.connector_connection_max_seconds
        <= MAX_CONNECTOR_CONNECTION_SECONDS
    ):
        errors.append(
            f"Set CONNECTOR_CONNECTION_MAX_SECONDS between 1 and {MAX_CONNECTOR_CONNECTION_SECONDS}"
        )
    if not 1 <= settings.connector_authorization_recheck_seconds <= 60:
        errors.append("Set CONNECTOR_AUTHORIZATION_RECHECK_SECONDS between 1 and 60")
    if settings.public_l4_relay_enabled:
        if not settings.public_l4_relay_mtls_required:
            errors.append(
                "Set PUBLIC_L4_RELAY_MTLS_REQUIRED=true only after every OPNsense WebGUI enforces client certificates"
            )
        if not settings.public_l4_relay_bind_host.strip():
            errors.append("Set PUBLIC_L4_RELAY_BIND_HOST")
        if not 1024 <= settings.public_l4_relay_port_min <= 65535:
            errors.append("Set PUBLIC_L4_RELAY_PORT_MIN to an unprivileged TCP port")
        if not 1024 <= settings.public_l4_relay_port_max <= 65535:
            errors.append("Set PUBLIC_L4_RELAY_PORT_MAX to an unprivileged TCP port")
        if settings.public_l4_relay_port_min > settings.public_l4_relay_port_max:
            errors.append("Set PUBLIC_L4_RELAY_PORT_MIN no higher than the maximum")
        if not 1 <= settings.public_l4_relay_ttl_seconds <= MAX_PUBLIC_L4_RELAY_TTL_SECONDS:
            errors.append(
                f"Set PUBLIC_L4_RELAY_TTL_SECONDS between 1 and {MAX_PUBLIC_L4_RELAY_TTL_SECONDS}"
            )
        if not 1 <= settings.public_l4_relay_idle_timeout_seconds <= settings.public_l4_relay_ttl_seconds:
            errors.append(
                "Set PUBLIC_L4_RELAY_IDLE_TIMEOUT_SECONDS between 1 and the relay TTL"
            )
        if not 1 <= settings.public_l4_relay_max_connections <= 64:
            errors.append("Set PUBLIC_L4_RELAY_MAX_CONNECTIONS between 1 and 64")
    if (
        proxy_public_url.hostname
        and proxy_public_url.hostname.lower()
        not in _configured_allowed_hosts(settings)
    ):
        errors.append("Add the PROXY_PUBLIC_URL host to ALLOWED_HOSTS")
    if (
        not settings.proxy_verify_tls
        and not settings.allow_insecure_proxy_tls_in_production
    ):
        errors.append(
            "Set PROXY_VERIFY_TLS=true in production or explicitly set ALLOW_INSECURE_PROXY_TLS_IN_PRODUCTION=true"
        )
    if settings.rate_limit_backend.strip().lower() not in {"memory", "redis", "edge"}:
        errors.append("Set RATE_LIMIT_BACKEND to memory, redis, or edge")
    if settings.rate_limit_memory_max_buckets <= 0:
        errors.append("Set RATE_LIMIT_MEMORY_MAX_BUCKETS to a positive value")
    if settings.network_control_mode.strip().lower() not in {"inline", "external"}:
        errors.append("Set NETWORK_CONTROL_MODE to inline or external")
    if settings.wg_agent_url and not settings.wg_agent_token:
        errors.append("Set WG_AGENT_TOKEN when WG_AGENT_URL is configured")
    if settings.wg_agent_token and (
        len(settings.wg_agent_token) < 32
        or "change-me" in settings.wg_agent_token.lower()
        or "development-only" in settings.wg_agent_token.lower()
    ):
        errors.append("Set WG_AGENT_TOKEN to a random value at least 32 characters long")
    if settings.wg_agent_url and settings.wg_agent_mode:
        errors.append("Do not set WG_AGENT_URL inside the WireGuard agent process")
    if settings.rate_limit_backend.strip().lower() == "memory":
        errors.append("Set RATE_LIMIT_BACKEND to redis or edge in production")
    if (
        settings.rate_limit_backend.strip().lower() == "redis"
        and not settings.rate_limit_redis_url
    ):
        errors.append("Set RATE_LIMIT_REDIS_URL when RATE_LIMIT_BACKEND=redis")
    if (
        public_url.hostname
        and public_url.hostname.lower() not in _configured_allowed_hosts(settings)
    ):
        errors.append("Add the PUBLIC_URL host to ALLOWED_HOSTS")
    if settings.trusted_proxy_cidrs.strip() and not _trusted_proxy_networks(settings):
        errors.append("TRUSTED_PROXY_CIDRS contains no valid proxy networks")
    if settings.log_retention_sweep_interval_hours <= 0:
        errors.append("Set LOG_RETENTION_SWEEP_INTERVAL_HOURS to a positive value")
    elif (
        settings.log_retention_sweep_interval_hours
        > MAX_LOG_RETENTION_SWEEP_INTERVAL_HOURS
    ):
        errors.append(
            f"Set LOG_RETENTION_SWEEP_INTERVAL_HOURS to {MAX_LOG_RETENTION_SWEEP_INTERVAL_HOURS} or less"
        )
    if settings.log_retention_delete_batch_size <= 0:
        errors.append("Set LOG_RETENTION_DELETE_BATCH_SIZE to a positive value")
    elif settings.log_retention_delete_batch_size > MAX_LOG_RETENTION_DELETE_BATCH_SIZE:
        errors.append(
            f"Set LOG_RETENTION_DELETE_BATCH_SIZE to {MAX_LOG_RETENTION_DELETE_BATCH_SIZE} or less"
        )
    if settings.audit_device_view_throttle_minutes <= 0:
        errors.append("Set AUDIT_DEVICE_VIEW_THROTTLE_MINUTES to a positive value")
    if settings.audit_log_min_retention_days <= 0:
        errors.append("Set AUDIT_LOG_MIN_RETENTION_DAYS to a positive value")
    if settings.device_event_min_retention_days <= 0:
        errors.append("Set DEVICE_EVENT_MIN_RETENTION_DAYS to a positive value")
    if settings.log_retention_enabled and (
        settings.audit_log_retention_days < settings.audit_log_min_retention_days
    ):
        errors.append(
            f"Set AUDIT_LOG_RETENTION_DAYS to at least {settings.audit_log_min_retention_days}"
        )
    if settings.log_retention_enabled and (
        settings.device_event_retention_days < settings.device_event_min_retention_days
    ):
        errors.append(
            f"Set DEVICE_EVENT_RETENTION_DAYS to at least {settings.device_event_min_retention_days}"
        )
    errors.extend(isolation_invariant_errors(settings))
    return errors


def validate_runtime_settings(settings: Settings) -> None:
    errors = runtime_validation_errors(settings)
    if not errors:
        return
    message = "; ".join(errors)
    if is_production(settings):
        raise StartupHardeningError(message)
    logger.warning("Insecure development defaults detected: %s", message)


def should_fail_closed(settings: Settings) -> bool:
    return is_production(settings) and not settings.wg_dry_run


def run_command(args: list[str]) -> CommandResult:
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=(completed.stdout or "").strip(),
        stderr=(completed.stderr or "").strip(),
    )


def ensure_command_ok(result: CommandResult, args: list[str]) -> None:
    if result.returncode == 0:
        return
    detail = result.stderr or result.stdout or "unknown error"
    raise StartupHardeningError(f"{' '.join(args)} failed: {detail}")


def configure_ip_forwarding(settings: Settings, runner=run_command) -> None:
    if settings.network_control_mode.strip().lower() == "external":
        logger.info(
            "Skipping IP forwarding changes because NETWORK_CONTROL_MODE=external"
        )
        return
    if settings.hub_enable_ip_forwarding:
        logger.warning(
            "HUB_ENABLE_IP_FORWARDING=true: kernel forwarding remains enabled, but managed policy still drops every forwarded packet originating from %s",
            settings.wg_interface,
        )
        return
    commands = [
        ["sysctl", "-w", "net.ipv4.ip_forward=0"],
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"],
    ]
    for args in commands:
        try:
            ensure_command_ok(runner(args), args)
        except Exception as exc:
            if should_fail_closed(settings):
                raise StartupHardeningError(
                    f"Failed to disable IP forwarding: {exc}"
                ) from exc
            logger.warning("Failed to disable IP forwarding: %s", exc)
            return
    logger.info("Disabled IPv4 and IPv6 forwarding inside the Hub runtime")


NFT_FORWARD_DROP_RULE = 'iifname "{iface}" counter drop'
NFT_INPUT_ESTABLISHED_RULE = (
    'iifname "{iface}" ct state established,related counter accept'
)
NFT_INPUT_CONTROL_RULE = (
    'iifname "{iface}" ip saddr {network} ip daddr {hub_ip} '
    "tcp dport {port} ct state new counter accept"
)
NFT_INPUT_DROP_RULE = 'iifname "{iface}" counter drop'
IPTABLES_INPUT_CHAIN = "OPNHUB_INPUT"
IPTABLES_INPUT6_CHAIN = "OPNHUB_INPUT6"
IPTABLES_FORWARD_CHAIN = "OPNHUB_FORWARD"


def _wireguard_rule_context(
    settings: Settings,
) -> tuple[str, ipaddress.IPv4Network, ipaddress.IPv4Address, int]:
    try:
        network = ipaddress.ip_network(settings.hub_wg_cidr, strict=False)
        hub_interface = ipaddress.ip_interface(settings.hub_wg_address)
    except ValueError as exc:
        raise StartupHardeningError(
            "HUB_WG_CIDR and HUB_WG_ADDRESS must be valid before installing isolation rules"
        ) from exc
    if not isinstance(network, ipaddress.IPv4Network) or not isinstance(
        hub_interface, ipaddress.IPv4Interface
    ):
        raise StartupHardeningError("Hub WireGuard isolation currently requires IPv4")
    if hub_interface.ip not in network:
        raise StartupHardeningError("HUB_WG_ADDRESS must be inside HUB_WG_CIDR")
    if not 1 <= settings.hub_control_plane_port <= 65535:
        raise StartupHardeningError("HUB_CONTROL_PLANE_PORT must be a valid TCP port")
    return (
        settings.wg_interface,
        network,
        hub_interface.ip,
        settings.hub_control_plane_port,
    )


def _normalized_nft_rule_output(value: str) -> str:
    return re.sub(r"counter(?: packets \d+ bytes \d+)?", "counter", value)


def verify_nftables_rule_present(settings: Settings, runner=run_command) -> None:
    iface, network, hub_ip, port = _wireguard_rule_context(settings)
    input_args = ["nft", "list", "chain", "inet", "opnsense_hub", "input"]
    forward_args = ["nft", "list", "chain", "inet", "opnsense_hub", "forward"]
    input_result = runner(input_args)
    forward_result = runner(forward_args)
    ensure_command_ok(input_result, input_args)
    ensure_command_ok(forward_result, forward_args)
    input_text = _normalized_nft_rule_output(
        f"{input_result.stdout}\n{input_result.stderr}"
    )
    forward_text = _normalized_nft_rule_output(
        f"{forward_result.stdout}\n{forward_result.stderr}"
    )
    required_input_rules = (
        NFT_INPUT_ESTABLISHED_RULE.format(iface=iface),
        NFT_INPUT_CONTROL_RULE.format(
            iface=iface, network=network, hub_ip=hub_ip, port=port
        ),
        NFT_INPUT_DROP_RULE.format(iface=iface),
    )
    if any(rule not in input_text for rule in required_input_rules):
        raise StartupHardeningError(
            f"Hub tunnel input policy for {iface} is incomplete after installation"
        )
    if NFT_FORWARD_DROP_RULE.format(iface=iface) not in forward_text:
        raise StartupHardeningError(
            f"Hub forwarding default-drop rule for {iface} is missing after installation"
        )


def _iptables_input_rules(settings: Settings) -> list[list[str]]:
    iface, network, hub_ip, port = _wireguard_rule_context(settings)
    return [
        [
            "-i",
            iface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        [
            "-i",
            iface,
            "-s",
            str(network),
            "-d",
            f"{hub_ip}/32",
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-j",
            "ACCEPT",
        ],
        ["-i", iface, "-j", "DROP"],
    ]


def _ip6tables_input_rules(iface: str) -> list[list[str]]:
    return [
        [
            "-i",
            iface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        ["-i", iface, "-j", "DROP"],
    ]


def verify_iptables_rule_present(settings: Settings, runner=run_command) -> None:
    iface, _network, _hub_ip, _port = _wireguard_rule_context(settings)
    checks = [
        ["iptables", "-C", "INPUT", "-i", iface, "-j", IPTABLES_INPUT_CHAIN],
        *(
            ["iptables", "-C", IPTABLES_INPUT_CHAIN, *rule]
            for rule in _iptables_input_rules(settings)
        ),
        [
            "iptables",
            "-C",
            "FORWARD",
            "-i",
            iface,
            "-j",
            IPTABLES_FORWARD_CHAIN,
        ],
        ["iptables", "-C", IPTABLES_FORWARD_CHAIN, "-j", "DROP"],
        ["ip6tables", "-C", "INPUT", "-i", iface, "-j", IPTABLES_INPUT6_CHAIN],
        *(
            ["ip6tables", "-C", IPTABLES_INPUT6_CHAIN, *rule]
            for rule in _ip6tables_input_rules(iface)
        ),
        ["ip6tables", "-C", "FORWARD", "-i", iface, "-j", "DROP"],
    ]
    for args in checks:
        ensure_command_ok(runner(args), args)


def install_nftables_rules(settings: Settings, runner=run_command) -> None:
    iface, network, hub_ip, port = _wireguard_rule_context(settings)
    table_args = ["nft", "list", "table", "inet", "opnsense_hub"]
    if runner(table_args).returncode == 0:
        delete_args = ["nft", "delete", "table", "inet", "opnsense_hub"]
        ensure_command_ok(runner(delete_args), delete_args)
    add_table_args = ["nft", "add", "table", "inet", "opnsense_hub"]
    ensure_command_ok(runner(add_table_args), add_table_args)
    for chain, hook in (("input", "input"), ("forward", "forward")):
        args = [
            "nft",
            "add",
            "chain",
            "inet",
            "opnsense_hub",
            chain,
            "{",
            "type",
            "filter",
            "hook",
            hook,
            "priority",
            "-100",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ]
        ensure_command_ok(runner(args), args)
    rules = [
        [
            "nft",
            "add",
            "rule",
            "inet",
            "opnsense_hub",
            "input",
            "iifname",
            iface,
            "ct",
            "state",
            "established,related",
            "counter",
            "accept",
        ],
        [
            "nft",
            "add",
            "rule",
            "inet",
            "opnsense_hub",
            "input",
            "iifname",
            iface,
            "ip",
            "saddr",
            str(network),
            "ip",
            "daddr",
            str(hub_ip),
            "tcp",
            "dport",
            str(port),
            "ct",
            "state",
            "new",
            "counter",
            "accept",
        ],
        [
            "nft",
            "add",
            "rule",
            "inet",
            "opnsense_hub",
            "input",
            "iifname",
            iface,
            "counter",
            "drop",
        ],
        [
            "nft",
            "add",
            "rule",
            "inet",
            "opnsense_hub",
            "forward",
            "iifname",
            iface,
            "counter",
            "drop",
        ],
    ]
    for args in rules:
        ensure_command_ok(runner(args), args)


def _ensure_iptables_chain(
    command: str, chain: str, runner=run_command
) -> None:
    if runner([command, "-L", chain, "-n"]).returncode != 0:
        create_args = [command, "-N", chain]
        ensure_command_ok(runner(create_args), create_args)
    flush_args = [command, "-F", chain]
    ensure_command_ok(runner(flush_args), flush_args)


def _install_iptables_jump(
    parent_chain: str,
    iface: str,
    target_chain: str,
    runner=run_command,
    command: str = "iptables",
) -> None:
    check_args = [
        command,
        "-C",
        parent_chain,
        "-i",
        iface,
        "-j",
        target_chain,
    ]
    if runner(check_args).returncode == 0:
        delete_args = [
            command,
            "-D",
            parent_chain,
            "-i",
            iface,
            "-j",
            target_chain,
        ]
        ensure_command_ok(runner(delete_args), delete_args)
    insert_args = [
        command,
        "-I",
        parent_chain,
        "1",
        "-i",
        iface,
        "-j",
        target_chain,
    ]
    ensure_command_ok(runner(insert_args), insert_args)


def install_iptables_rules(settings: Settings, runner=run_command) -> None:
    iface, _network, _hub_ip, _port = _wireguard_rule_context(settings)
    _ensure_iptables_chain("iptables", IPTABLES_INPUT_CHAIN, runner=runner)
    _ensure_iptables_chain("iptables", IPTABLES_FORWARD_CHAIN, runner=runner)
    _ensure_iptables_chain("ip6tables", IPTABLES_INPUT6_CHAIN, runner=runner)
    for rule in _iptables_input_rules(settings):
        args = ["iptables", "-A", IPTABLES_INPUT_CHAIN, *rule]
        ensure_command_ok(runner(args), args)
    for rule in _ip6tables_input_rules(iface):
        args = ["ip6tables", "-A", IPTABLES_INPUT6_CHAIN, *rule]
        ensure_command_ok(runner(args), args)
    forward_drop_args = ["iptables", "-A", IPTABLES_FORWARD_CHAIN, "-j", "DROP"]
    ensure_command_ok(runner(forward_drop_args), forward_drop_args)
    _install_iptables_jump("INPUT", iface, IPTABLES_INPUT_CHAIN, runner=runner)
    _install_iptables_jump("FORWARD", iface, IPTABLES_FORWARD_CHAIN, runner=runner)
    _install_iptables_jump(
        "INPUT",
        iface,
        IPTABLES_INPUT6_CHAIN,
        runner=runner,
        command="ip6tables",
    )
    check_args = ["ip6tables", "-C", "FORWARD", "-i", iface, "-j", "DROP"]
    if runner(check_args).returncode != 0:
        insert_args = [
            "ip6tables",
            "-I",
            "FORWARD",
            "1",
            "-i",
            iface,
            "-j",
            "DROP",
        ]
        ensure_command_ok(runner(insert_args), insert_args)


def verify_firewall_rules_present(
    settings: Settings,
    runner=run_command,
    which=shutil.which,
) -> None:
    if which("nft"):
        verify_nftables_rule_present(settings, runner=runner)
        return
    if which("iptables") and which("ip6tables"):
        verify_iptables_rule_present(settings, runner=runner)
        return
    raise StartupHardeningError(
        "Neither nftables nor the complete iptables/ip6tables toolset is available to verify Hub isolation rules"
    )


def install_firewall_rules(
    settings: Settings,
    runner=run_command,
    which=shutil.which,
) -> None:
    if settings.network_control_mode.strip().lower() == "external":
        logger.info("Skipping Hub firewall rules because NETWORK_CONTROL_MODE=external")
        return
    if not settings.hub_manage_firewall_rules:
        logger.info(
            "Skipping Hub firewall rules because HUB_MANAGE_FIREWALL_RULES=false"
        )
        return
    if settings.wg_dry_run:
        logger.info("Skipping Hub firewall rules because WG_DRY_RUN=true")
        return
    try:
        if which("nft"):
            install_nftables_rules(settings, runner=runner)
            verify_firewall_rules_present(settings, runner=runner, which=which)
            logger.info(
                "Installed and verified nftables tunnel isolation policy for %s",
                settings.wg_interface,
            )
            return
        if which("iptables") and which("ip6tables"):
            install_iptables_rules(settings, runner=runner)
            verify_firewall_rules_present(settings, runner=runner, which=which)
            logger.info(
                "Installed and verified iptables/ip6tables tunnel isolation policy for %s",
                settings.wg_interface,
            )
            return
        raise StartupHardeningError(
            "Neither nftables nor the complete iptables/ip6tables toolset is available to install Hub isolation rules"
        )
    except Exception as exc:
        if should_fail_closed(settings):
            raise StartupHardeningError(
                f"Failed to install Hub firewall rules: {exc}"
            ) from exc
        logger.warning("Failed to install Hub firewall rules: %s", exc)


def apply_startup_hardening(settings: Settings) -> None:
    validate_runtime_settings(settings)
    if settings.wg_agent_url and not settings.wg_agent_mode:
        logger.info(
            "Skipping privileged network hardening in web process; WireGuard agent is configured"
        )
        return
    configure_ip_forwarding(settings)
    install_firewall_rules(settings)
