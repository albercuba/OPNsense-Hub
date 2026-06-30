import logging
import shutil
import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse

from .config import Settings
from .security import password_is_strong_enough

MAX_LOG_RETENTION_DELETE_BATCH_SIZE = 20000
MAX_LOG_RETENTION_SWEEP_INTERVAL_HOURS = 720

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


def runtime_validation_errors(settings: Settings) -> list[str]:
    errors: list[str] = []
    public_url = urlparse(settings.public_url)

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
        not settings.proxy_verify_tls
        and not settings.allow_insecure_proxy_tls_in_production
    ):
        errors.append(
            "Set PROXY_VERIFY_TLS=true in production or explicitly set ALLOW_INSECURE_PROXY_TLS_IN_PRODUCTION=true"
        )
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
    if settings.hub_enable_ip_forwarding:
        logger.warning(
            "HUB_ENABLE_IP_FORWARDING=true: routing between tunnel peers must be controlled externally"
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


NFT_DROP_RULE = 'iifname "{iface}" oifname "{iface}" counter drop'


def install_nftables_rules(settings: Settings, runner=run_command) -> None:
    iface = settings.wg_interface
    table_args = ["nft", "list", "table", "inet", "opnsense_hub"]
    if runner(table_args).returncode != 0:
        ensure_command_ok(
            runner(["nft", "add", "table", "inet", "opnsense_hub"]),
            ["nft", "add", "table", "inet", "opnsense_hub"],
        )
    chain_args = ["nft", "list", "chain", "inet", "opnsense_hub", "forward"]
    chain_result = runner(chain_args)
    if chain_result.returncode != 0:
        ensure_command_ok(
            runner(
                [
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    "opnsense_hub",
                    "forward",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "forward",
                    "priority",
                    "0",
                    ";",
                    "policy",
                    "accept",
                    ";",
                    "}",
                ]
            ),
            ["nft", "add", "chain", "inet", "opnsense_hub", "forward", "..."],
        )
        chain_result = runner(chain_args)
    rule_text = NFT_DROP_RULE.format(iface=iface)
    if rule_text not in f"{chain_result.stdout}\n{chain_result.stderr}":
        ensure_command_ok(
            runner(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "opnsense_hub",
                    "forward",
                    "iifname",
                    iface,
                    "oifname",
                    iface,
                    "counter",
                    "drop",
                ]
            ),
            ["nft", "add", "rule", "inet", "opnsense_hub", "forward", "..."],
        )


def install_iptables_rules(settings: Settings, runner=run_command) -> None:
    iface = settings.wg_interface
    check_args = ["iptables", "-C", "FORWARD", "-i", iface, "-o", iface, "-j", "DROP"]
    if runner(check_args).returncode == 0:
        return
    ensure_command_ok(
        runner(
            ["iptables", "-I", "FORWARD", "1", "-i", iface, "-o", iface, "-j", "DROP"]
        ),
        ["iptables", "-I", "FORWARD", "1", "-i", iface, "-o", iface, "-j", "DROP"],
    )


def install_firewall_rules(
    settings: Settings,
    runner=run_command,
    which=shutil.which,
) -> None:
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
            logger.info(
                "Installed nftables isolation rule for %s", settings.wg_interface
            )
            return
        if which("iptables"):
            install_iptables_rules(settings, runner=runner)
            logger.info(
                "Installed iptables isolation rule for %s", settings.wg_interface
            )
            return
        raise StartupHardeningError(
            "Neither nft nor iptables is available to install Hub isolation rules"
        )
    except Exception as exc:
        if should_fail_closed(settings):
            raise StartupHardeningError(
                f"Failed to install Hub firewall rules: {exc}"
            ) from exc
        logger.warning("Failed to install Hub firewall rules: %s", exc)


def apply_startup_hardening(settings: Settings) -> None:
    validate_runtime_settings(settings)
    configure_ip_forwarding(settings)
    install_firewall_rules(settings)
