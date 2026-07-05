from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..config import get_settings
from ..hardening import isolation_invariant_errors, verify_nftables_rule_present
from ..models import AuditLog, Company, Device
from ..security import utc_now
from ..wireguard import (
    RuntimeWireGuardPeer,
    WireGuardError,
    client_allowed_ips,
    get_runtime_peers,
    peer_allowed_ips,
)

settings = get_settings()
logger = logging.getLogger(__name__)
EXPECTED_ENROLLMENT_FAILURE_ACTIONS = {
    "enrollment.invalid_payload",
    "enrollment.invalid_otp",
    "enrollment.peer_add_failed",
}
_PLUGIN_VERSION_RE = re.compile(r'^PLUGIN_VERSION\s*=\s*"([^"]+)"', re.MULTILINE)


@dataclass(frozen=True)
class RuntimePeerSnapshot:
    status: str
    interface: str
    peers: dict[str, RuntimeWireGuardPeer]
    error: str | None = None


def expected_plugin_version() -> str | None:
    root = Path(__file__).resolve().parents[3]
    plugin_file = (
        root
        / "net-mgmt"
        / "os-opnsensehub"
        / "src"
        / "opnsense"
        / "scripts"
        / "OPNsense"
        / "OPNsenseHub"
        / "connect.py"
    )
    try:
        match = _PLUGIN_VERSION_RE.search(plugin_file.read_text(encoding="utf-8"))
    except OSError:
        return None
    return match.group(1).strip() if match else None


def summarize_handshake_age(
    last_handshake_at: datetime | None, now: datetime | None = None
) -> tuple[str, str]:
    if last_handshake_at is None:
        return "critical", "No handshake observed"
    current = now or utc_now()
    age = current.astimezone(timezone.utc) - last_handshake_at.astimezone(timezone.utc)
    if age <= timedelta(minutes=5):
        return "success", f"Fresh {humanize_timedelta(age)} ago"
    if age <= timedelta(hours=1):
        return "warning", f"Stale {humanize_timedelta(age)} ago"
    return "critical", f"Old {humanize_timedelta(age)} ago"


def humanize_timedelta(delta: timedelta) -> str:
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def runtime_peer_snapshot() -> RuntimePeerSnapshot:
    try:
        peers = get_runtime_peers()
        status = "dry-run" if settings.wg_dry_run else "ok"
        return RuntimePeerSnapshot(
            status=status,
            interface=settings.wg_interface,
            peers={peer.public_key: peer for peer in peers},
        )
    except WireGuardError as exc:
        return RuntimePeerSnapshot(
            status="error",
            interface=settings.wg_interface,
            peers={},
            error=str(exc),
        )


def build_isolation_check() -> dict[str, Any]:
    issues = isolation_invariant_errors(settings)
    if issues:
        return {
            "state": "critical",
            "label": "Isolation risk",
            "summary": "Peer-to-peer firewall isolation has configuration issues that need review.",
            "details": list(issues),
        }

    mode = settings.network_control_mode.strip().lower()
    if mode == "external" or not settings.hub_manage_firewall_rules:
        return {
            "state": "warning",
            "label": "Externally enforced",
            "summary": "Peer-to-peer firewall isolation is expected to be enforced outside the app runtime.",
            "details": [
                "The container is not the source of truth for the isolation rule in this deployment model.",
                f"Expected policy still limits each firewall to its own tunnel /32 and the Hub route {client_allowed_ips()}.",
            ],
        }

    if settings.wg_dry_run:
        return {
            "state": "warning",
            "label": "Dry run",
            "summary": "WireGuard runtime checks are skipped because WG_DRY_RUN=true.",
            "details": [
                "Policy intent still restricts firewall reachability to tunnel /32 routes only."
            ],
        }

    runtime_error = None
    try:
        verify_nftables_rule_present(settings)
    except Exception as exc:  # pragma: no cover - defensive runtime check
        runtime_error = str(exc)
    if runtime_error:
        return {
            "state": "critical",
            "label": "Verification failed",
            "summary": "Peer-to-peer firewall isolation should be enforced by the app runtime, but runtime verification failed.",
            "details": [runtime_error],
        }

    return {
        "state": "success",
        "label": "Isolation verified",
        "summary": "No firewall should be able to reach another firewall through the Hub tunnel.",
        "details": [
            f"Inline isolation rule present on {settings.wg_interface}.",
            "Hub routes each firewall only to its own tunnel /32.",
            f"Firewall clients should route only the Hub tunnel IP {client_allowed_ips()}.",
        ],
    }


def _policy_summary(
    actual_allowed_ips: list[str], expected_device_route: str
) -> tuple[str, list[str]]:
    warnings: list[str] = []
    normalized_actual = sorted(ip.strip() for ip in actual_allowed_ips if ip.strip())
    if normalized_actual != [expected_device_route]:
        warnings.append(
            f"Hub peer route drift detected: expected {expected_device_route}, actual {', '.join(normalized_actual) or 'none'}"
        )
    return (
        "Only the firewall tunnel /32 should be reachable through the Hub overlay.",
        warnings,
    )


def build_device_network_diagnostics(db: Session, device: Device) -> dict[str, Any]:
    try:
        now = utc_now()
        snapshot = runtime_peer_snapshot()
        runtime_peer = snapshot.peers.get(device.wg_public_key)
        expected_device_route = peer_allowed_ips(str(device.wg_tunnel_ip))
        actual_allowed_ips = runtime_peer.allowed_ips if runtime_peer else []
        policy_summary, policy_warnings = _policy_summary(
            actual_allowed_ips,
            expected_device_route,
        )
        plugin_expected = expected_plugin_version()
        plugin_actual = (device.plugin_version or "").strip() or None
        plugin_ok = (
            plugin_expected is None
            or plugin_actual is None
            or plugin_actual == plugin_expected
        )
        handshake_state, handshake_label = summarize_handshake_age(
            runtime_peer.last_handshake_at if runtime_peer else None,
            now,
        )
        if snapshot.status == "error":
            tunnel_state = "warning"
            tunnel_label = snapshot.error or "WireGuard runtime unavailable"
        elif snapshot.status == "dry-run":
            tunnel_state = "warning"
            tunnel_label = "WireGuard runtime checks are disabled in dry run mode"
        elif runtime_peer is None:
            tunnel_state = "critical"
            tunnel_label = "Peer missing from the Hub WireGuard runtime"
        else:
            tunnel_state = "success"
            tunnel_label = "Peer present in the Hub WireGuard runtime"

        recent_enrollment_logs = list(
            db.scalars(
                select(AuditLog)
                .where(
                    AuditLog.company_id == device.company_id,
                    AuditLog.action.in_(EXPECTED_ENROLLMENT_FAILURE_ACTIONS),
                )
                .order_by(AuditLog.created_at.desc())
                .limit(10)
            ).all()
        )
        enrollment_diagnostics = [
            {
                "created_at": entry.created_at,
                "action": entry.action,
                "summary": enrollment_failure_summary(entry.action),
                "ip_address": entry.ip_address,
            }
            for entry in recent_enrollment_logs
        ]
        reachability_hint = None
        if (
            runtime_peer
            and runtime_peer.last_handshake_at is None
            and device.last_seen_at
        ):
            reachability_hint = "Heartbeat exists but no recent WireGuard handshake was observed; confirm endpoint reachability and peer state."
        elif not device.last_seen_at:
            reachability_hint = "This firewall has not reported a heartbeat yet. Verify enrollment, endpoint DNS, and tunnel reachability."

        return {
            "tunnel": {
                "state": tunnel_state,
                "label": tunnel_label,
                "runtime_status": snapshot.status,
                "interface": snapshot.interface,
                "endpoint": runtime_peer.endpoint if runtime_peer else None,
                "last_handshake_at": runtime_peer.last_handshake_at
                if runtime_peer
                else None,
                "handshake_state": handshake_state,
                "handshake_label": handshake_label,
                "rx_bytes": runtime_peer.rx_bytes if runtime_peer else None,
                "tx_bytes": runtime_peer.tx_bytes if runtime_peer else None,
            },
            "policy": {
                "summary": policy_summary,
                "expected_device_route": expected_device_route,
                "expected_firewall_route": client_allowed_ips(),
                "actual_allowed_ips": actual_allowed_ips,
                "warnings": policy_warnings,
                "state": "critical" if policy_warnings else "success",
            },
            "plugin": {
                "expected": plugin_expected,
                "actual": plugin_actual,
                "state": "success" if plugin_ok else "warning",
                "label": (
                    "Plugin version matches"
                    if plugin_ok
                    else f"Plugin version mismatch: device={plugin_actual or 'unknown'}, expected={plugin_expected or 'unknown'}"
                ),
            },
            "enrollment_diagnostics": enrollment_diagnostics,
            "reachability_hint": reachability_hint,
        }
    except Exception as exc:  # pragma: no cover - runtime safety net
        logger.exception("Failed to build device network diagnostics")
        return {
            "tunnel": {
                "state": "warning",
                "label": "Network diagnostics unavailable",
                "runtime_status": "error",
                "interface": settings.wg_interface,
                "endpoint": None,
                "last_handshake_at": None,
                "handshake_state": "warning",
                "handshake_label": str(exc),
                "rx_bytes": None,
                "tx_bytes": None,
            },
            "policy": {
                "summary": "Network policy simulation is temporarily unavailable.",
                "expected_device_route": str(device.wg_tunnel_ip),
                "expected_firewall_route": "Unavailable",
                "actual_allowed_ips": [],
                "warnings": [str(exc)],
                "state": "warning",
            },
            "plugin": {
                "expected": expected_plugin_version(),
                "actual": (device.plugin_version or "").strip() or None,
                "state": "warning",
                "label": "Network diagnostics could not be computed",
            },
            "enrollment_diagnostics": [],
            "reachability_hint": str(exc),
        }


def enrollment_failure_summary(action: str) -> str:
    return {
        "enrollment.invalid_payload": "Missing otp, hostname, or WireGuard public key",
        "enrollment.invalid_otp": "Invalid or expired enrollment code",
        "enrollment.peer_add_failed": "Hub failed to add the WireGuard peer",
    }.get(action, action)


def _company_name(db: Session, company_id: Any) -> str:
    if not company_id:
        return "Unknown"
    company = db.get(Company, company_id)
    return company.name if company is not None else "Unknown"


def build_network_settings_context(db: Session) -> dict[str, Any]:
    try:
        devices = list(
            db.scalars(
                select(Device)
                .options(selectinload(Device.company))
                .join(Company)
                .where(Device.revoked_at.is_(None))
                .order_by(Company.name, Device.hostname)
            ).all()
        )
        snapshot = runtime_peer_snapshot()
        now = utc_now()
        rows: list[dict[str, Any]] = []
        for device in devices:
            peer = snapshot.peers.get(device.wg_public_key)
            expected_route = peer_allowed_ips(str(device.wg_tunnel_ip))
            actual_allowed_ips = peer.allowed_ips if peer else []
            drift = actual_allowed_ips != [expected_route]
            handshake_state, handshake_label = summarize_handshake_age(
                peer.last_handshake_at if peer else None,
                now,
            )
            rows.append(
                {
                    "device": device,
                    "company_name": device.company.name
                    if device.company
                    else "Unknown",
                    "peer_present": peer is not None,
                    "endpoint": peer.endpoint if peer else None,
                    "expected_route": expected_route,
                    "actual_allowed_ips": actual_allowed_ips,
                    "assigned_ip": str(device.wg_tunnel_ip),
                    "last_handshake_at": peer.last_handshake_at if peer else None,
                    "handshake_state": handshake_state,
                    "handshake_label": handshake_label,
                    "policy_state": "critical" if drift else "success",
                    "policy_label": "Drift detected" if drift else "As expected",
                    "rx_bytes": peer.rx_bytes if peer else None,
                    "tx_bytes": peer.tx_bytes if peer else None,
                }
            )
        enrollment_logs = list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.action.in_(EXPECTED_ENROLLMENT_FAILURE_ACTIONS))
                .order_by(AuditLog.created_at.desc())
                .limit(25)
            ).all()
        )
        plugin_expected = expected_plugin_version()
        return {
            "isolation_check": build_isolation_check(),
            "wireguard_runtime": {
                "status": snapshot.status,
                "interface": snapshot.interface,
                "error": snapshot.error,
                "peer_count": len(snapshot.peers),
                "rows": rows,
            },
            "enrollment_logs": [
                {
                    "created_at": entry.created_at,
                    "company_name": _company_name(db, entry.company_id),
                    "summary": enrollment_failure_summary(entry.action),
                    "action": entry.action,
                    "ip_address": entry.ip_address,
                }
                for entry in enrollment_logs
            ],
            "plugin_expected": plugin_expected,
        }
    except Exception as exc:  # pragma: no cover - runtime safety net
        logger.exception("Failed to build network settings context")
        return {
            "isolation_check": {
                "state": "warning",
                "label": "Network diagnostics unavailable",
                "summary": "The Network page could not compute diagnostics for this environment.",
                "details": [str(exc)],
            },
            "wireguard_runtime": {
                "status": "error",
                "interface": settings.wg_interface,
                "error": str(exc),
                "peer_count": 0,
                "rows": [],
            },
            "enrollment_logs": [],
            "plugin_expected": expected_plugin_version(),
        }
