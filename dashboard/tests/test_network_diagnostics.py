from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.models import Company, Device
from app.security import hash_secret
from app.services import network_diagnostics


class FakeDb:
    def scalars(self, _statement):
        return SimpleNamespace(all=lambda: [])

    def get(self, model, key):
        if model is Company and key == self.company.id:
            return self.company
        return None

    def __init__(self, company: Company):
        self.company = company


def make_device(company: Company) -> Device:
    return Device(
        id=uuid4(),
        company_id=company.id,
        hostname="fw-01",
        wg_public_key="pubkey",
        wg_tunnel_ip="100.96.0.10/32",
        device_token_hash=hash_secret("device-token"),
        status="online",
        plugin_version="0.1",
    )


def test_device_network_diagnostics_treats_missing_handshake_as_critical(monkeypatch):
    company = Company(id=uuid4(), name="Acme")
    device = make_device(company)
    db = FakeDb(company)
    runtime_peer = SimpleNamespace(
        public_key=device.wg_public_key,
        allowed_ips=["100.96.0.10/32"],
        last_handshake_at=None,
        endpoint="198.51.100.10:51820",
        rx_bytes=0,
        tx_bytes=0,
    )
    snapshot = network_diagnostics.RuntimePeerSnapshot(
        status="ok",
        interface="wg0",
        peers={device.wg_public_key: runtime_peer},
    )

    monkeypatch.setattr(network_diagnostics, "runtime_peer_snapshot", lambda: snapshot)
    monkeypatch.setattr(
        network_diagnostics, "expected_plugin_version", lambda: device.plugin_version
    )
    monkeypatch.setattr(
        network_diagnostics,
        "utc_now",
        lambda: datetime(2026, 7, 6, 15, 0, tzinfo=timezone.utc),
    )

    diagnostics = network_diagnostics.build_device_network_diagnostics(db, device)

    assert diagnostics["tunnel"]["state"] == "critical"
    assert diagnostics["tunnel"]["label"] == (
        "Peer present, but no recent handshake was observed"
    )
    assert diagnostics["tunnel"]["handshake_label"] == "No handshake observed"
    assert diagnostics["policy"]["state"] == "success"
