from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import firmware_scheduler
from app import wireguard_agent


class FakeAgentProbeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "reachable": True,
            "message": "WebGUI reachable at https://100.96.0.2:443/",
        }


class FakeAgentProbeClient:
    def __init__(self):
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeAgentProbeResponse()


@pytest.mark.anyio
async def test_health_probe_delegates_to_wireguard_agent(monkeypatch):
    client = FakeAgentProbeClient()
    monkeypatch.setattr(
        firmware_scheduler.settings,
        "wg_agent_url",
        "http://opnsense-hub-wireguard:8084",
    )
    monkeypatch.setattr(firmware_scheduler.settings, "wg_agent_token", "a" * 32)
    monkeypatch.setattr(firmware_scheduler.settings, "opnsense_gui_port", 443)

    healthy, message = await firmware_scheduler.probe_device_webgui(
        client,
        SimpleNamespace(wg_tunnel_ip="100.96.0.2/32"),
    )

    assert healthy is True
    assert message == "WebGUI reachable at https://100.96.0.2:443/"
    assert client.calls == [
        (
            "http://opnsense-hub-wireguard:8084/probe-webgui",
            {
                "params": {"host": "100.96.0.2", "port": 443},
                "headers": {"Authorization": "Bearer " + "a" * 32},
            },
        )
    ]


@pytest.mark.anyio
async def test_wireguard_agent_probe_rejects_targets_outside_tunnel_cidr(monkeypatch):
    monkeypatch.setattr(wireguard_agent.settings, "hub_wg_cidr", "100.96.0.0/16")
    monkeypatch.setattr(wireguard_agent.settings, "opnsense_gui_port", 443)

    with pytest.raises(HTTPException) as exc_info:
        await wireguard_agent.probe_webgui("192.168.1.10", 443)

    assert exc_info.value.status_code == 400
    assert "outside HUB_WG_CIDR" in str(exc_info.value.detail)
