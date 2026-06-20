#!/usr/local/bin/python3
import json
import subprocess
from pathlib import Path

STATE_FILE = Path("/var/db/opnsensehub/state.json")
WG_CONF = Path("/usr/local/etc/wireguard/opnsensehub.conf")


def main():
    state = {}
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
        except Exception:
            state = {}
    tunnel = False
    try:
        result = subprocess.run(
            ["wg", "show"], capture_output=True, text=True, timeout=5
        )
        tunnel = result.returncode == 0 and "interface:" in result.stdout
    except Exception:
        tunnel = False
    status = state.get("status", "disconnected")
    if tunnel and status != "revoked":
        status = "connected"
    print(
        json.dumps(
            {
                "status": status,
                "device_id": state.get("device_id"),
                "tunnel_ip": state.get("tunnel_ip"),
                "wireguard_config": str(WG_CONF),
                "tunnel_running": tunnel,
            }
        )
    )


if __name__ == "__main__":
    main()
