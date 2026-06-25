#!/usr/local/bin/python3
"""Remove local OPNsense Hub tunnel artifacts and integration state."""

import json
import subprocess

from connect import (
    KEY_FILE,
    STATE_FILE,
    WG_CONF,
    WG_IFACE,
    cleanup_opnsense_integration,
    hub_route_for,
)


def delete_path(path):
    try:
        if path.exists():
            path.unlink()
            return True
    except Exception:
        return False
    return False


def main():
    state = {}
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
        except Exception:
            state = {}

    wireguard = (
        state.get("wireguard") if isinstance(state.get("wireguard"), dict) else None
    )
    if wireguard:
        try:
            subprocess.run(
                ["route", "delete", "-host", hub_route_for(wireguard)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception:
            pass

    subprocess.run(
        ["ifconfig", WG_IFACE, "destroy"], capture_output=True, text=True, timeout=10
    )

    cleanup = cleanup_opnsense_integration()
    removed_files = {
        "wireguard_config": delete_path(WG_CONF),
        "private_key": delete_path(KEY_FILE),
        "state": delete_path(STATE_FILE),
    }

    print(
        json.dumps(
            {
                "status": "removed",
                "message": "Removed local OPNsense Hub tunnel, interface assignment, and state",
                "interface": cleanup.get("interface_key"),
                "config_changed": cleanup.get("config_changed", False),
                "removed_files": removed_files,
                "device_id": state.get("device_id"),
            }
        )
    )


if __name__ == "__main__":
    main()
