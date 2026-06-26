#!/usr/local/bin/python3
"""Stop the local OPNsense Hub WireGuard tunnel without deleting enrollment."""

import json
import subprocess

from connect import STATE_FILE, WG_IFACE, remove_heartbeat_cron


def main():
    state = {}
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
        except Exception:
            state = {}
    subprocess.run(
        ["ifconfig", WG_IFACE, "destroy"], capture_output=True, text=True, timeout=10
    )
    remove_heartbeat_cron()
    state["status"] = "disconnected"
    if STATE_FILE.parent.exists():
        STATE_FILE.write_text(json.dumps(state, indent=2))
    print(json.dumps({"status": "disconnected", "device_id": state.get("device_id")}))


if __name__ == "__main__":
    main()
