#!/usr/local/bin/python3
import json
import socket
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from connect import license_metadata

STATE_FILE = Path("/var/db/opnsensehub/state.json")


def opnsense_version():
    try:
        result = subprocess.run(
            ["opnsense-version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def main():
    if not STATE_FILE.exists():
        print(json.dumps({"status": "error", "message": "not enrolled"}))
        sys.exit(1)
    state = json.loads(STATE_FILE.read_text())
    payload = {
        "status": "online",
        "hostname": socket.gethostname(),
        "opnsense_version": opnsense_version(),
        "tunnel_ip": state.get("tunnel_ip"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **license_metadata(),
    }
    url = (
        state["hub_url"].rstrip("/")
        + "/api/v1/devices/"
        + state["device_id"]
        + "/heartbeat"
    )
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + state["device_token"],
            "User-Agent": "os-opnsensehub/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = json.loads(response.read().decode("utf-8"))
        state["status"] = "online"
        state["last_heartbeat"] = payload["timestamp"]
        STATE_FILE.write_text(json.dumps(state, indent=2))
        print(json.dumps({"status": "ok", "hub_response": body}))
    except Exception:
        print(json.dumps({"status": "error", "message": "heartbeat failed"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
