#!/usr/local/bin/python3
import json
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from connect import PLUGIN_VERSION, license_metadata, load_state, save_state
from firmware_status import collect_firmware_status
from remove import remove_local_artifacts

STATE_FILE = Path("/var/db/opnsensehub/state.json")
CONFIG_XML = Path("/conf/config.xml")


def opnsense_version():
    try:
        import subprocess

        result = subprocess.run(
            ["opnsense-version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def heartbeat_timestamp():
    return datetime.now(timezone.utc).isoformat()


def heartbeat_payload(state, firmware=None):
    payload = {
        "status": "online",
        "hostname": socket.gethostname(),
        "opnsense_version": opnsense_version(),
        "plugin_version": PLUGIN_VERSION,
        "timestamp": heartbeat_timestamp(),
        **license_metadata(),
    }
    if firmware is not None:
        payload["firmware"] = firmware
    return payload


def heartbeat_url(state):
    return (
        state["hub_url"].rstrip("/")
        + "/api/v1/devices/"
        + state["device_id"]
        + "/heartbeat"
    )


def send_heartbeat(state, payload):
    req = urllib.request.Request(
        heartbeat_url(state),
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + state["device_token"],
            "User-Agent": "os-opnsensehub/0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        body = json.loads(response.read().decode("utf-8"))
    state["status"] = "online"
    state["last_heartbeat"] = payload["timestamp"]
    state["last_error"] = ""
    save_state(state)
    return body


def request_firmware_check_pending(body):
    return bool(body.get("firmware_check_requested"))


def backup_request_pending(body):
    return bool(body.get("backup_requested"))


def upload_backup(state):
    if not CONFIG_XML.exists():
        raise FileNotFoundError("config.xml not found")
    created_at = heartbeat_timestamp()
    filename = (
        socket.gethostname().replace(" ", "-")
        + "-"
        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        + ".xml"
    )
    req = urllib.request.Request(
        state["hub_url"].rstrip("/")
        + "/api/v1/devices/"
        + state["device_id"]
        + "/backups",
        data=json.dumps(
            {
                "filename": filename,
                "created_at": created_at,
                "content": CONFIG_XML.read_text(),
            }
        ).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + state["device_token"],
            "User-Agent": "os-opnsensehub/0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        body = json.loads(response.read().decode("utf-8"))
    state["last_backup_at"] = created_at
    save_state(state)
    return body


def main():
    if not STATE_FILE.exists():
        print(json.dumps({"status": "error", "message": "not enrolled"}))
        sys.exit(1)

    state = load_state()
    try:
        response_body = send_heartbeat(state, heartbeat_payload(state))
        if request_firmware_check_pending(response_body):
            firmware = collect_firmware_status()
            state["firmware"] = firmware
            save_state(state)
            response_body = send_heartbeat(state, heartbeat_payload(state, firmware))
        if backup_request_pending(response_body):
            upload_backup(state)
        print(json.dumps({"status": "ok", "hub_response": response_body}))
    except urllib.error.HTTPError as exc:
        state["last_error"] = f"heartbeat failed with HTTP {exc.code}"
        save_state(state)
        if exc.code in (401, 404):
            result = remove_local_artifacts(reason=state["last_error"])
            result["status"] = "revoked"
            result["message"] = (
                "Hub rejected this device; removed local OPNsense Hub tunnel and state"
            )
            print(json.dumps(result))
            sys.exit(1)
        print(
            json.dumps(
                {
                    "status": "error",
                    "message": state["last_error"],
                }
            )
        )
        sys.exit(1)
    except Exception:
        state["last_error"] = "heartbeat failed"
        save_state(state)
        print(json.dumps({"status": "error", "message": "heartbeat failed"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
