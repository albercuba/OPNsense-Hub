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

from backup_crypto import (
    BACKUP_FORMAT,
    BACKUP_KEY_FILE,
    BackupCryptoError,
    encrypt_config_backup,
)
from connect import PLUGIN_VERSION, license_metadata, load_state, save_state
from firmware_status import collect_firmware_status
from remove import remove_local_artifacts

STATE_FILE = Path("/var/db/opnsensehub/state.json")
CONFIG_XML = Path("/conf/config.xml")
PLAINTEXT_BACKUP_FORMAT = "opnsense-config-plaintext-v1"
PLAINTEXT_BACKUP_MAX_BYTES = 2_100_000


class HeartbeatRevoked(RuntimeError):
    pass


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
        "backup_formats": [BACKUP_FORMAT, PLAINTEXT_BACKUP_FORMAT],
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
    url = heartbeat_url(state)
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
    except urllib.error.HTTPError as exc:
        if exc.code == 410 and exc.url == url:
            raise HeartbeatRevoked("heartbeat revoked by Hub") from exc
        raise
    state["status"] = "online"
    state["last_heartbeat"] = payload["timestamp"]
    state["last_error"] = ""
    save_state(state)
    return body


def request_firmware_check_pending(body):
    return bool(body.get("firmware_check_requested"))


def backup_request_pending(body):
    return bool(body.get("backup_requested"))


def token_rotation_pending(body):
    return bool(body.get("device_token_rotation_required"))


def rotate_device_token(state, body):
    rotate_url = body.get("device_token_rotation_url")
    if not isinstance(rotate_url, str) or not rotate_url.strip():
        rotate_url = "/api/v1/devices/" + state["device_id"] + "/token/rotate"
    if rotate_url.startswith("/"):
        rotate_url = state["hub_url"].rstrip("/") + rotate_url
    req = urllib.request.Request(
        rotate_url,
        data=b"{}",
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + state["device_token"],
            "User-Agent": "os-opnsensehub/0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    new_token = payload.get("device_token")
    if not isinstance(new_token, str) or not new_token:
        raise RuntimeError("Hub token rotation response did not include a device token")
    state["device_token"] = new_token
    state["device_token_issued_at"] = payload.get("device_token_issued_at")
    state["device_token_expires_at"] = payload.get("device_token_expires_at")
    save_state(state)
    return payload



def backup_upload_payload(state, required_format, captured_at):
    if required_format == PLAINTEXT_BACKUP_FORMAT:
        content = CONFIG_XML.read_bytes()
        if len(content) > PLAINTEXT_BACKUP_MAX_BYTES:
            raise RuntimeError("configuration backup is too large")
        return {
            "format": PLAINTEXT_BACKUP_FORMAT,
            "plaintext_backup": {
                "format": PLAINTEXT_BACKUP_FORMAT,
                "version": 1,
                "device_id": state["device_id"],
                "source_hostname": socket.gethostname(),
                "captured_at": captured_at,
                "content": content.decode("utf-8"),
            },
        }, None

    expected_key_id = state.get("backup_key_id")
    if expected_key_id and not BACKUP_KEY_FILE.exists():
        raise BackupCryptoError(
            "backup master key is missing; import the matching recovery key"
        )
    encrypted_backup = encrypt_config_backup(
        CONFIG_XML,
        device_id=state["device_id"],
        source_hostname=socket.gethostname(),
        captured_at=captured_at,
    )
    actual_key_id = encrypted_backup["key_id"]
    if expected_key_id and actual_key_id != expected_key_id:
        raise BackupCryptoError(
            "backup master key does not match the established recovery key"
        )
    return {
        "format": BACKUP_FORMAT,
        "encrypted_backup": encrypted_backup,
    }, actual_key_id


def upload_backup(state, required_format=None):
    captured_at = heartbeat_timestamp()
    payload, backup_key_id = backup_upload_payload(state, required_format, captured_at)
    req = urllib.request.Request(
        state["hub_url"].rstrip("/")
        + "/api/v1/devices/"
        + state["device_id"]
        + "/backups",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + state["device_token"],
            "User-Agent": "os-opnsensehub/0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        body = json.loads(response.read().decode("utf-8"))
    state["last_backup_at"] = captured_at
    if backup_key_id:
        state["backup_key_id"] = backup_key_id
    save_state(state)
    return body


def main():
    if not STATE_FILE.exists():
        print(json.dumps({"status": "error", "message": "not enrolled"}))
        sys.exit(1)

    state = load_state()
    try:
        response_body = send_heartbeat(state, heartbeat_payload(state))
        if token_rotation_pending(response_body):
            rotate_device_token(state, response_body)
        if request_firmware_check_pending(response_body):
            firmware = collect_firmware_status()
            state["firmware"] = firmware
            save_state(state)
            response_body = send_heartbeat(state, heartbeat_payload(state, firmware))
            if token_rotation_pending(response_body):
                rotate_device_token(state, response_body)
        backup_error = False
        if backup_request_pending(response_body):
            try:
                upload_backup(state, response_body.get("backup_format_required"))
            except Exception:
                backup_error = True
                state["last_error"] = "configuration backup upload failed"
                save_state(state)
        print(
            json.dumps(
                {
                    "status": "warning" if backup_error else "ok",
                    "hub_response": response_body,
                    "backup_error": backup_error,
                }
            )
        )
    except HeartbeatRevoked as exc:
        state["last_error"] = str(exc)
        save_state(state)
        result = remove_local_artifacts(reason=state["last_error"])
        result["status"] = "revoked"
        result["message"] = (
            "Hub explicitly revoked this device; removed local OPNsense Hub tunnel and state"
        )
        print(json.dumps(result))
        sys.exit(1)
    except urllib.error.HTTPError as exc:
        state["last_error"] = f"heartbeat failed with HTTP {exc.code}"
        save_state(state)
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
