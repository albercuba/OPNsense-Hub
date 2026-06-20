#!/usr/local/bin/python3
"""Enroll this firewall in OPNsense Hub and start the local WireGuard tunnel.

verify against current OPNsense plugin conventions: the WireGuard config path and
wg-quick service invocation may need adjustment for the installed WireGuard plugin.
"""

import json
import os
import socket
import stat
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

STATE_DIR = Path("/var/db/opnsensehub")
STATE_FILE = STATE_DIR / "state.json"
KEY_FILE = STATE_DIR / "wg_private.key"
WG_CONF = Path("/usr/local/etc/wireguard/opnsensehub.conf")
CONFIG_XML = Path("/conf/config.xml")
PLUGIN_VERSION = "0.1.0"


def out(payload):
    print(json.dumps(payload))


def fail(message):
    out({"status": "error", "message": message})
    sys.exit(1)


def load_settings():
    if not CONFIG_XML.exists():
        fail("OPNsense config.xml not found")
    root = ET.parse(CONFIG_XML).getroot()
    node = root.find("./OPNsense/OPNsenseHub")
    if node is None:
        fail("OPNsense Hub settings not found")
    return {child.tag: (child.text or "").strip() for child in node}


def validate_hub_url(value):
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        fail("Hub URL must be HTTPS")
    return value.rstrip("/")


def run_cmd(args, input_text=None):
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
            timeout=15,
        )
        return result.stdout.strip()
    except Exception as exc:
        fail(f"command failed: {args[0]}")


def ensure_private_key():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return KEY_FILE.read_text().strip()
    private_key = run_cmd(["wg", "genkey"])
    KEY_FILE.write_text(private_key + "\n")
    os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
    return private_key


def public_key(private_key):
    return run_cmd(["wg", "pubkey"], input_text=private_key + "\n")


def opnsense_version():
    try:
        return run_cmd(["opnsense-version"])
    except SystemExit:
        return "unknown"


def post_json(url, payload, token=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "os-opnsensehub/0.1",
        },
    )
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8")
        except Exception:
            body = "HTTP enrollment failed"
        fail(body)
    except Exception:
        fail("Could not reach OPNsense Hub")


def render_wg(private_key, wg):
    text = """[Interface]
PrivateKey = {private_key}
Address = {interface_address}

[Peer]
PublicKey = {server_public_key}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = {persistent_keepalive}
""".format(private_key=private_key, **wg)
    WG_CONF.parent.mkdir(parents=True, exist_ok=True)
    WG_CONF.write_text(text)
    os.chmod(WG_CONF, stat.S_IRUSR | stat.S_IWUSR)


def save_state(state):
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))
    os.chmod(STATE_FILE, stat.S_IRUSR | stat.S_IWUSR)


def start_tunnel():
    # verify against current OPNsense plugin conventions
    subprocess.run(
        ["wg-quick", "down", str(WG_CONF)], capture_output=True, text=True, timeout=15
    )
    subprocess.run(
        ["wg-quick", "up", str(WG_CONF)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def main():
    settings = load_settings()
    hub_url = validate_hub_url(settings.get("hub_url", ""))
    otp = settings.get("otp", "")
    if not otp:
        fail("OTP enrollment code is required")
    private_key = ensure_private_key()
    pub = public_key(private_key)
    response = post_json(
        hub_url + "/api/v1/enroll",
        {
            "otp": otp,
            "hostname": socket.gethostname(),
            "opnsense_version": opnsense_version(),
            "plugin_version": PLUGIN_VERSION,
            "wg_public_key": pub,
        },
    )
    render_wg(private_key, response["wireguard"])
    save_state(
        {
            "hub_url": hub_url,
            "device_id": response["device_id"],
            "device_token": response["device_token"],
            "tunnel_ip": response["wireguard"]["interface_address"],
            "status": "connected",
        }
    )
    start_tunnel()
    out(
        {
            "status": "connected",
            "device_id": response["device_id"],
            "tunnel_ip": response["wireguard"]["interface_address"],
        }
    )


if __name__ == "__main__":
    main()
