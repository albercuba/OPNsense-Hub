#!/usr/local/bin/python3
"""Enroll this firewall in OPNsense Hub and start the local WireGuard tunnel."""

import ipaddress
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
WG_IFACE = "wgopnhub"
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


def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def validate_hub_url(value):
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        fail("Hub URL must be HTTPS")
    return value.rstrip("/")


def run_cmd(args, input_text=None, check=True):
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except FileNotFoundError:
        fail(f"required command not found: {args[0]}")
    except subprocess.TimeoutExpired:
        fail(f"command timed out: {args[0]}")
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        fail(f"command failed: {' '.join(args)}{': ' + detail if detail else ''}")
    return result.stdout.strip()


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
    result = subprocess.run(
        ["opnsense-version"], capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0:
        return result.stdout.strip()
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
    except Exception as exc:
        fail(f"Could not reach OPNsense Hub: {exc}")


def render_wg(private_key, wg):
    text = """[Interface]
PrivateKey = {private_key}
Address = {interface_address}

[Peer]
PublicKey = {server_public_key}
Endpoint = {endpoint}
# OPNsense Hub is management-only. This must remain the Hub tunnel /32,
# never a customer LAN subnet.
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


def is_loopback_host(host):
    return host in {"localhost", "127.0.0.1", "::1", "[::1]"}


def endpoint_host_port(endpoint):
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint.rsplit(":", 1)
        return host.strip("[]"), port
    if ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
        return host, port
    return endpoint, "51820"


def normalize_wireguard_endpoint(wg, hub_url):
    endpoint = wg.get("endpoint", "")
    endpoint_host, endpoint_port = endpoint_host_port(endpoint)
    hub_host = urlparse(hub_url).hostname
    if hub_host and is_loopback_host(endpoint_host) and not is_loopback_host(hub_host):
        wg = dict(wg)
        wg["endpoint"] = f"{hub_host}:{endpoint_port}"
    return wg


def load_wireguard_config():
    if not WG_CONF.exists():
        return None
    values = {}
    for line in WG_CONF.read_text().splitlines():
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        values[key.lower()] = value
    required = ["address", "publickey", "endpoint", "allowedips"]
    if any(not values.get(key) for key in required):
        return None
    return {
        "interface_address": values["address"],
        "server_public_key": values["publickey"],
        "endpoint": values["endpoint"],
        "allowed_ips": values["allowedips"],
        "persistent_keepalive": int(values.get("persistentkeepalive", "25")),
    }


def destroy_tunnel():
    subprocess.run(
        ["ifconfig", WG_IFACE, "destroy"], capture_output=True, text=True, timeout=10
    )


def start_tunnel(private_key, wg):
    interface = ipaddress.ip_interface(wg["interface_address"])
    allowed_ips = [
        item.strip() for item in wg["allowed_ips"].split(",") if item.strip()
    ]
    if not allowed_ips:
        fail("WireGuard allowed_ips is empty")
    hub_route = str(ipaddress.ip_network(allowed_ips[0], strict=False).network_address)

    destroy_tunnel()
    run_cmd(["ifconfig", "wg", "create", "name", WG_IFACE])
    try:
        run_cmd(
            [
                "ifconfig",
                WG_IFACE,
                "inet",
                str(interface.ip),
                "netmask",
                "255.255.255.255",
                "up",
            ]
        )
        run_cmd(
            [
                "wg",
                "set",
                WG_IFACE,
                "private-key",
                str(KEY_FILE),
                "peer",
                wg["server_public_key"],
                "allowed-ips",
                wg["allowed_ips"],
                "endpoint",
                wg["endpoint"],
                "persistent-keepalive",
                str(wg.get("persistent_keepalive", 25)),
            ]
        )
        subprocess.run(
            ["route", "delete", "-host", hub_route],
            capture_output=True,
            text=True,
            timeout=10,
        )
        run_cmd(["route", "add", "-host", hub_route, "-interface", WG_IFACE])
    except Exception:
        destroy_tunnel()
        raise


def main():
    settings = load_settings()
    hub_url = validate_hub_url(settings.get("hub_url", ""))
    private_key = ensure_private_key()
    state = load_state()

    if state.get("device_id") and not state.get("wireguard"):
        wireguard = load_wireguard_config()
        if wireguard:
            state["wireguard"] = wireguard

    if state.get("device_id") and state.get("wireguard"):
        state["wireguard"] = normalize_wireguard_endpoint(state["wireguard"], hub_url)
        render_wg(private_key, state["wireguard"])
        start_tunnel(private_key, state["wireguard"])
        state["status"] = "connected"
        save_state(state)
        out(
            {
                "status": "connected",
                "device_id": state["device_id"],
                "tunnel_ip": state.get("tunnel_ip"),
            }
        )
        return

    otp = settings.get("otp", "")
    if not otp:
        fail("OTP enrollment code is required")
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
    wireguard = normalize_wireguard_endpoint(response["wireguard"], hub_url)
    render_wg(private_key, wireguard)
    state = {
        "hub_url": hub_url,
        "device_id": response["device_id"],
        "device_token": response["device_token"],
        "tunnel_ip": wireguard["interface_address"],
        "wireguard": wireguard,
        "status": "connected",
    }
    save_state(state)
    start_tunnel(private_key, wireguard)
    out(
        {
            "status": "connected",
            "device_id": response["device_id"],
            "tunnel_ip": response["wireguard"]["interface_address"],
        }
    )


if __name__ == "__main__":
    main()
