#!/usr/local/bin/python3
import json
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

STATE_FILE = Path("/var/db/opnsensehub/state.json")
WG_CONF = Path("/usr/local/etc/wireguard/opnsensehub.conf")
CONFIG_XML = Path("/conf/config.xml")
WG_IFACE = "wgopnhub"
ASSIGNED_IF_DESCR = "OPNHUB"
RULE_DESCR = "Allow OPNsense Hub WebGUI proxy"


def tunnel_host(value):
    return str(value).split("/", 1)[0]


def load_config_root():
    if not CONFIG_XML.exists():
        return None
    try:
        return ET.parse(CONFIG_XML).getroot()
    except Exception:
        return None


def assigned_interface(root):
    if root is None:
        return None
    interfaces = root.find("interfaces")
    if interfaces is None:
        return None
    for child in list(interfaces):
        if (
            child.findtext("if") == WG_IFACE
            or child.findtext("descr") == ASSIGNED_IF_DESCR
        ):
            return child.tag
    return None


def webgui_port(root):
    webgui = root.find("./system/webgui") if root is not None else None
    if webgui is None:
        return "443"
    port = (webgui.findtext("port") or "").strip()
    if port:
        return port
    protocol = (webgui.findtext("protocol") or "https").strip().lower()
    return "80" if protocol == "http" else "443"


def webgui_listen_status(root, interface_key):
    webgui = root.find("./system/webgui") if root is not None else None
    if webgui is None:
        return "default"
    listen_nodes = webgui.findall("interfaces")
    if not listen_nodes:
        return "all"
    values = []
    for node in listen_nodes:
        if len(list(node)) > 0:
            values.extend((child.text or "").strip() for child in list(node))
        else:
            values.extend(item.strip() for item in (node.text or "").split(","))
    values = [value for value in values if value]
    if not values:
        return "all"
    if interface_key and interface_key in values:
        return "includes_opnhub"
    return "restricted_missing_opnhub"


def firewall_rule_present(root):
    if root is None:
        return False
    filter_node = root.find("filter")
    if filter_node is None:
        return False
    return any(
        rule.findtext("descr") == RULE_DESCR for rule in filter_node.findall("rule")
    )


def tcp_reachable(host, port):
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            return True
    except Exception:
        return False


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
            ["wg", "show", WG_IFACE], capture_output=True, text=True, timeout=5
        )
        tunnel = result.returncode == 0
    except Exception:
        tunnel = False

    root = load_config_root()
    interface_key = assigned_interface(root)
    port = webgui_port(root)
    tunnel_ip = state.get("tunnel_ip")
    host = tunnel_host(tunnel_ip) if tunnel_ip else None
    status = state.get("status", "disconnected")
    if tunnel and status != "revoked":
        status = "connected"

    print(
        json.dumps(
            {
                "status": status,
                "device_id": state.get("device_id"),
                "tunnel_ip": tunnel_ip,
                "wireguard_config": str(WG_CONF),
                "tunnel_running": tunnel,
                "interface": ASSIGNED_IF_DESCR if interface_key else None,
                "interface_key": interface_key,
                "webgui_port": port,
                "webgui_listen": webgui_listen_status(root, interface_key),
                "firewall_rule_present": firewall_rule_present(root),
                "local_webgui_tcp_reachable": tcp_reachable(host, port),
                "last_heartbeat": state.get("last_heartbeat"),
                "last_error": state.get("last_error"),
            }
        )
    )


if __name__ == "__main__":
    main()
