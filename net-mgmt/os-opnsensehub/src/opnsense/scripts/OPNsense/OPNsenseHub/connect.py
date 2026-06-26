#!/usr/local/bin/python3
"""Enroll this firewall in OPNsense Hub and start the local WireGuard tunnel."""

import ipaddress
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import time
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
ASSIGNED_IF_DESCR = "OPNHUB"
RULE_DESCR = "Allow OPNsense Hub WebGUI proxy"
FLOATING_RULE_DESCR = "Allow OPNsense Hub WebGUI proxy (floating)"
PLUGIN_VERSION = "0.1.0"
HEARTBEAT_SCRIPT = "/usr/local/opnsense/scripts/OPNsense/OPNsenseHub/heartbeat.py"
HEARTBEAT_CRON_MARKER = "# OPNsense Hub heartbeat"
HEARTBEAT_CRON_LINE = (
    f"* * * * * {HEARTBEAT_SCRIPT} >/dev/null 2>&1 {HEARTBEAT_CRON_MARKER}"
)


def out(payload):
    print(json.dumps(payload))


def update_state(**changes):
    state = load_state()
    state.update(changes)
    save_state(state)


def fail(message, exit_code=0):
    try:
        update_state(last_error=str(message))
    except Exception:
        pass
    out({"status": "error", "message": str(message)})
    sys.exit(exit_code)


def hub_error_message(body):
    try:
        payload = json.loads(body)
    except Exception:
        return body.strip() or "HTTP enrollment failed"

    detail = payload.get("detail")
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        messages = []
        for item in detail:
            if isinstance(item, dict) and item.get("msg"):
                messages.append(str(item["msg"]))
            else:
                messages.append(str(item))
        return "; ".join(messages)
    if payload.get("message"):
        return str(payload["message"])
    return body.strip() or "HTTP enrollment failed"


def load_config_root():
    if not CONFIG_XML.exists():
        fail("OPNsense config.xml not found")
    return ET.parse(CONFIG_XML).getroot()


def write_config_root(root):
    backup = CONFIG_XML.with_name(f"config.xml.opnsensehub.{int(time.time())}.bak")
    shutil.copy2(CONFIG_XML, backup)
    try:
        ET.indent(root, space="  ")
    except AttributeError:
        pass
    ET.ElementTree(root).write(CONFIG_XML, encoding="utf-8", xml_declaration=True)


def load_settings():
    root = load_config_root()
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


def firmware_product():
    try:
        result = subprocess.run(
            ["/usr/local/opnsense/scripts/firmware/product.php"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return {}
    if result.returncode != 0:
        return {}
    try:
        payload = json.loads(result.stdout)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def license_metadata():
    product = firmware_product()
    product_license = product.get("product_license")
    if isinstance(product_license, dict) and product_license:
        valid_to = str(product_license.get("valid_to", "")).strip()
        return {
            "license_type": "Business",
            "license_expires_at": valid_to or None,
        }
    return {"license_type": "Community", "license_expires_at": None}


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
        fail(f"Hub enrollment failed with HTTP {exc.code}: {hub_error_message(body)}")
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


def current_crontab_lines():
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        fail("required command not found: crontab")
    except subprocess.TimeoutExpired:
        fail("command timed out: crontab")
    if result.returncode != 0:
        return []
    return [line.rstrip() for line in result.stdout.splitlines()]


def write_crontab_lines(lines):
    payload = "\n".join(lines).strip()
    if payload:
        payload += "\n"
    try:
        result = subprocess.run(
            ["crontab", "-"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        fail("required command not found: crontab")
    except subprocess.TimeoutExpired:
        fail("command timed out: crontab")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        fail(f"could not update crontab{': ' + detail if detail else ''}")


def ensure_heartbeat_cron():
    lines = [
        line for line in current_crontab_lines() if HEARTBEAT_CRON_MARKER not in line
    ]
    lines.append(HEARTBEAT_CRON_LINE)
    write_crontab_lines(lines)


def remove_heartbeat_cron():
    lines = [
        line for line in current_crontab_lines() if HEARTBEAT_CRON_MARKER not in line
    ]
    write_crontab_lines(lines)


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


def validate_wireguard_payload(wg):
    if not isinstance(wg, dict):
        fail("Hub returned an invalid WireGuard payload")

    try:
        interface = ipaddress.ip_interface(str(wg.get("interface_address", "")).strip())
    except ValueError as exc:
        fail(f"Hub returned an invalid WireGuard interface_address: {exc}")
    if not isinstance(interface, ipaddress.IPv4Interface):
        fail(
            "Hub returned a non-IPv4 WireGuard interface_address; expected an IPv4 /32"
        )
    if interface.network.prefixlen != 32:
        fail(
            "Hub returned an unsafe WireGuard interface_address; expected the firewall tunnel IP as an IPv4 /32"
        )

    allowed_ip_values = [
        item.strip()
        for item in str(wg.get("allowed_ips", "")).split(",")
        if item.strip()
    ]
    if len(allowed_ip_values) != 1:
        fail(
            "Hub returned an unsafe WireGuard allowed_ips value; expected exactly one IPv4 /32 for the Hub tunnel IP"
        )
    try:
        allowed_network = ipaddress.ip_network(allowed_ip_values[0], strict=False)
    except ValueError as exc:
        fail(f"Hub returned an invalid WireGuard allowed_ips CIDR: {exc}")
    if not isinstance(allowed_network, ipaddress.IPv4Network):
        fail(
            "Hub returned a non-IPv4 allowed_ips value; expected the Hub tunnel IPv4 /32"
        )
    if allowed_network.prefixlen != 32:
        fail(
            "Hub returned an unsafe WireGuard allowed_ips route; expected only the Hub tunnel IPv4 /32, not a LAN or Hub network"
        )
    if allowed_network.network_address == ipaddress.IPv4Address("0.0.0.0"):
        fail(
            "Hub returned 0.0.0.0/0 for allowed_ips; only the Hub tunnel IP /32 is permitted"
        )
    if allowed_network.network_address == interface.ip:
        fail(
            "Hub returned the firewall's own WireGuard interface_address in allowed_ips; expected only the Hub tunnel IP /32"
        )

    normalized = dict(wg)
    normalized["interface_address"] = str(interface)
    normalized["allowed_ips"] = str(allowed_network)
    if "persistent_keepalive" in normalized:
        normalized["persistent_keepalive"] = int(normalized["persistent_keepalive"])
    return normalized


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


def find_or_create(parent, tag):
    node = parent.find(tag)
    if node is None:
        node = ET.SubElement(parent, tag)
    return node


def set_child_text(parent, tag, value):
    child = find_or_create(parent, tag)
    if child.text != str(value):
        child.text = str(value)
        return True
    return False


def remove_child(parent, tag):
    child = parent.find(tag)
    if child is None:
        return False
    parent.remove(child)
    return True


def ensure_assigned_interface(root, tunnel_ip):
    interfaces = find_or_create(root, "interfaces")
    interface_ip = str(ipaddress.ip_interface(tunnel_ip).ip)
    prefix_len = str(ipaddress.ip_interface(tunnel_ip).network.prefixlen)

    existing_key = None
    for child in list(interfaces):
        if (
            child.findtext("if") == WG_IFACE
            or child.findtext("descr") == ASSIGNED_IF_DESCR
        ):
            existing_key = child.tag
            break

    if existing_key is None:
        used = {child.tag for child in list(interfaces)}
        index = 1
        while f"opt{index}" in used:
            index += 1
        existing_key = f"opt{index}"
        interface = ET.SubElement(interfaces, existing_key)
        changed = True
    else:
        interface = interfaces.find(existing_key)
        changed = False

    changed |= set_child_text(interface, "enable", "1")
    changed |= set_child_text(interface, "if", WG_IFACE)
    changed |= set_child_text(interface, "descr", ASSIGNED_IF_DESCR)
    changed |= set_child_text(interface, "ipaddr", interface_ip)
    changed |= set_child_text(interface, "subnet", prefix_len)
    changed |= set_child_text(interface, "ipaddrv6", "none")
    changed |= remove_child(interface, "type")

    return existing_key, changed


def webgui_port(root):
    webgui = root.find("./system/webgui")
    if webgui is None:
        return "443"
    port = (webgui.findtext("port") or "").strip()
    if port:
        return port
    protocol = (webgui.findtext("protocol") or "https").strip().lower()
    return "80" if protocol == "http" else "443"


def ensure_webgui_listen_interface(root, interface_key):
    webgui = root.find("./system/webgui")
    if webgui is None:
        return False

    listen_nodes = webgui.findall("interfaces")
    if not listen_nodes:
        return False

    values = []
    for node in listen_nodes:
        if len(list(node)) > 0:
            values.extend((child.text or "").strip() for child in list(node))
        else:
            values.extend(item.strip() for item in (node.text or "").split(","))
    values = [value for value in values if value]

    if not values or interface_key in values:
        return False

    first = listen_nodes[0]
    if len(list(first)) > 0:
        item = ET.SubElement(first, "interface")
        item.text = interface_key
    elif len(listen_nodes) == 1 and "," in (first.text or ""):
        first.text = ",".join(values + [interface_key])
    else:
        item = ET.SubElement(webgui, "interfaces")
        item.text = interface_key
    return True


def rule_matches(rule, interface_key, hub_ip, firewall_ip, port, descr):
    if rule.findtext("descr") == descr:
        return True
    return (
        rule.findtext("type") == "pass"
        and rule.findtext("interface") == interface_key
        and rule.findtext("ipprotocol") == "inet"
        and rule.findtext("protocol") == "tcp"
        and rule.findtext("source/address") == f"{hub_ip}/32"
        and rule.findtext("destination/address") == f"{firewall_ip}/32"
        and rule.findtext("destination/port") == str(port)
    )


def configure_firewall_rule(
    rule, interface_key, hub_ip, firewall_ip, port, descr, floating=False
):
    changed = False
    changed |= set_child_text(rule, "type", "pass")
    changed |= set_child_text(rule, "interface", interface_key)
    changed |= set_child_text(rule, "ipprotocol", "inet")
    changed |= set_child_text(rule, "direction", "in")
    changed |= set_child_text(rule, "quick", "1")
    changed |= set_child_text(rule, "statetype", "keep state")
    changed |= set_child_text(rule, "protocol", "tcp")
    if floating:
        changed |= set_child_text(rule, "floating", "yes")
    else:
        changed |= remove_child(rule, "floating")
    source = find_or_create(rule, "source")
    changed |= set_child_text(source, "address", f"{hub_ip}/32")
    destination = find_or_create(rule, "destination")
    changed |= remove_child(destination, "network")
    changed |= set_child_text(destination, "address", f"{firewall_ip}/32")
    changed |= set_child_text(destination, "port", port)
    changed |= set_child_text(rule, "descr", descr)
    return changed


def ensure_firewall_rule(
    root, interface_key, hub_ip, firewall_ip, port, descr, floating=False
):
    filter_node = find_or_create(root, "filter")
    for rule in filter_node.findall("rule"):
        if rule_matches(rule, interface_key, hub_ip, firewall_ip, port, descr):
            return configure_firewall_rule(
                rule, interface_key, hub_ip, firewall_ip, port, descr, floating
            )

    rule = ET.SubElement(filter_node, "rule")
    configure_firewall_rule(
        rule, interface_key, hub_ip, firewall_ip, port, descr, floating
    )
    created = ET.SubElement(rule, "created")
    set_child_text(created, "time", str(int(time.time())))
    set_child_text(created, "username", "OPNsense Hub")
    return True


def remove_matching_firewall_rules(root, descriptions):
    filter_node = root.find("filter")
    if filter_node is None:
        return False
    changed = False
    description_set = set(descriptions)
    for rule in list(filter_node.findall("rule")):
        if rule.findtext("descr") in description_set:
            filter_node.remove(rule)
            changed = True
    return changed


def remove_webgui_listen_interface(root, interface_key):
    webgui = root.find("./system/webgui")
    if webgui is None or not interface_key:
        return False

    changed = False
    for node in list(webgui.findall("interfaces")):
        children = list(node)
        if children:
            for child in list(children):
                if (child.text or "").strip() == interface_key:
                    node.remove(child)
                    changed = True
            if len(list(node)) == 0 and not (node.text or "").strip():
                webgui.remove(node)
                changed = True
            continue

        values = [item.strip() for item in (node.text or "").split(",") if item.strip()]
        if interface_key not in values:
            continue
        values = [value for value in values if value != interface_key]
        if values:
            node.text = ",".join(values)
        else:
            webgui.remove(node)
        changed = True
    return changed


def remove_assigned_interface(root):
    interfaces = root.find("interfaces")
    if interfaces is None:
        return None, False

    for child in list(interfaces):
        if (
            child.findtext("if") == WG_IFACE
            or child.findtext("descr") == ASSIGNED_IF_DESCR
        ):
            interface_key = child.tag
            interfaces.remove(child)
            return interface_key, True
    return None, False


def cleanup_opnsense_integration():
    root = load_config_root()
    interface_key = assigned_interface_key = None
    interfaces = root.find("interfaces")
    if interfaces is not None:
        for child in list(interfaces):
            if (
                child.findtext("if") == WG_IFACE
                or child.findtext("descr") == ASSIGNED_IF_DESCR
            ):
                assigned_interface_key = child.tag
                break

    changed = False
    if assigned_interface_key:
        changed |= remove_webgui_listen_interface(root, assigned_interface_key)
    changed |= remove_matching_firewall_rules(root, [RULE_DESCR, FLOATING_RULE_DESCR])
    interface_key, interface_removed = remove_assigned_interface(root)
    changed |= interface_removed

    if changed:
        write_config_root(root)
        run_cmd(["configctl", "filter", "reload"], check=False)
        run_cmd(["service", "lighttpd", "onerestart"], check=False)

    return {
        "interface_key": interface_key or assigned_interface_key,
        "config_changed": changed,
    }


def ensure_opnsense_integration(wg):
    root = load_config_root()
    allowed_ips = [
        item.strip() for item in wg["allowed_ips"].split(",") if item.strip()
    ]
    if not allowed_ips:
        fail("WireGuard allowed_ips is empty")
    hub_ip = str(ipaddress.ip_network(allowed_ips[0], strict=False).network_address)
    firewall_ip = str(ipaddress.ip_interface(wg["interface_address"]).ip)
    interface_key, changed = ensure_assigned_interface(root, wg["interface_address"])
    port = webgui_port(root)
    changed |= ensure_firewall_rule(
        root, interface_key, hub_ip, firewall_ip, port, RULE_DESCR
    )
    changed |= ensure_firewall_rule(
        root,
        interface_key,
        hub_ip,
        firewall_ip,
        port,
        FLOATING_RULE_DESCR,
        floating=True,
    )
    webgui_listen_changed = ensure_webgui_listen_interface(root, interface_key)
    changed |= webgui_listen_changed

    if changed:
        write_config_root(root)
        run_cmd(["configctl", "interface", "reconfigure", interface_key], check=False)
        run_cmd(["configctl", "filter", "reload"], check=False)
        if webgui_listen_changed:
            run_cmd(["service", "lighttpd", "onerestart"], check=False)
    return {
        "interface": interface_key,
        "description": ASSIGNED_IF_DESCR,
        "webgui_port": port,
    }


def destroy_tunnel():
    subprocess.run(
        ["ifconfig", WG_IFACE, "destroy"], capture_output=True, text=True, timeout=10
    )


def hub_route_for(wg):
    allowed_ips = [
        item.strip() for item in wg["allowed_ips"].split(",") if item.strip()
    ]
    if not allowed_ips:
        fail("WireGuard allowed_ips is empty")
    return str(ipaddress.ip_network(allowed_ips[0], strict=False).network_address)


def ensure_hub_route(wg):
    hub_route = hub_route_for(wg)
    subprocess.run(
        ["route", "delete", "-host", hub_route],
        capture_output=True,
        text=True,
        timeout=10,
    )
    run_cmd(["route", "add", "-host", hub_route, "-interface", WG_IFACE])


def start_tunnel(private_key, wg):
    interface = ipaddress.ip_interface(wg["interface_address"])
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
        ensure_hub_route(wg)
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
        state["wireguard"] = validate_wireguard_payload(
            normalize_wireguard_endpoint(state["wireguard"], hub_url)
        )
        render_wg(private_key, state["wireguard"])
        start_tunnel(private_key, state["wireguard"])
        opnsense = ensure_opnsense_integration(state["wireguard"])
        ensure_hub_route(state["wireguard"])
        state["opnsense"] = opnsense
        state["status"] = "connected"
        state["last_error"] = ""
        save_state(state)
        ensure_heartbeat_cron()
        out(
            {
                "status": "connected",
                "device_id": state["device_id"],
                "tunnel_ip": state.get("tunnel_ip"),
                "interface": opnsense["description"],
                "webgui_port": opnsense["webgui_port"],
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
            **license_metadata(),
        },
    )
    wireguard = validate_wireguard_payload(
        normalize_wireguard_endpoint(response["wireguard"], hub_url)
    )
    render_wg(private_key, wireguard)
    state = {
        "hub_url": hub_url,
        "device_id": response["device_id"],
        "device_token": response["device_token"],
        "tunnel_ip": wireguard["interface_address"],
        "wireguard": wireguard,
        "status": "connected",
        "last_error": "",
    }
    save_state(state)
    start_tunnel(private_key, wireguard)
    opnsense = ensure_opnsense_integration(wireguard)
    ensure_hub_route(wireguard)
    state["opnsense"] = opnsense
    save_state(state)
    ensure_heartbeat_cron()
    out(
        {
            "status": "connected",
            "device_id": response["device_id"],
            "tunnel_ip": response["wireguard"]["interface_address"],
            "interface": opnsense["description"],
            "webgui_port": opnsense["webgui_port"],
        }
    )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"Unexpected enrollment error: {exc}")
