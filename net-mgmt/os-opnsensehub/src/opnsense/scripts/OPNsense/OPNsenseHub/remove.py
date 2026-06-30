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
    load_config_root,
    remove_heartbeat_cron,
    write_config_root,
)


def delete_path(path):
    try:
        if path.exists():
            path.unlink()
            return True
    except Exception:
        return False
    return False


def set_child_text(parent, tag, value):
    child = parent.find(tag)
    if child is None:
        return False
    if (child.text or "") == value:
        return False
    child.text = value
    return True


def clear_plugin_settings():
    try:
        root = load_config_root()
        node = root.find("./OPNsense/OPNsenseHub")
        if node is None:
            return False
        changed = False
        changed |= set_child_text(node, "enabled", "0")
        changed |= set_child_text(node, "hub_url", "")
        changed |= set_child_text(node, "otp", "")
        changed |= set_child_text(node, "last_heartbeat", "")
        changed |= set_child_text(node, "last_error", "")
        if changed:
            write_config_root(root)
        return changed
    except Exception:
        return False


def remove_local_artifacts(reason=None, clear_settings=True):
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
    remove_heartbeat_cron()

    cleanup = cleanup_opnsense_integration()
    settings_cleared = clear_plugin_settings() if clear_settings else False
    removed_files = {
        "wireguard_config": delete_path(WG_CONF),
        "private_key": delete_path(KEY_FILE),
        "state": delete_path(STATE_FILE),
    }

    return {
        "status": "removed",
        "message": "Removed local OPNsense Hub tunnel, interface assignment, saved settings, and state",
        "reason": reason,
        "interface": cleanup.get("interface_key"),
        "config_changed": cleanup.get("config_changed", False),
        "settings_cleared": settings_cleared,
        "removed_files": removed_files,
        "device_id": state.get("device_id"),
    }


def main():
    print(json.dumps(remove_local_artifacts()))


if __name__ == "__main__":
    main()
