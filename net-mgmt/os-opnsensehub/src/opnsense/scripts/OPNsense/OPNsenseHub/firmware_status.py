#!/usr/local/bin/python3
import json
import subprocess
from datetime import datetime, timezone

VERSION_MAX_LENGTH = 80
MESSAGE_MAX_LENGTH = 500


def truncate_optional_text(value, max_length):
    if value is None:
        return None
    text_value = str(value).strip()
    if not text_value:
        return None
    return text_value[:max_length]


def as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def list_value(payload, *keys):
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def text_value(payload, *keys):
    for key in keys:
        value = truncate_optional_text(payload.get(key), VERSION_MAX_LENGTH)
        if value:
            return value
    return None


def message_value(payload):
    for key in ("status_msg", "message", "notice", "error", "status"):
        value = truncate_optional_text(payload.get(key), MESSAGE_MAX_LENGTH)
        if value:
            return value
    return None


def highest_package_version(packages):
    versions = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        version = truncate_optional_text(
            package.get("new_version")
            or package.get("version")
            or package.get("target"),
            VERSION_MAX_LENGTH,
        )
        if version:
            versions.append(version)
    return versions[-1] if versions else None


def parse_firmware_product(payload, now=None):
    checked_at = (now or datetime.now(timezone.utc)).isoformat()
    if not isinstance(payload, dict):
        return {
            "status": "error",
            "update_available": False,
            "update_type": "error",
            "current_version": None,
            "available_version": None,
            "update_count": 0,
            "reboot_required": False,
            "message": "Invalid firmware product payload",
            "checked_at": checked_at,
        }

    if str(payload.get("status", "")).strip().lower() == "error":
        return {
            "status": "error",
            "update_available": False,
            "update_type": "error",
            "current_version": text_value(payload, "product_version", "version"),
            "available_version": None,
            "update_count": 0,
            "reboot_required": False,
            "message": message_value(payload) or "Firmware check failed",
            "checked_at": checked_at,
        }

    current_version = text_value(
        payload, "product_version", "product_series", "version"
    )
    latest_version = text_value(payload, "product_latest", "product_target_version")
    upgrade_sets = list_value(payload, "upgrade_sets", "major_upgrade_sets")
    upgrade_packages = list_value(payload, "upgrade_packages")
    all_packages = list_value(
        payload,
        "all_packages",
        "new_packages",
        "package_updates",
        "packages",
    )
    update_count = max(
        len(all_packages),
        len(upgrade_packages),
        int(payload.get("update_count", 0) or 0),
    )
    reboot_required = as_bool(
        payload.get("needs_reboot")
        or payload.get("reboot_required")
        or payload.get("upgrade_needs_reboot")
    )
    message = message_value(payload)

    upgrade_version = text_value(payload, "upgrade_major_version", "upgrade_series")
    if not upgrade_version:
        for item in upgrade_sets:
            if isinstance(item, dict):
                upgrade_version = truncate_optional_text(
                    item.get("new_version") or item.get("version") or item.get("name"),
                    VERSION_MAX_LENGTH,
                )
                if upgrade_version:
                    break
    update_version = (
        latest_version
        or highest_package_version(all_packages)
        or highest_package_version(upgrade_packages)
    )

    has_upgrade = bool(
        upgrade_version
        or upgrade_sets
        or as_bool(payload.get("major_upgrade_available"))
    )
    has_update = bool(
        update_count > 0 or (update_version and update_version != current_version)
    )

    if has_upgrade:
        status = "upgrade"
        available_version = upgrade_version or update_version
        update_available = True
        update_type = "upgrade"
        message = message or "Upgrade available"
    elif has_update:
        status = "update"
        available_version = update_version
        update_available = True
        update_type = "update"
        message = message or f"There are {update_count} updates available."
    else:
        status = "none"
        available_version = update_version or current_version
        update_available = False
        update_type = "none"
        message = message or "System is up to date"

    return {
        "status": status,
        "update_available": update_available,
        "update_type": update_type,
        "current_version": truncate_optional_text(current_version, VERSION_MAX_LENGTH),
        "available_version": truncate_optional_text(
            available_version, VERSION_MAX_LENGTH
        ),
        "update_count": max(0, update_count),
        "reboot_required": reboot_required,
        "message": truncate_optional_text(message, MESSAGE_MAX_LENGTH),
        "checked_at": checked_at,
    }


def run_json_command(args, timeout=60, check=True):
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(detail or f"command failed: {' '.join(args)}")
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except Exception as exc:
        raise RuntimeError(f"invalid JSON from {' '.join(args)}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid JSON object from {' '.join(args)}")
    return payload


def collect_firmware_status(now=None):
    checked_at = now or datetime.now(timezone.utc)
    try:
        subprocess.run(
            ["configctl", "firmware", "probe"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        product = run_json_command(["configctl", "firmware", "product"], timeout=60)
        return parse_firmware_product(product, now=checked_at)
    except Exception as exc:
        return {
            "status": "error",
            "update_available": False,
            "update_type": "error",
            "current_version": None,
            "available_version": None,
            "update_count": 0,
            "reboot_required": False,
            "message": truncate_optional_text(str(exc), MESSAGE_MAX_LENGTH)
            or "Firmware check failed",
            "checked_at": checked_at.isoformat(),
        }


def main():
    print(json.dumps(collect_firmware_status()))


if __name__ == "__main__":
    main()
