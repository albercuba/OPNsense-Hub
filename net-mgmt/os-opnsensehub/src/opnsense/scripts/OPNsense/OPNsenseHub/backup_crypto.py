#!/usr/local/bin/python3
"""Encrypt OPNsense configuration backups before they leave the firewall."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path("/var/db/opnsensehub")
BACKUP_KEY_FILE = STATE_DIR / "backup_master.key"
BACKUP_FORMAT = "opnsense-config-encrypted-v1"
BACKUP_KEY_EXPORT_FORMAT = "opnsense-config-backup-key-v1"
BACKUP_VERSION = 1
CIPHER = "AES-256-CBC+HMAC-SHA256"
KDF = "PBKDF2-HMAC-SHA256"
PBKDF2_ITERATIONS = 200_000
MASTER_KEY_BYTES = 32
OPENSSL_TIMEOUT_SECONDS = 60
MAX_CIPHERTEXT_BYTES = 2_100_000
_ENVELOPE_FIELDS = {
    "format",
    "version",
    "cipher",
    "kdf",
    "iterations",
    "key_id",
    "device_id",
    "source_hostname",
    "captured_at",
    "ciphertext",
    "mac",
}


class BackupCryptoError(RuntimeError):
    """Raised when a backup cannot be encrypted, authenticated, or recovered."""


def _write_private_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, stat.S_IRWXU)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def load_backup_key(key_path: Path = BACKUP_KEY_FILE) -> bytes:
    if not key_path.exists():
        raise BackupCryptoError(
            "backup master key is missing; import the recovery key first"
        )
    key = key_path.read_bytes()
    if len(key) != MASTER_KEY_BYTES:
        raise BackupCryptoError("backup master key has an invalid length")
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    return key


def ensure_backup_key(key_path: Path = BACKUP_KEY_FILE) -> bytes:
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(key_path.parent, stat.S_IRWXU)
    if key_path.exists():
        return load_backup_key(key_path)

    key = os.urandom(MASTER_KEY_BYTES)
    try:
        _write_private_file(key_path, key)
    except FileExistsError:
        key = key_path.read_bytes()
        if len(key) != MASTER_KEY_BYTES:
            raise BackupCryptoError("backup master key has an invalid length")
    return key


def backup_key_id(master_key: bytes) -> str:
    if len(master_key) != MASTER_KEY_BYTES:
        raise BackupCryptoError("backup master key has an invalid length")
    return hashlib.sha256(master_key).hexdigest()[:24]


def _derived_keys(master_key: bytes) -> tuple[str, bytes]:
    encryption_key = hmac.new(
        master_key, b"opnsense-hub/config-backup/v1/encryption", hashlib.sha256
    ).digest()
    mac_key = hmac.new(
        master_key, b"opnsense-hub/config-backup/v1/authentication", hashlib.sha256
    ).digest()
    return base64.b64encode(encryption_key).decode("ascii"), mac_key


def _canonical_envelope(envelope_without_mac: dict[str, object]) -> bytes:
    return json.dumps(
        envelope_without_mac,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _openssl_path() -> str:
    for candidate in ("/usr/bin/openssl", "/usr/local/bin/openssl"):
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    resolved = shutil.which("openssl")
    if resolved:
        return resolved
    raise BackupCryptoError("OpenSSL is required for encrypted configuration backups")


def _run_openssl(args: list[str], passphrase: str) -> bytes:
    try:
        result = subprocess.run(
            [_openssl_path(), *args],
            input=(passphrase + "\n").encode("ascii"),
            capture_output=True,
            check=False,
            timeout=OPENSSL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupCryptoError("OpenSSL backup cryptographic operation failed") from exc
    if result.returncode != 0:
        raise BackupCryptoError("OpenSSL backup cryptographic operation failed")
    return result.stdout


def _validate_ciphertext(ciphertext: bytes) -> None:
    if not ciphertext.startswith(b"Salted__"):
        raise BackupCryptoError("encrypted backup is missing the OpenSSL salt header")
    encrypted_body = ciphertext[16:]
    if not encrypted_body or len(encrypted_body) % 16 != 0:
        raise BackupCryptoError("encrypted backup ciphertext has an invalid length")
    if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise BackupCryptoError("encrypted backup ciphertext is too large")


def encrypt_config_backup(
    config_path: Path,
    *,
    device_id: str,
    source_hostname: str,
    captured_at: str | None = None,
    key_path: Path = BACKUP_KEY_FILE,
) -> dict[str, object]:
    if not config_path.is_file():
        raise BackupCryptoError("OPNsense config.xml was not found")
    if config_path.stat().st_size > MAX_CIPHERTEXT_BYTES - 128:
        raise BackupCryptoError("OPNsense config.xml is too large")

    master_key = ensure_backup_key(key_path)
    passphrase, mac_key = _derived_keys(master_key)
    ciphertext = _run_openssl(
        [
            "enc",
            "-aes-256-cbc",
            "-e",
            "-salt",
            "-pbkdf2",
            "-iter",
            str(PBKDF2_ITERATIONS),
            "-md",
            "sha256",
            "-pass",
            "stdin",
            "-in",
            str(config_path),
        ],
        passphrase,
    )
    _validate_ciphertext(ciphertext)
    envelope: dict[str, object] = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "cipher": CIPHER,
        "kdf": KDF,
        "iterations": PBKDF2_ITERATIONS,
        "key_id": backup_key_id(master_key),
        "device_id": str(device_id),
        "source_hostname": str(source_hostname)[:255],
        "captured_at": captured_at
        or datetime.now(timezone.utc).isoformat(),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    envelope["mac"] = hmac.new(
        mac_key, _canonical_envelope(envelope), hashlib.sha256
    ).hexdigest()
    return envelope


def _parse_envelope(payload: bytes | str | dict[str, object]) -> dict[str, object]:
    if isinstance(payload, dict):
        envelope = dict(payload)
    else:
        try:
            raw = payload.decode("utf-8") if isinstance(payload, bytes) else payload
            envelope = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackupCryptoError("encrypted backup envelope is invalid") from exc
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        raise BackupCryptoError("encrypted backup envelope fields are invalid")
    if (
        envelope.get("format") != BACKUP_FORMAT
        or envelope.get("version") != BACKUP_VERSION
        or envelope.get("cipher") != CIPHER
        or envelope.get("kdf") != KDF
        or envelope.get("iterations") != PBKDF2_ITERATIONS
    ):
        raise BackupCryptoError("encrypted backup format is not supported")
    return envelope


def decrypt_config_backup(
    payload: bytes | str | dict[str, object],
    *,
    key_path: Path = BACKUP_KEY_FILE,
) -> bytes:
    envelope = _parse_envelope(payload)
    master_key = load_backup_key(key_path)
    if envelope["key_id"] != backup_key_id(master_key):
        raise BackupCryptoError("the recovery key does not match this backup")
    passphrase, mac_key = _derived_keys(master_key)
    supplied_mac = envelope.pop("mac")
    if not isinstance(supplied_mac, str) or len(supplied_mac) != 64:
        raise BackupCryptoError("encrypted backup authentication code is invalid")
    expected_mac = hmac.new(
        mac_key, _canonical_envelope(envelope), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise BackupCryptoError("encrypted backup authentication failed")

    encoded_ciphertext = envelope.get("ciphertext")
    if not isinstance(encoded_ciphertext, str):
        raise BackupCryptoError("encrypted backup ciphertext is invalid")
    try:
        ciphertext = base64.b64decode(encoded_ciphertext, validate=True)
    except (ValueError, TypeError) as exc:
        raise BackupCryptoError("encrypted backup ciphertext is invalid") from exc
    _validate_ciphertext(ciphertext)

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="opnhub-backup-", delete=False) as handle:
            handle.write(ciphertext)
            handle.flush()
            os.fchmod(handle.fileno(), stat.S_IRUSR | stat.S_IWUSR)
            temporary_path = Path(handle.name)
        return _run_openssl(
            [
                "enc",
                "-aes-256-cbc",
                "-d",
                "-pbkdf2",
                "-iter",
                str(PBKDF2_ITERATIONS),
                "-md",
                "sha256",
                "-pass",
                "stdin",
                "-in",
                str(temporary_path),
            ],
            passphrase,
        )
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def export_recovery_key(destination: Path, key_path: Path = BACKUP_KEY_FILE) -> str:
    master_key = ensure_backup_key(key_path)
    recovery_document = {
        "format": BACKUP_KEY_EXPORT_FORMAT,
        "key_id": backup_key_id(master_key),
        "key": base64.b64encode(master_key).decode("ascii"),
    }
    _write_private_file(
        destination,
        (json.dumps(recovery_document, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )
    return recovery_document["key_id"]


def import_recovery_key(source: Path, key_path: Path = BACKUP_KEY_FILE) -> str:
    try:
        recovery_document = json.loads(source.read_text(encoding="utf-8"))
        encoded_key = recovery_document["key"]
        master_key = base64.b64decode(encoded_key, validate=True)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BackupCryptoError("backup recovery-key file is invalid") from exc
    if recovery_document.get("format") != BACKUP_KEY_EXPORT_FORMAT:
        raise BackupCryptoError("backup recovery-key format is not supported")
    if len(master_key) != MASTER_KEY_BYTES:
        raise BackupCryptoError("backup recovery key has an invalid length")
    key_id = backup_key_id(master_key)
    if recovery_document.get("key_id") != key_id:
        raise BackupCryptoError("backup recovery-key fingerprint is invalid")
    if key_path.exists():
        existing = load_backup_key(key_path)
        if hmac.compare_digest(existing, master_key):
            return key_id
        raise BackupCryptoError("a different backup master key already exists")
    _write_private_file(key_path, master_key)
    return key_id


def _write_decrypted_config(destination: Path, content: bytes) -> None:
    _write_private_file(destination, content)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the local OPNsense Hub configuration-backup recovery key."
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=BACKUP_KEY_FILE,
        help=argparse.SUPPRESS,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    export_parser = subparsers.add_parser(
        "export-key", help="write a root-only recovery-key file for offline storage"
    )
    export_parser.add_argument("destination", type=Path)
    import_parser = subparsers.add_parser(
        "import-key", help="install a previously exported recovery key"
    )
    import_parser.add_argument("source", type=Path)
    decrypt_parser = subparsers.add_parser(
        "decrypt", help="decrypt a downloaded backup to a new root-only file"
    )
    decrypt_parser.add_argument("backup", type=Path)
    decrypt_parser.add_argument("destination", type=Path)
    subparsers.add_parser("key-info", help="show the non-secret recovery-key fingerprint")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "export-key":
            key_id = export_recovery_key(args.destination, args.key_file)
            print(json.dumps({"status": "ok", "key_id": key_id}))
        elif args.command == "import-key":
            key_id = import_recovery_key(args.source, args.key_file)
            print(json.dumps({"status": "ok", "key_id": key_id}))
        elif args.command == "decrypt":
            plaintext = decrypt_config_backup(args.backup.read_bytes(), key_path=args.key_file)
            _write_decrypted_config(args.destination, plaintext)
            print(json.dumps({"status": "ok", "destination": str(args.destination)}))
        else:
            key_id = backup_key_id(load_backup_key(args.key_file))
            print(json.dumps({"status": "ok", "key_id": key_id}))
    except (BackupCryptoError, OSError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
