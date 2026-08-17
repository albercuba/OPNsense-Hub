from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = (
    Path(__file__).resolve().parents[1]
    / "src/opnsense/scripts/OPNsense/OPNsenseHub"
)
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import heartbeat  # noqa: E402
from backup_crypto import (  # noqa: E402
    BACKUP_FORMAT,
    BackupCryptoError,
    backup_key_id,
    decrypt_config_backup,
    encrypt_config_backup,
    ensure_backup_key,
    export_recovery_key,
    import_recovery_key,
)


class FakeHttpResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return b'{"ok":true}'


class BackupCryptoTests(unittest.TestCase):
    def test_encrypt_decrypt_round_trip_and_no_plaintext_in_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = root / "config.xml"
            key_file = root / "state" / "backup_master.key"
            plaintext = (
                b"<opnsense><password>secret-hash</password>"
                b"<private-key>private-material</private-key></opnsense>"
            )
            config.write_bytes(plaintext)

            envelope = encrypt_config_backup(
                config,
                device_id="01234567-89ab-cdef-0123-456789abcdef",
                source_hostname="firewall.example.test",
                captured_at="2026-08-17T12:00:00+00:00",
                key_path=key_file,
            )
            serialized = json.dumps(envelope, sort_keys=True)

            self.assertEqual(envelope["format"], BACKUP_FORMAT)
            self.assertNotIn("secret-hash", serialized)
            self.assertNotIn("private-material", serialized)
            self.assertNotIn("<opnsense", serialized)
            self.assertEqual(
                decrypt_config_backup(envelope, key_path=key_file), plaintext
            )
            self.assertEqual(
                stat.S_IMODE(key_file.stat().st_mode),
                stat.S_IRUSR | stat.S_IWUSR,
            )

    def test_tampering_is_rejected_before_decryption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = root / "config.xml"
            key_file = root / "backup_master.key"
            config.write_text("<opnsense><secret>value</secret></opnsense>")
            envelope = encrypt_config_backup(
                config,
                device_id="01234567-89ab-cdef-0123-456789abcdef",
                source_hostname="firewall",
                key_path=key_file,
            )
            envelope["source_hostname"] = "attacker-modified"

            with self.assertRaisesRegex(BackupCryptoError, "authentication failed"):
                decrypt_config_backup(envelope, key_path=key_file)

    def test_recovery_key_export_import_restores_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = root / "config.xml"
            source_key = root / "source" / "backup_master.key"
            imported_key = root / "replacement" / "backup_master.key"
            recovery_file = root / "offline" / "firewall-recovery-key.json"
            plaintext = b"<opnsense><vpn-secret>recover-me</vpn-secret></opnsense>"
            config.write_bytes(plaintext)
            envelope = encrypt_config_backup(
                config,
                device_id="01234567-89ab-cdef-0123-456789abcdef",
                source_hostname="firewall",
                key_path=source_key,
            )

            exported_key_id = export_recovery_key(recovery_file, source_key)
            imported_key_id = import_recovery_key(recovery_file, imported_key)

            self.assertEqual(exported_key_id, imported_key_id)
            self.assertEqual(
                exported_key_id, backup_key_id(ensure_backup_key(imported_key))
            )
            self.assertEqual(
                decrypt_config_backup(envelope, key_path=imported_key), plaintext
            )
            self.assertEqual(
                stat.S_IMODE(recovery_file.stat().st_mode),
                stat.S_IRUSR | stat.S_IWUSR,
            )

    def test_heartbeat_advertises_only_encrypted_backup_format(self) -> None:
        payload = heartbeat.heartbeat_payload({})
        self.assertEqual(payload["backup_formats"], [BACKUP_FORMAT])

    def test_heartbeat_upload_contains_only_encrypted_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = root / "config.xml"
            key_file = root / "backup_master.key"
            plaintext = "<opnsense><api-key>must-not-leave-plaintext</api-key></opnsense>"
            config.write_text(plaintext)
            captured_request = None

            def encrypt_for_test(path, **kwargs):
                return encrypt_config_backup(path, key_path=key_file, **kwargs)

            def fake_urlopen(request, timeout):
                nonlocal captured_request
                captured_request = request
                self.assertEqual(timeout, 30)
                return FakeHttpResponse()

            state = {
                "hub_url": "https://hub.example.test",
                "device_id": "01234567-89ab-cdef-0123-456789abcdef",
                "device_token": "device-token",
            }
            with (
                patch.object(heartbeat, "CONFIG_XML", config),
                patch.object(heartbeat, "encrypt_config_backup", encrypt_for_test),
                patch.object(heartbeat, "save_state", lambda _state: None),
                patch.object(heartbeat.urllib.request, "urlopen", fake_urlopen),
            ):
                heartbeat.upload_backup(state)

            self.assertIsNotNone(captured_request)
            request_body = captured_request.data.decode("utf-8")
            self.assertNotIn("must-not-leave-plaintext", request_body)
            self.assertNotIn("<opnsense", request_body)
            self.assertNotIn("backup_master", request_body)
            payload = json.loads(request_body)
            self.assertEqual(payload["format"], BACKUP_FORMAT)
            self.assertEqual(payload["encrypted_backup"]["format"], BACKUP_FORMAT)

    def test_decrypt_without_key_does_not_create_wrong_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = root / "config.xml"
            source_key = root / "source.key"
            missing_key = root / "missing.key"
            config.write_text("<opnsense />")
            envelope = encrypt_config_backup(
                config,
                device_id="01234567-89ab-cdef-0123-456789abcdef",
                source_hostname="firewall",
                key_path=source_key,
            )

            with self.assertRaisesRegex(BackupCryptoError, "import the recovery key"):
                decrypt_config_backup(envelope, key_path=missing_key)
            self.assertFalse(missing_key.exists())

    def test_missing_established_key_does_not_silently_rotate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing_key = Path(temporary_directory) / "missing.key"
            state = {
                "hub_url": "https://hub.example.test",
                "device_id": "01234567-89ab-cdef-0123-456789abcdef",
                "device_token": "device-token",
                "backup_key_id": "a" * 24,
            }
            with patch.object(heartbeat, "BACKUP_KEY_FILE", missing_key):
                with self.assertRaisesRegex(BackupCryptoError, "missing"):
                    heartbeat.upload_backup(state)

    def test_wrong_recovery_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config = root / "config.xml"
            source_key = root / "source.key"
            wrong_key = root / "wrong.key"
            config.write_text("<opnsense />")
            envelope = encrypt_config_backup(
                config,
                device_id="01234567-89ab-cdef-0123-456789abcdef",
                source_hostname="firewall",
                key_path=source_key,
            )
            ensure_backup_key(wrong_key)

            with self.assertRaisesRegex(BackupCryptoError, "does not match"):
                decrypt_config_backup(envelope, key_path=wrong_key)


if __name__ == "__main__":
    unittest.main()
