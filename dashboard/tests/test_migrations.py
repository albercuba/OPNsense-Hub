import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "dashboard/migrations/versions/0001_current_schema_baseline.py"
ALEMBIC_INI = ROOT / "dashboard/alembic.ini"
POSTGRES_URL = "postgresql+psycopg://opnsensehub:opnsensehub@localhost:5432/opnsensehub"


def run_alembic(*args: str) -> str:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "dashboard"),
        "DATABASE_URL": POSTGRES_URL,
    }
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout + result.stderr


def test_baseline_is_frozen_and_does_not_import_current_metadata():
    source = BASELINE.read_text()

    assert "from app.models" not in source
    assert "Base.metadata" not in source
    assert "create_all" not in source
    assert "drop_all" not in source
    assert 'op.create_table(\n        "users"' in source
    assert 'op.create_table(\n        "devices"' in source


def test_alembic_has_single_head():
    output = run_alembic("heads")
    heads = [line for line in output.splitlines() if "(head)" in line]

    assert heads == ["0016_config_backup_plaintext_mode (head)"]


def test_fresh_postgresql_upgrade_sql_uses_static_baseline_and_later_migrations():
    output = run_alembic("upgrade", "head", "--sql")

    assert "CREATE TABLE users" in output
    assert "CREATE TABLE sessions" in output
    assert "CREATE TABLE devices" in output
    assert "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider" in output
    assert "CREATE TABLE pending_mfa_logins" in output
    assert "ALTER TABLE devices ADD COLUMN device_token_issued_at" in output
    assert "opnsense-config-plaintext-v1" in output
    assert "Base.metadata" not in output
    assert "create_all" not in output


def test_legacy_postgresql_upgrade_sql_from_baseline_to_head():
    output = run_alembic(
        "upgrade",
        "0001_current_schema_baseline:head",
        "--sql",
    )

    assert "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider" in output
    assert "CREATE TABLE IF NOT EXISTS device_proxy_sessions" in output
    assert "ALTER TABLE device_proxy_sessions ADD COLUMN dashboard_session_id" in output
    assert "ALTER TABLE device_backups RENAME content TO encrypted_payload" in output
    assert "ALTER TABLE devices ADD CONSTRAINT uq_devices_wg_public_key" in output
    assert "CREATE TABLE pending_mfa_logins" in output
    assert "ALTER TABLE devices ADD COLUMN device_token_expires_at" in output
    assert "opnsense-config-plaintext-v1" in output


def test_incremental_postgresql_upgrade_sql_from_previous_head():
    output = run_alembic(
        "upgrade",
        "0014_pending_mfa_login_attempts:head",
        "--sql",
    )

    assert "ALTER TABLE devices ADD COLUMN device_token_issued_at" in output
    assert "ALTER TABLE devices ADD COLUMN device_token_expires_at" in output
    assert "opnsense-config-plaintext-v1" in output
    assert "UPDATE alembic_version SET version_num='0016_config_backup_plaintext_mode'" in output


def test_incremental_postgresql_upgrade_sql_from_device_token_head():
    output = run_alembic(
        "upgrade",
        "0015_device_token_expiry:head",
        "--sql",
    )

    assert "DROP CONSTRAINT ck_device_backups_encrypted_format" in output
    assert "opnsense-config-plaintext-v1" in output
    assert "UPDATE alembic_version SET version_num='0016_config_backup_plaintext_mode'" in output
