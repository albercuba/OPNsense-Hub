from pathlib import Path

import pytest

from app.config import Settings
from app.hardening import runtime_validation_errors
from app.services import scheduler_locks

ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / "dashboard/app/main.py"


def production_settings(**overrides):
    values = {
        "app_env": "production",
        "public_url": "https://hub.example.com",
        "proxy_public_url": "https://proxy.example.com",
        "database_url": "postgresql+psycopg://opnsensehub:opnsensehub@db:5432/opnsensehub",
        "secret_key": "x" * 32,
        "initial_admin_email": "admin@hub.example.com",
        "initial_admin_password": "StrongPassword123",
        "session_secure": True,
        "proxy_verify_tls": True,
        "wg_dry_run": False,
        "allowed_hosts": "hub.example.com,proxy.example.com",
        "rate_limit_backend": "edge",
    }
    values.update(overrides)
    return Settings(**values)


def test_scheduler_lock_key_is_stable_signed_bigint():
    key = scheduler_locks.advisory_lock_key("device_health_checks")

    assert key == scheduler_locks.advisory_lock_key("device_health_checks")
    assert key != scheduler_locks.advisory_lock_key("firmware_schedule")
    assert -(2**63) <= key <= 2**63 - 1


def test_postgres_advisory_lock_releases_when_acquired(monkeypatch):
    calls = []

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar(self):
            return self.value

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, statement, params):
            calls.append((str(statement), params["key"]))
            if "pg_try_advisory_lock" in str(statement):
                return Result(True)
            return Result(True)

        def commit(self):
            calls.append(("commit", None))

    monkeypatch.setattr(scheduler_locks, "SessionLocal", FakeSession)

    with scheduler_locks.postgres_advisory_lock("log_retention") as acquired:
        assert acquired is True

    assert calls[0][0] == "SELECT pg_try_advisory_lock(:key)"
    assert calls[1][0] == "SELECT pg_advisory_unlock(:key)"
    assert calls[1][1] == calls[0][1]
    assert calls[2] == ("commit", None)


def test_postgres_advisory_lock_does_not_unlock_when_not_acquired(monkeypatch):
    calls = []

    class Result:
        def scalar(self):
            return False

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, statement, params):
            calls.append(str(statement))
            return Result()

        def commit(self):
            calls.append("commit")

    monkeypatch.setattr(scheduler_locks, "SessionLocal", FakeSession)

    with scheduler_locks.postgres_advisory_lock("firmware_schedule") as acquired:
        assert acquired is False

    assert calls == ["SELECT pg_try_advisory_lock(:key)"]


@pytest.mark.anyio
async def test_cluster_singleton_loop_bypasses_locks_without_postgresql(monkeypatch):
    calls = []

    async def loop_once():
        calls.append("ran")

    monkeypatch.setattr(scheduler_locks, "scheduler_locks_supported", lambda: False)

    await scheduler_locks.run_cluster_singleton_loop("device_health_checks", loop_once)

    assert calls == ["ran"]


def test_lifespan_starts_background_loops_through_cluster_singleton_wrapper():
    source = MAIN.read_text()

    assert 'run_cluster_singleton_loop("device_health_checks", device_health_check_loop)' in source
    assert 'run_cluster_singleton_loop("firmware_schedule", firmware_check_schedule_loop)' in source
    assert 'run_cluster_singleton_loop("log_retention", log_retention_loop)' in source


def test_runtime_validation_rejects_invalid_scheduler_lock_poll_seconds():
    errors = runtime_validation_errors(
        production_settings(scheduler_lock_poll_seconds=0)
    )

    assert any("SCHEDULER_LOCK_POLL_SECONDS" in error for error in errors)
