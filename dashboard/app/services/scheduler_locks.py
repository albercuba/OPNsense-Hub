from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager

from sqlalchemy import text

from ..database import SessionLocal, engine
from ..web import settings

logger = logging.getLogger(__name__)
_LOCK_NAMESPACE = "opnsense-hub-scheduler"


def advisory_lock_key(name: str) -> int:
    digest = hashlib.blake2b(
        f"{_LOCK_NAMESPACE}:{name}".encode(), digest_size=8
    ).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


def scheduler_locks_supported() -> bool:
    return engine.url.get_backend_name().startswith("postgresql")


@contextmanager
def postgres_advisory_lock(name: str) -> Iterator[bool]:
    key = advisory_lock_key(name)
    with SessionLocal() as db:
        acquired = bool(
            db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}).scalar()
        )
        try:
            yield acquired
        finally:
            if acquired:
                db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
                db.commit()


async def run_cluster_singleton_loop(
    name: str,
    loop_factory: Callable[[], Awaitable[None]],
) -> None:
    if not scheduler_locks_supported():
        await loop_factory()
        return

    poll_seconds = max(1, settings.scheduler_lock_poll_seconds)
    while True:
        try:
            with postgres_advisory_lock(name) as acquired:
                if acquired:
                    logger.info("Acquired scheduler lock: %s", name)
                    await loop_factory()
                else:
                    logger.info(
                        "Scheduler lock already held elsewhere; waiting: %s", name
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduler lock worker failed: %s", name)
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(poll_seconds)
