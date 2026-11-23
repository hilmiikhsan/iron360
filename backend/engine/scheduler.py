"""Scheduled scan scheduler for Iron360.

Runs in the background and checks every 60s for scheduled scans that are due.
Uses croniter to parse cron expressions and calculate next run times.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import threading

from ..database import SessionLocal
from ..models import Scan, ScheduledScan, Target

log = logging.getLogger("iron360.scheduler")

_loop: asyncio.AbstractEventLoop | None = None
_task: asyncio.Task | None = None


def _next_run(cron_expr: str, after: dt.datetime | None = None) -> dt.datetime | None:
    try:
        from croniter import croniter
        base = after or dt.datetime.now(dt.timezone.utc)
        return croniter(cron_expr, base).get_next(dt.datetime).replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


def _check_and_run() -> None:
    from . import runner

    db = SessionLocal()
    try:
        now = dt.datetime.now(dt.timezone.utc)
        schedules = db.query(ScheduledScan).filter(
            ScheduledScan.enabled == True,  # noqa: E712
            ScheduledScan.next_run <= now,
        ).all()

        for sched in schedules:
            target = db.get(Target, sched.target_id)
            if not target or not target.authorized:
                sched.next_run = _next_run(sched.cron_expr, now)
                db.commit()
                continue

            log.info("Scheduled scan triggered: target=%s profile=%s", target.value, sched.profile)
            try:
                scan = Scan(target_id=target.id, mode="va", autonomy="auto",
                            profile=sched.profile, status="queued")
                db.add(scan)
                db.commit()
                db.refresh(scan)
                runner.start_scan(scan.id)
            except Exception:
                log.exception("Failed to start scheduled scan for target %s", target.value)

            sched.last_run = now
            sched.next_run = _next_run(sched.cron_expr, now)
            db.commit()
    except Exception:
        log.exception("Scheduler tick error")
    finally:
        db.close()


async def _scheduler_loop() -> None:
    log.info("Scan scheduler started (60s interval)")
    while True:
        await asyncio.sleep(60)
        try:
            await asyncio.get_running_loop().run_in_executor(None, _check_and_run)
        except asyncio.CancelledError:
            break
        except Exception:
            log.exception("Scheduler loop error")


def start(loop: asyncio.AbstractEventLoop) -> None:
    global _loop, _task
    _loop = loop
    _task = loop.create_task(_scheduler_loop())


def stop() -> None:
    global _task
    if _task:
        _task.cancel()
        _task = None


def compute_next_run(cron_expr: str) -> dt.datetime | None:
    return _next_run(cron_expr)
