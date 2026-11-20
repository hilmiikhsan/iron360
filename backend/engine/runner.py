"""Background scan runner + live event bus.

A scan executes in its own thread (executor subprocess calls are blocking). Events
are fan-outed to any subscribed WebSocket via per-scan asyncio queues, and the full
timeline + findings are persisted to the DB when the run ends.
"""
from __future__ import annotations

import asyncio
import threading
from collections import defaultdict

from ..database import SessionLocal
from ..models import Finding, Scan, Target
from . import orchestrator

# scan_id -> set of asyncio.Queue (one per connected websocket)
_subscribers: dict[int, set[asyncio.Queue]] = defaultdict(set)
# scan_id -> accumulated events (so a late subscriber can replay)
_history: dict[int, list[dict]] = defaultdict(list)
# scan_id -> stop signal (set when the operator presses Stop)
_stop_events: dict[int, threading.Event] = {}
_loop: asyncio.AbstractEventLoop | None = None


def request_stop(scan_id: int) -> None:
    ev = _stop_events.get(scan_id)
    if ev is not None:
        ev.set()


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


def subscribe(scan_id: int) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _subscribers[scan_id].add(q)
    return q


def unsubscribe(scan_id: int, q: asyncio.Queue) -> None:
    _subscribers[scan_id].discard(q)


def replay(scan_id: int) -> list[dict]:
    return list(_history.get(scan_id, []))


def _publish(scan_id: int, event: dict) -> None:
    _history[scan_id].append(event)
    if _loop is None:
        return
    for q in list(_subscribers.get(scan_id, ())):
        _loop.call_soon_threadsafe(q.put_nowait, event)


def start_scan(scan_id: int) -> None:
    t = threading.Thread(target=_run, args=(scan_id,), daemon=True)
    t.start()


def _run(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        target = db.get(Target, scan.target_id)
        scan.status = "running"
        scan.timeline = []
        db.commit()

        stop_event = threading.Event()
        _stop_events[scan_id] = stop_event
        timeline: list[dict] = []

        def emit(event: dict) -> None:
            timeline.append(event)
            _publish(scan_id, event)

        def on_finding(data: dict) -> None:
            f = Finding(
                target_id=target.id, scan_id=scan_id,
                title=data.get("title", "Untitled"),
                severity=data.get("severity", "info"),
                status=data.get("status", "needs_review"),
                confidence=int(data.get("confidence", 0)),
                cve=data.get("cve", ""),
                affected=data.get("affected", ""),
                description=data.get("description", ""),
                evidence=data.get("evidence", ""),
                remediation=data.get("remediation", ""),
                fix_config=data.get("fix_config", ""),
                fix_steps=data.get("fix_steps", ""),
                sources=data.get("sources", []),
            )
            db.add(f)
            db.commit()

        summary = orchestrator.run_assessment(
            target, scan.mode, scan.autonomy, emit, on_finding, stop_event,
            profile=scan.profile or "full",
        )

        scan.summary = summary
        scan.timeline = timeline
        scan.status = "stopped" if stop_event.is_set() else "done"
        from datetime import datetime, timezone
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        _publish(scan_id, {"type": "done", "summary": summary, "stopped": stop_event.is_set()})
    except Exception as e:  # noqa: BLE001
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.summary = f"error: {e}"
            db.commit()
        _publish(scan_id, {"type": "error", "text": str(e)})
    finally:
        _stop_events.pop(scan_id, None)
        db.close()
