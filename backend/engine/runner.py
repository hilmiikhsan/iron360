"""Background scan runner + live event bus.

A scan executes in its own thread (executor subprocess calls are blocking). Events
are fan-outed to any subscribed WebSocket via per-scan asyncio queues, and the full
timeline + findings are persisted to the DB when the run ends.

Supports two modes:
  - VA / legacy pentest: hardcoded pipeline via orchestrator.run_assessment()
  - Pentest agent (chat): interactive Claude agent via agent.run_agent_turn()
"""
from __future__ import annotations

import asyncio
import threading
import time
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
# scan_id -> {approval_id: {"event": Event, "approved": bool}} for interactive Approve mode
_approvals: dict[int, dict[str, dict]] = defaultdict(dict)
# scan_id -> agent conversation messages (pentest chat mode)
_chat_sessions: dict[int, list[dict]] = {}
# scan_id -> lock to serialize chat messages
_chat_locks: dict[int, threading.Lock] = {}
_loop: asyncio.AbstractEventLoop | None = None


def request_stop(scan_id: int) -> None:
    ev = _stop_events.get(scan_id)
    if ev is not None:
        ev.set()


def submit_approval(scan_id: int, approval_id: str, approved: bool) -> bool:
    """Called from the HTTP endpoint when the operator approves/denies an intrusive step."""
    slot = _approvals.get(scan_id, {}).get(approval_id)
    if slot is None:
        return False
    slot["approved"] = bool(approved)
    slot["event"].set()
    return True


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


def start_pentest_session(scan_id: int) -> None:
    """Initialize a pentest chat session (no auto-run — waits for operator messages)."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "chat_active"
        scan.timeline = []
        db.commit()

        _stop_events[scan_id] = threading.Event()
        _chat_sessions[scan_id] = []
        _chat_locks[scan_id] = threading.Lock()
        _publish(scan_id, {"type": "note", "text": "Pentest agent ready. Type your instructions."})
        _publish(scan_id, {"type": "chat_ready"})
    finally:
        db.close()


def submit_chat(scan_id: int, message: str) -> bool:
    """Submit an operator message to the pentest agent. Runs in a background thread."""
    if scan_id not in _chat_sessions:
        return False
    lock = _chat_locks.get(scan_id)
    if lock and lock.locked():
        return False  # agent is still processing
    t = threading.Thread(target=_run_chat_turn, args=(scan_id, message), daemon=True)
    t.start()
    return True


def _run_chat_turn(scan_id: int, message: str) -> None:
    """Process one operator message through the pentest agent."""
    from . import agent

    lock = _chat_locks.get(scan_id)
    if not lock:
        return
    with lock:
        db = SessionLocal()
        try:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            target = db.get(Target, scan.target_id)
            stop_event = _stop_events.get(scan_id)
            timeline = list(scan.timeline or [])

            _emit_count = [0]

            def emit(event: dict) -> None:
                timeline.append(event)
                _publish(scan_id, event)
                _emit_count[0] += 1
                if _emit_count[0] % 20 == 0:
                    try:
                        snap = db.get(Scan, scan_id)
                        if snap:
                            snap.timeline = list(timeline)
                            db.commit()
                    except Exception:
                        pass

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

            # Emit the user message
            emit({"type": "chat_user", "text": message})

            # Add user message to conversation
            messages = _chat_sessions.get(scan_id, [])
            messages.append({"role": "user", "content": message})

            # Run agent turn
            emit({"type": "agent_status", "status": "thinking"})
            messages = agent.run_agent_turn(target, messages, emit, on_finding, stop_event)
            _chat_sessions[scan_id] = messages

            # Persist
            scan.timeline = timeline
            db.commit()

            emit({"type": "agent_status", "status": "ready"})
            emit({"type": "chat_turn_done"})
        except Exception as e:
            _publish(scan_id, {"type": "error", "text": f"Agent error: {e}"})
        finally:
            db.close()


def end_pentest_session(scan_id: int) -> None:
    """End a pentest chat session."""
    _chat_sessions.pop(scan_id, None)
    _chat_locks.pop(scan_id, None)
    stop_ev = _stop_events.get(scan_id)
    if stop_ev:
        stop_ev.set()


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

        _emit_count = [0]

        def emit(event: dict) -> None:
            timeline.append(event)
            _publish(scan_id, event)
            _emit_count[0] += 1
            if _emit_count[0] % 20 == 0:
                try:
                    snap = db.get(Scan, scan_id)
                    if snap:
                        snap.timeline = list(timeline)
                        db.commit()
                except Exception:
                    pass

        def ask_approval(approval_id: str, timeout: float = 300.0) -> bool:
            ev = threading.Event()
            _approvals[scan_id][approval_id] = {"event": ev, "approved": False}
            deadline = time.time() + timeout
            while time.time() < deadline:
                if ev.wait(timeout=0.5):
                    break
                if stop_event.is_set():
                    break
            slot = _approvals[scan_id].pop(approval_id, {})
            return bool(slot.get("approved"))

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
            profile=scan.profile or "full", ask_approval=ask_approval,
        )

        scan.summary = summary
        scan.timeline = timeline
        scan.status = "stopped" if stop_event.is_set() else "done"
        from datetime import datetime, timezone
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        _publish(scan_id, {"type": "done", "summary": summary, "stopped": stop_event.is_set()})
    except Exception as e:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.summary = f"error: {e}"
            db.commit()
        _publish(scan_id, {"type": "error", "text": str(e)})
    finally:
        _stop_events.pop(scan_id, None)
        _approvals.pop(scan_id, None)
        db.close()
