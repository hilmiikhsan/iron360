from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from ..audit import record
from ..config import get_settings
from ..database import SessionLocal, get_db
from ..engine import runner
from ..models import Finding, Scan, Target, User
from ..schemas import ApprovalDecision, ChatMessage, ScanCreate, ScanOut
from ..security import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])
settings = get_settings()

PROFILES = {"quick", "full", "web", "network", "compliance"}


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(body: ScanCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = db.get(Target, body.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.authorized:
        raise HTTPException(
            status_code=403,
            detail="Target is not authorized. Mark the engagement authorized (with an SOW/NDA reference) before scanning.",
        )
    if body.mode not in {"va", "pentest"} or body.autonomy not in {"auto", "approve"}:
        raise HTTPException(status_code=400, detail="Invalid mode or autonomy")
    if body.profile not in PROFILES:
        raise HTTPException(status_code=400, detail=f"Invalid profile (allowed: {', '.join(sorted(PROFILES))})")
    scan = Scan(target_id=target.id, mode=body.mode, autonomy=body.autonomy,
                profile=body.profile, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    record(db, actor=user.username, action="scan_start", target_value=target.value,
           detail=f"mode={body.mode} profile={body.profile} autonomy={body.autonomy} scan_id={scan.id}")
    if body.mode == "pentest" and get_settings().ai_live:
        runner.start_pentest_session(scan.id)
        db.refresh(scan)
    else:
        runner.start_scan(scan.id)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(target_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(Scan)
    if target_id is not None:
        q = q.filter(Scan.target_id == target_id)
    return q.order_by(Scan.started_at.desc()).all()


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/stop", response_model=ScanOut)
def stop_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in {"queued", "running", "chat_active"}:
        runner.request_stop(scan_id)
        runner.end_pentest_session(scan_id)
        scan.status = "stopped"
        from datetime import datetime, timezone
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        record(db, actor=user.username, action="scan_stop", detail=f"scan_id={scan_id}")
    return scan


@router.post("/{scan_id}/chat")
def chat_message(scan_id: int, body: ChatMessage,
                 db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Send a message to the pentest agent. The agent processes it in the background
    and streams events via the WebSocket."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "chat_active":
        raise HTTPException(status_code=409, detail="Scan is not in chat mode")
    ok = runner.submit_chat(scan_id, body.message)
    if not ok:
        raise HTTPException(status_code=409, detail="Agent is busy processing — wait for it to finish")
    record(db, actor=user.username, action="pentest_chat", target_value=scan.target.value if scan.target else "",
           detail=f"scan_id={scan_id} message_len={len(body.message)}")
    return {"ok": True, "scan_id": scan_id}


@router.post("/{scan_id}/approve")
def approve_step(scan_id: int, body: ApprovalDecision,
                 db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Operator decision for an intrusive step held in Approve mode."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    ok = runner.submit_approval(scan_id, body.approval_id, body.approved)
    if not ok:
        raise HTTPException(status_code=409, detail="No pending approval with that id (expired or already decided)")
    record(db, actor=user.username, action="scan_approval", target_value=scan.target.value if scan.target else "",
           detail=f"scan_id={scan_id} approval_id={body.approval_id} approved={body.approved}")
    return {"ok": True, "approval_id": body.approval_id, "approved": body.approved}


def _fkey(f: Finding) -> str:
    """Identity of a finding across scans — title + affected surface (case/space-normalized)."""
    title = " ".join((f.title or "").lower().split())
    aff = " ".join((f.affected or "").lower().split())
    return f"{title}||{aff}"


def _fbrief(f: Finding) -> dict:
    return {"id": f.id, "title": f.title, "severity": f.severity, "status": f.status,
            "confidence": f.confidence, "cve": f.cve, "affected": f.affected}


@router.get("/{scan_id}/diff")
def diff_scan(scan_id: int, against: int | None = None,
              db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Delta between this scan and a baseline (new / fixed / persistent findings).

    If `against` is omitted, the previous completed scan of the same target is used —
    this is how Nessus-style 'what changed since last scan' tracking works.
    """
    cur = db.get(Scan, scan_id)
    if not cur:
        raise HTTPException(status_code=404, detail="Scan not found")
    if against is not None:
        base = db.get(Scan, against)
    else:
        base = (db.query(Scan)
                .filter(Scan.target_id == cur.target_id, Scan.id < cur.id,
                        Scan.status.in_(["done", "stopped"]))
                .order_by(Scan.id.desc()).first())
    cur_f = db.query(Finding).filter(Finding.scan_id == cur.id,
                                     Finding.status != "false_positive").all()
    if base is None:
        return {"current_scan": scan_id, "baseline_scan": None,
                "new": [_fbrief(f) for f in cur_f], "fixed": [], "persistent": [],
                "note": "No earlier scan to compare against — all findings are new."}
    base_f = db.query(Finding).filter(Finding.scan_id == base.id,
                                      Finding.status != "false_positive").all()
    base_map = {_fkey(f): f for f in base_f}
    cur_map = {_fkey(f): f for f in cur_f}
    new = [_fbrief(f) for k, f in cur_map.items() if k not in base_map]
    fixed = [_fbrief(f) for k, f in base_map.items() if k not in cur_map]
    persistent = [{**_fbrief(c), "baseline_severity": base_map[k].severity}
                  for k, c in cur_map.items() if k in base_map]
    return {"current_scan": scan_id, "baseline_scan": base.id,
            "new": new, "fixed": fixed, "persistent": persistent}


def _user_from_token(token: str | None) -> str | None:
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
        return payload.get("username")
    except jwt.PyJWTError:
        return None


@router.websocket("/{scan_id}/stream")
async def stream(websocket: WebSocket, scan_id: int, token: str | None = None):
    # WebSocket auth via query token (browsers can't set Authorization on WS).
    username = _user_from_token(token)
    if not username:
        await websocket.close(code=4401)
        return
    await websocket.accept()

    # Replay any events already produced (from in-memory history), then live-stream new ones.
    # Fallback: if memory history is empty (e.g. server restarted mid-scan), replay from DB timeline.
    history = runner.replay(scan_id)
    if not history:
        db_fallback = SessionLocal()
        try:
            snap = db_fallback.get(Scan, scan_id)
            if snap and snap.timeline:
                history = snap.timeline
        finally:
            db_fallback.close()
    for event in history:
        await websocket.send_json(event)

    q = runner.subscribe(scan_id)
    try:
        while True:
            event = await q.get()
            await websocket.send_json(event)
            if event.get("type") in {"done", "error", "session_end"}:
                break
    except WebSocketDisconnect:
        pass
    finally:
        runner.unsubscribe(scan_id, q)
