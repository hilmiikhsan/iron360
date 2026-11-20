from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from ..audit import record
from ..config import get_settings
from ..database import SessionLocal, get_db
from ..engine import runner
from ..models import Scan, Target, User
from ..schemas import ScanCreate, ScanOut
from ..security import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])
settings = get_settings()


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
    scan = Scan(target_id=target.id, mode=body.mode, autonomy=body.autonomy, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    record(db, actor=user.username, action="scan_start", target_value=target.value,
           detail=f"mode={body.mode} autonomy={body.autonomy} scan_id={scan.id}")
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
    if scan.status in {"queued", "running"}:
        scan.status = "stopped"
        db.commit()
        record(db, actor=user.username, action="scan_stop", detail=f"scan_id={scan_id}")
    return scan


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

    # Replay any events already produced, then live-stream new ones.
    for event in runner.replay(scan_id):
        await websocket.send_json(event)

    q = runner.subscribe(scan_id)
    try:
        while True:
            event = await q.get()
            await websocket.send_json(event)
            if event.get("type") in {"done", "error"}:
                break
    except WebSocketDisconnect:
        pass
    finally:
        runner.unsubscribe(scan_id, q)
