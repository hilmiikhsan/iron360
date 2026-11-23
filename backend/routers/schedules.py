from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..audit import record
from ..database import get_db
from ..engine.scheduler import compute_next_run
from ..models import ScheduledScan, Target, User
from ..schemas import ScheduledScanCreate, ScheduledScanOut, ScheduledScanUpdate
from ..security import get_current_user

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


@router.get("", response_model=list[ScheduledScanOut])
def list_schedules(target_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(ScheduledScan)
    if target_id is not None:
        q = q.filter(ScheduledScan.target_id == target_id)
    return q.order_by(ScheduledScan.created_at.desc()).all()


@router.post("", response_model=ScheduledScanOut, status_code=201)
def create_schedule(body: ScheduledScanCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = db.get(Target, body.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    nxt = compute_next_run(body.cron_expr)
    if nxt is None:
        raise HTTPException(status_code=400, detail="Invalid cron expression")
    sched = ScheduledScan(
        target_id=body.target_id,
        profile=body.profile,
        cron_expr=body.cron_expr,
        next_run=nxt,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    record(db, actor=user.username, action="schedule_create", target_value=target.value,
           detail=f"schedule_id={sched.id} cron={body.cron_expr} profile={body.profile}")
    return sched


@router.patch("/{schedule_id}", response_model=ScheduledScanOut)
def update_schedule(schedule_id: int, body: ScheduledScanUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sched = db.get(ScheduledScan, schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if body.cron_expr is not None:
        nxt = compute_next_run(body.cron_expr)
        if nxt is None:
            raise HTTPException(status_code=400, detail="Invalid cron expression")
        sched.cron_expr = body.cron_expr
        sched.next_run = nxt
    if body.profile is not None:
        sched.profile = body.profile
    if body.enabled is not None:
        sched.enabled = body.enabled
        if body.enabled and not sched.next_run:
            sched.next_run = compute_next_run(sched.cron_expr)
    db.commit()
    db.refresh(sched)
    record(db, actor=user.username, action="schedule_update", detail=f"schedule_id={schedule_id}")
    return sched


@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sched = db.get(ScheduledScan, schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    record(db, actor=user.username, action="schedule_delete", detail=f"schedule_id={schedule_id}")
    db.delete(sched)
    db.commit()
