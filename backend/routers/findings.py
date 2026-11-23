from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..audit import record
from ..database import get_db
from ..models import Finding, User
from ..schemas import FindingOut, FindingStatusUpdate
from ..security import get_current_user

router = APIRouter(prefix="/api/findings", tags=["findings"])

_VALID = {"confirmed", "likely", "needs_review", "false_positive"}


@router.get("", response_model=list[FindingOut])
def list_findings(target_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(Finding)
    if target_id is not None:
        q = q.filter(Finding.target_id == target_id)
    return q.order_by(Finding.created_at.desc()).all()


@router.patch("/{finding_id}/status", response_model=FindingOut)
def set_status(finding_id: int, body: FindingStatusUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if body.status not in _VALID:
        raise HTTPException(status_code=400, detail="Invalid status")
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = body.status
    db.commit()
    db.refresh(f)
    record(db, actor=user.username, action="finding_status", target_value=f.affected,
           detail=f"finding_id={finding_id} -> {body.status}")
    return f


@router.delete("/{finding_id}", status_code=204)
def delete_finding(finding_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    record(db, actor=user.username, action="finding_delete", target_value=f.affected,
           detail=f"finding_id={finding_id} title={f.title}")
    db.delete(f)
    db.commit()


@router.delete("", status_code=204)
def delete_all_findings(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    count = db.query(Finding).filter(Finding.target_id == target_id).count()
    if count == 0:
        raise HTTPException(status_code=404, detail="No findings for this target")
    db.query(Finding).filter(Finding.target_id == target_id).delete()
    db.commit()
    record(db, actor=user.username, action="findings_reset", detail=f"target_id={target_id} deleted={count}")
