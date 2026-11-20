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
    # Human validation is the final gate — record who changed the verdict.
    record(db, actor=user.username, action="finding_status", target_value=f.affected,
           detail=f"finding_id={finding_id} -> {body.status}")
    return f
