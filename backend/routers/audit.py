from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, User
from ..schemas import AuditOut
from ..security import get_current_user

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit(limit: int = 200, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(AuditLog).order_by(AuditLog.at.desc()).limit(min(limit, 1000)).all()
