from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..audit import record
from ..database import get_db
from ..engine import scope
from ..models import Target, User
from ..schemas import TargetCreate, TargetOut, TargetUpdate
from ..security import get_current_user

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Target).order_by(Target.created_at.desc()).all()


@router.post("", response_model=TargetOut, status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    value = scope.normalize_host(body.value) if body.kind != "cidr" else body.value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="Invalid target value")
    extra = [scope.normalize_host(s) for s in body.scope_extra if s.strip()]
    t = Target(
        label=body.label, value=value, kind=body.kind, engagement=body.engagement,
        authorized=body.authorized, authorization_ref=body.authorization_ref,
        scope_extra=extra, notes=body.notes,
        auth_type=body.auth_type, auth_user=body.auth_user,
        auth_secret=body.auth_secret, auth_port=body.auth_port,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    record(db, actor=user.username, action="target_create", target_value=t.value,
           detail=f"authorized={t.authorized} ref={t.authorization_ref}")
    return t


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    return t


@router.patch("/{target_id}", response_model=TargetOut)
def update_target(target_id: int, body: TargetUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    data = body.model_dump(exclude_unset=True)
    if "scope_extra" in data and data["scope_extra"] is not None:
        data["scope_extra"] = [scope.normalize_host(s) for s in data["scope_extra"] if s.strip()]
    for k, v in data.items():
        setattr(t, k, v)
    db.commit()
    db.refresh(t)
    record(db, actor=user.username, action="target_update", target_value=t.value, detail=str(data))
    return t


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    val = t.value
    db.delete(t)
    db.commit()
    record(db, actor=user.username, action="target_delete", target_value=val)
