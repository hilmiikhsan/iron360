from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..audit import record
from ..config import get_settings
from ..database import get_db
from ..engine import report
from ..models import Finding, Scan, Target, User
from ..security import get_current_user

router = APIRouter(tags=["reports"])
settings = get_settings()


def _render(db: Session, target_id: int, actor: str) -> str:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    findings = db.query(Finding).filter(Finding.target_id == target_id).all()
    summary = report.executive_summary(target, findings)
    # Pull exploit-db / CVE intel from the target's latest scan timeline
    scan = db.query(Scan).filter(Scan.target_id == target_id).order_by(Scan.started_at.desc()).first()
    intel: dict = {}
    if scan and scan.timeline:
        for e in scan.timeline:
            if isinstance(e, dict) and e.get("type") == "intel":
                intel[e.get("kind")] = e.get("items")
    record(db, actor=actor, action="report_generate", target_value=target.value,
           detail=f"findings={len(findings)}")
    return report.build_report_html(target, findings, summary, intel)


@router.get("/api/targets/{target_id}/report", response_class=HTMLResponse)
def report_json(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Authenticated preview (returns the HTML to embed in the SPA)."""
    return HTMLResponse(_render(db, target_id, user.username))


@router.get("/report/{target_id}", response_class=HTMLResponse)
def report_page(target_id: int, token: str | None = None, db: Session = Depends(get_db)):
    """Standalone printable page (opened in a new tab; token via query string)."""
    username = None
    if token:
        try:
            username = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg]).get("username")
        except jwt.PyJWTError:
            username = None
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return HTMLResponse(_render(db, target_id, username))
