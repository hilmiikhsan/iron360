"""Audit logging helper — every sensitive/outbound action is recorded."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog


def record(
    db: Session,
    *,
    actor: str,
    action: str,
    target_value: str = "",
    detail: str = "",
    outcome: str = "ok",
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            target_value=target_value,
            detail=detail[:4000],
            outcome=outcome,
        )
    )
    db.commit()
