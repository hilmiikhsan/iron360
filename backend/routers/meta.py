from __future__ import annotations

from fastapi import APIRouter, Depends

from ..config import get_settings
from ..engine import knowledge, tools
from ..models import User
from ..security import get_current_user

router = APIRouter(prefix="/api", tags=["meta"])
settings = get_settings()


@router.get("/status")
def status(user: User = Depends(get_current_user)) -> dict:
    return {
        "ai_engine": "live" if settings.ai_live else "simulation",
        "ai_model": settings.ai_model if settings.ai_live else None,
        "executor_enabled": settings.executor_enabled,
        "tools": tools.installed_tools(),
        "env": settings.env,
    }


@router.get("/knowledge")
def knowledge_catalog(user: User = Depends(get_current_user)) -> dict:
    return {"references": knowledge.catalog()}
