"""Iron360 — FastAPI application entrypoint.

Run:  uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .database import SessionLocal, init_db
from .engine import runner
from .models import User
from .routers import audit, auth, findings, meta, modules, reports, scans, schedules, targets
from .security import hash_password

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("iron360")
settings = get_settings()
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def seed_admin() -> None:
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        if not settings.admin_password:
            log.warning("No users and IRON360_ADMIN_PASSWORD unset — no admin seeded. "
                        "Set it in .env and restart to create the first admin.")
            return
        db.add(User(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            role="admin",
        ))
        db.commit()
        log.info("Seeded first admin user '%s'. Rotate the password after first login.", settings.admin_username)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_admin()
    loop = asyncio.get_running_loop()
    runner.bind_loop(loop)
    from .engine import scheduler
    scheduler.start(loop)
    from .engine.tools import REGISTRY
    cph_tools = sum(1 for k in REGISTRY if k.startswith("cphunter_"))
    log.info("Iron360 up — AI engine: %s, tools: %d (%d CPHunter CVE modules)",
             "LIVE" if settings.ai_live else "SIMULATION", len(REGISTRY), cph_tools)
    yield


app = FastAPI(title="Iron360 VAPT AI", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # CSP: self only; the SPA is self-contained (no external script/style hosts).
    # The standalone report page is server-generated and uses an inline print handler,
    # so it gets a narrowly-relaxed script-src for that one route only.
    if request.url.path.startswith("/report/"):
        script_src = "script-src 'self' 'unsafe-inline'"
    else:
        script_src = "script-src 'self'"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; {script_src}; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'"
    )
    return response


for r in (auth.router, targets.router, scans.router, findings.router, audit.router,
          meta.router, reports.router, modules.router, schedules.router):
    app.include_router(r)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


# ---- Serve the SPA frontend ----
# Prefer dist/ (minified+obfuscated build) over raw assets/
_ASSETS_DIR = FRONTEND_DIR / "dist" if (FRONTEND_DIR / "dist").exists() else FRONTEND_DIR / "assets"
if _ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=_ASSETS_DIR), name="assets")


@app.get("/")
def index() -> FileResponse:
    built_index = FRONTEND_DIR / "dist" / "index.html"
    return FileResponse(built_index if built_index.exists() else FRONTEND_DIR / "index.html")


@app.exception_handler(404)
async def spa_fallback(request: Request, exc):
    # Let API 404s stay JSON; serve the SPA for everything else.
    if request.url.path.startswith(("/api", "/healthz", "/assets")):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return FileResponse(FRONTEND_DIR / "index.html")
