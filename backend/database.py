"""SQLAlchemy engine/session setup for Iron360."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

from .config import get_settings

settings = get_settings()

engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False},  # SQLite + threaded server
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # Import models so they register on Base.metadata before create_all.
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate() -> None:
    """Lightweight additive migrations (SQLite create_all won't alter existing tables)."""
    from sqlalchemy import text
    add_cols = {
        "targets": {
            "auth_type": "VARCHAR(16) DEFAULT 'none'",
            "auth_user": "VARCHAR(64) DEFAULT ''",
            "auth_secret": "TEXT DEFAULT ''",
            "auth_port": "INTEGER DEFAULT 22",
        },
        "findings": {
            "fix_config": "TEXT DEFAULT ''",
            "fix_steps": "TEXT DEFAULT ''",
        },
    }
    with engine.begin() as conn:
        for table, cols in add_cols.items():
            try:
                existing = {r[1] for r in conn.execute(text(f"PRAGMA table_info({table})"))}
            except Exception:  # noqa: BLE001
                continue
            for col, ddl in cols.items():
                if col not in existing:
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
                    except Exception:  # noqa: BLE001
                        pass
