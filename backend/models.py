"""ORM models for Iron360.

Core domain:
  User      -> who can log in
  Target    -> one in-scope domain/IP == one focused workspace (Ironcloud-style)
  Scan      -> one VA/Pentest run against a target (holds the agent timeline)
  Finding   -> a vulnerability, with confidence + validation state (anti-FP)
  AuditLog  -> immutable record of every sensitive/outbound action
"""
from __future__ import annotations

import datetime as dt
from sqlalchemy import String, Integer, Text, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Target(Base):
    """One target == one workspace. VA/PT is always scoped to a single target."""
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(128))            # friendly name, e.g. "Indorama Web"
    value: Mapped[str] = mapped_column(String(255), index=True)  # domain or IP
    kind: Mapped[str] = mapped_column(String(16), default="domain")  # domain | ip | cidr
    engagement: Mapped[str] = mapped_column(String(128), default="")  # client / engagement name
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)  # NDA / authorization gate
    authorization_ref: Mapped[str] = mapped_column(String(255), default="")  # SOW / PKS reference
    # Additional in-scope hosts allowed for THIS workspace (subdomains/IPs), JSON list.
    scope_extra: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    # Optional credentials for AUTHENTICATED (credentialed) VA — stored only in the local DB.
    auth_type: Mapped[str] = mapped_column(String(16), default="none")   # none | ssh_password | ssh_key
    auth_user: Mapped[str] = mapped_column(String(64), default="")
    auth_secret: Mapped[str] = mapped_column(Text, default="")           # password or private key (local only)
    auth_port: Mapped[int] = mapped_column(Integer, default=22)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    mode: Mapped[str] = mapped_column(String(16), default="va")  # va | pentest
    # Scan policy/profile — which phases & intensity run (Nessus-style policies).
    profile: Mapped[str] = mapped_column(String(16), default="full")  # quick|full|web|network|compliance
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed|stopped
    autonomy: Mapped[str] = mapped_column(String(16), default="approve")  # auto | approve
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The agent timeline: reasoning steps + executed commands + observations (JSON list).
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")

    target: Mapped["Target"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), default="info")  # critical|high|medium|low|info
    # Anti-false-positive state:
    status: Mapped[str] = mapped_column(String(24), default="needs_review")  # confirmed|likely|needs_review|false_positive
    confidence: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    cve: Mapped[str] = mapped_column(String(64), default="")
    affected: Mapped[str] = mapped_column(String(255), default="")  # url / host / param
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")        # PoC / proof output
    remediation: Mapped[str] = mapped_column(Text, default="")
    # Concrete, copy-pasteable fix generated by the AI for the detected stack
    # (NOT generic advice — this is the boss's "kasih tau config-nya apa" requirement).
    fix_config: Mapped[str] = mapped_column(Text, default="")      # actual config/code block
    fix_steps: Mapped[str] = mapped_column(Text, default="")       # apply + verify steps
    # Which tools corroborated this (multi-tool corroboration), JSON list.
    sources: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    target: Mapped["Target"] = relationship(back_populates="findings")
    scan: Mapped["Scan"] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(64))
    target_value: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    outcome: Mapped[str] = mapped_column(String(24), default="ok")  # ok | denied | error
