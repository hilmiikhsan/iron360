"""Pydantic request/response schemas."""
from __future__ import annotations

import datetime as dt
from pydantic import BaseModel, Field, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10)


# ---- Targets ----
class TargetCreate(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=255)
    kind: str = "domain"            # domain | ip | cidr
    engagement: str = ""
    authorized: bool = False
    authorization_ref: str = ""
    scope_extra: list[str] = []
    notes: str = ""
    auth_type: str = "none"         # none | ssh_password | ssh_key
    auth_user: str = ""
    auth_secret: str = ""
    auth_port: int = 22


class TargetUpdate(BaseModel):
    label: str | None = None
    engagement: str | None = None
    authorized: bool | None = None
    authorization_ref: str | None = None
    scope_extra: list[str] | None = None
    notes: str | None = None
    auth_type: str | None = None
    auth_user: str | None = None
    auth_secret: str | None = None
    auth_port: int | None = None


class TargetOut(ORMModel):
    id: int
    label: str
    value: str
    kind: str
    engagement: str
    authorized: bool
    authorization_ref: str
    scope_extra: list[str]
    notes: str
    auth_type: str
    auth_user: str
    auth_port: int
    created_at: dt.datetime


# ---- Scans ----
class ScanCreate(BaseModel):
    target_id: int
    mode: str = "pentest"          # va | pentest
    autonomy: str = "approve"      # auto | approve


class ScanOut(ORMModel):
    id: int
    target_id: int
    mode: str
    status: str
    autonomy: str
    started_at: dt.datetime
    finished_at: dt.datetime | None
    summary: str
    timeline: list


# ---- Findings ----
class FindingOut(ORMModel):
    id: int
    target_id: int
    scan_id: int | None
    title: str
    severity: str
    status: str
    confidence: int
    cve: str
    affected: str
    description: str
    evidence: str
    remediation: str
    fix_config: str
    fix_steps: str
    sources: list
    created_at: dt.datetime


class FindingStatusUpdate(BaseModel):
    status: str  # confirmed | likely | needs_review | false_positive


class AuditOut(ORMModel):
    id: int
    at: dt.datetime
    actor: str
    action: str
    target_value: str
    detail: str
    outcome: str
