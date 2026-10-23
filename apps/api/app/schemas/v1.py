from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


def dt(v: datetime | None) -> Any:
    if not v:
        return None
    if getattr(v, "tzinfo", None) is not None:
        return v.isoformat()
    return v.isoformat() + "Z"


# ── Assets ──────────────────────────────────────────────────────────────────
class AssetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=4, max_length=2048)
    description: str | None = Field(default=None, max_length=2000)
    scan_interval_seconds: int = Field(default=86400, ge=3600, le=30 * 86400)
    monitoring_enabled: bool = False
    authorization_confirmed: bool = False


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    scan_interval_seconds: int | None = Field(default=None, ge=3600, le=30 * 86400)
    monitoring_enabled: bool | None = None
    authorization_confirmed: bool | None = None


class AssetOut(BaseModel):
    id: UUID
    name: str
    url: str
    normalized_url: str
    host: str
    description: str | None
    authorization_confirmed: bool
    authorization_confirmed_at: datetime | None
    monitoring_enabled: bool
    scan_interval_seconds: int
    last_scan_at: datetime | None
    next_scan_at: datetime | None
    created_at: datetime
    updated_at: datetime
    open_findings: int | None = None
    last_scan_status: str | None = None

    class Config:
        from_attributes = True

    def to_json(self) -> dict:
        d = {
            "id": str(self.id),
            "name": self.name,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "host": self.host,
            "description": self.description,
            "authorization_confirmed": self.authorization_confirmed,
            "authorization_confirmed_at": dt(self.authorization_confirmed_at),
            "monitoring_enabled": self.monitoring_enabled,
            "scan_interval_seconds": self.scan_interval_seconds,
            "last_scan_at": dt(self.last_scan_at),
            "next_scan_at": dt(self.next_scan_at),
            "created_at": dt(self.created_at),
            "updated_at": dt(self.updated_at),
            "open_findings": self.open_findings,
            "last_scan_status": self.last_scan_status,
        }
        return d


# ── Scans ───────────────────────────────────────────────────────────────────
class ScanOut(BaseModel):
    id: UUID
    asset_id: UUID
    status: str
    scanner_version: str | None
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    summary: dict | None
    error: str | None
    error_code: str | None
    created_at: datetime

    class Config:
        from_attributes = True

    def to_json(self) -> dict:
        return {
            "id": str(self.id),
            "asset_id": str(self.asset_id),
            "status": self.status,
            "scanner_version": self.scanner_version,
            "started_at": dt(self.started_at),
            "completed_at": dt(self.completed_at),
            "duration_seconds": self.duration_seconds,
            "summary": self.summary,
            "error": self.error,
            "error_code": self.error_code,
            "created_at": dt(self.created_at),
        }


# ── Findings ────────────────────────────────────────────────────────────────
class FindingOut(BaseModel):
    id: UUID
    asset_id: UUID
    scan_id: UUID | None
    vulnerability_id: str
    title: str
    severity: str
    cvss: float | None
    confidence: str
    status: str
    summary: str | None
    impact: str | None
    remediation: str | None
    detected_version: str | None
    fixed_version: str | None
    vendor_patch_possible: bool | None
    detection_method: str | None
    scanner_version: str | None
    references: dict | list | None
    first_seen: datetime | None
    last_seen: datetime | None
    resolved_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True

    def to_json(self) -> dict:
        return {
            "id": str(self.id),
            "asset_id": str(self.asset_id),
            "scan_id": str(self.scan_id) if self.scan_id else None,
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "severity": self.severity,
            "cvss": float(self.cvss) if self.cvss is not None else None,
            "confidence": self.confidence,
            "status": self.status,
            "summary": self.summary,
            "impact": self.impact,
            "remediation": self.remediation,
            "detected_version": self.detected_version,
            "fixed_version": self.fixed_version,
            "vendor_patch_possible": self.vendor_patch_possible,
            "detection_method": self.detection_method,
            "scanner_version": self.scanner_version,
            "references": self.references,
            "first_seen": dt(self.first_seen),
            "last_seen": dt(self.last_seen),
            "resolved_at": dt(self.resolved_at),
            "created_at": dt(self.created_at),
        }


# ── Contacts ────────────────────────────────────────────────────────────────
class ContactOut(BaseModel):
    id: UUID
    email: str | None
    contact_url: str | None
    source: str
    source_url: str | None
    confidence: str
    policy_url: str | None
    encryption_url: str | None
    preferred_languages: str | None
    discovered_at: datetime

    class Config:
        from_attributes = True

    def to_json(self) -> dict:
        return {
            "id": str(self.id),
            "email": self.email,
            "contact_url": self.contact_url,
            "source": self.source,
            "source_url": self.source_url,
            "confidence": self.confidence,
            "policy_url": self.policy_url,
            "encryption_url": self.encryption_url,
            "preferred_languages": self.preferred_languages,
            "discovered_at": dt(self.discovered_at),
        }


# ── Disclosures ─────────────────────────────────────────────────────────────
class DisclosureUpdate(BaseModel):
    subject: str = Field(min_length=4, max_length=300)
    body: str = Field(min_length=20, max_length=60000)


class DisclosureOut(BaseModel):
    id: UUID
    finding_id: UUID
    contact_id: UUID | None
    asset_id: UUID
    user_id: UUID
    status: str
    delivery_status: str | None
    subject: str
    body: str
    recipient_email: str
    recipient_source: str | None
    created_at: datetime
    approved_at: datetime | None
    approved_by: UUID | None
    sent_at: datetime | None
    last_sent_at: datetime | None
    error: str | None

    class Config:
        from_attributes = True

    def to_json(self) -> dict:
        return {
            "id": str(self.id),
            "finding_id": str(self.finding_id),
            "contact_id": str(self.contact_id) if self.contact_id else None,
            "asset_id": str(self.asset_id),
            "user_id": str(self.user_id),
            "status": self.status,
            "delivery_status": self.delivery_status,
            "subject": self.subject,
            "body": self.body,
            "recipient_email": self.recipient_email,
            "recipient_source": self.recipient_source,
            "created_at": dt(self.created_at),
            "approved_at": dt(self.approved_at),
            "approved_by": str(self.approved_by) if self.approved_by else None,
            "sent_at": dt(self.sent_at),
            "last_sent_at": dt(self.last_sent_at),
            "error": self.error,
        }


# ── Notifications ───────────────────────────────────────────────────────────
class NotificationOut(BaseModel):
    id: UUID
    type: str
    title: str
    message: str | None
    data: dict | None
    read_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True

    def to_json(self) -> dict:
        return {
            "id": str(self.id),
            "type": self.type,
            "title": self.title,
            "message": self.message,
            "data": self.data,
            "read_at": dt(self.read_at),
            "created_at": dt(self.created_at),
        }


class AuditOut(BaseModel):
    id: UUID
    user_id: UUID | None
    asset_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    detail: dict | None
    created_at: datetime

    class Config:
        from_attributes = True

    def to_json(self) -> dict:
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "detail": self.detail,
            "created_at": dt(self.created_at),
        }
