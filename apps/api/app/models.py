from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator

from app.core.db import Base


class GUID(TypeDecorator):
    """Portable UUID: native UUID on Postgres, CHAR(36) elsewhere (SQLite tests)."""
    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import UUID as PGUUID
            return dialect.type_descriptor(PGUUID(as_uuid=False))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, _dialect):
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value, _dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError):
            return None


JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()


class User(Base):
    __tablename__ = "users"

    id = Column(GUID, primary_key=True, default=new_uuid)
    email = Column(String(320), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow,
                        onupdate=utcnow)

    sessions = relationship("UserSession", back_populates="user",
                            cascade="all, delete-orphan")


class UserSession(Base):
    __tablename__ = "sessions"

    id = Column(GUID, primary_key=True, default=new_uuid)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                     index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    csrf_token = Column(String(64), nullable=False)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="sessions")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(GUID, primary_key=True, default=new_uuid)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                     index=True)
    name = Column(String(200), nullable=False)
    url = Column(String(2048), nullable=False)
    normalized_url = Column(String(2048), nullable=False)
    host = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    authorization_confirmed = Column(Boolean, nullable=False, default=False)
    authorization_confirmed_at = Column(DateTime(timezone=True), nullable=True)
    monitoring_enabled = Column(Boolean, nullable=False, default=False)
    scan_interval_seconds = Column(Integer, nullable=False, default=86400)
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    next_scan_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow,
                        onupdate=utcnow)

    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(GUID, primary_key=True, default=new_uuid)
    asset_id = Column(GUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False,
                      index=True)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                     index=True)
    status = Column(String(20), nullable=False, default="QUEUED", index=True)
    scanner_version = Column(String(32), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, nullable=True)
    celery_task_id = Column(String(64), nullable=True)
    summary = Column(JSONType, nullable=True)
    error = Column(Text, nullable=True)
    error_code = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    asset = relationship("Asset", back_populates="scans")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(GUID, primary_key=True, default=new_uuid)
    asset_id = Column(GUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False,
                      index=True)
    scan_id = Column(GUID, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                     index=True)
    vulnerability_id = Column(String(64), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    cvss = Column(Numeric(4, 1), nullable=True)
    confidence = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="UNKNOWN", index=True)
    state = Column(String(30), nullable=False, default="POTENTIAL", index=True)
    summary = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    detected_version = Column(String(32), nullable=True)
    fixed_version = Column(String(32), nullable=True)
    vendor_patch_possible = Column(Boolean, nullable=False, default=False)
    detection_method = Column(String(64), nullable=True)
    scanner_version = Column(String(32), nullable=True)
    references = Column(JSONType, nullable=True)
    first_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow,
                        onupdate=utcnow)

    asset = relationship("Asset", back_populates="findings")
    evidence_items = relationship("Evidence", back_populates="finding",
                                  cascade="all, delete-orphan")
    disclosures = relationship("Disclosure", back_populates="finding")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(GUID, primary_key=True, default=new_uuid)
    finding_id = Column(GUID, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False,
                        index=True)
    evidence_type = Column(String(64), nullable=False)
    name = Column(String(200), nullable=False)
    value = Column(Text, nullable=False)
    source = Column(String(120), nullable=True)
    confidence = Column(String(20), nullable=True)
    collected_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    finding = relationship("Finding", back_populates="evidence_items")


class DisclosureContact(Base):
    __tablename__ = "disclosure_contacts"

    id = Column(GUID, primary_key=True, default=new_uuid)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                     index=True)
    asset_id = Column(GUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False,
                      index=True)
    email = Column(String(320), nullable=True)
    contact_url = Column(String(2048), nullable=True)
    source = Column(String(64), nullable=False)
    source_url = Column(String(2048), nullable=True)
    confidence = Column(String(20), nullable=False, default="LOW")
    policy_url = Column(String(2048), nullable=True)
    encryption_url = Column(String(2048), nullable=True)
    preferred_languages = Column(String(120), nullable=True)
    mx_verified = Column(Boolean, nullable=False, default=False)
    discovered_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class Disclosure(Base):
    __tablename__ = "disclosures"

    id = Column(GUID, primary_key=True, default=new_uuid)
    finding_id = Column(GUID, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False,
                        index=True)
    contact_id = Column(GUID, ForeignKey("disclosure_contacts.id", ondelete="SET NULL"),
                        nullable=True)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                     index=True)
    asset_id = Column(GUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False,
                      index=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    delivery_status = Column(String(30), nullable=True)
    subject = Column(Text, nullable=False)
    body = Column(Text, nullable=False)
    recipient_email = Column(String(320), nullable=False)
    recipient_source = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approved_by = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    last_sent_at = Column(DateTime(timezone=True), nullable=True)
    character_set = Column(String(32), nullable=True, default="utf-8")
    error = Column(Text, nullable=True)

    finding = relationship("Finding", back_populates="disclosures")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(GUID, primary_key=True, default=new_uuid)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                     index=True)
    type = Column(String(64), nullable=False)
    title = Column(String(300), nullable=False)
    message = Column(Text, nullable=True)
    data = Column(JSONType, nullable=True)
    read_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(GUID, primary_key=True, default=new_uuid)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
                     index=True)
    asset_id = Column(GUID, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(64), nullable=True)
    ip_address = Column(String(64), nullable=True)
    detail = Column(JSONType, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"


FINDING_STATES = {
    "NOT_DETECTED", "POTENTIAL", "LIKELY_VULNERABLE", "HIGH_CONFIDENCE",
    "CONFIRMED", "PATCHED", "UNKNOWN",
}

DISCLOSURE_STATUSES = {
    "DRAFT", "PENDING_APPROVAL", "APPROVED", "SENT", "DELIVERED", "FAILED", "CANCELLED",
}


def _iso(value):
    if not value:
        return None
    if getattr(value, "tzinfo", None) is not None:
        return value.isoformat()
    return value.isoformat() + "Z"


def _uuid_str(value):
    return str(value) if value else None


Asset.to_json = lambda self: {
    "id": _uuid_str(self.id),
    "name": self.name,
    "url": self.url,
    "normalized_url": self.normalized_url,
    "host": self.host,
    "description": self.description,
    "authorization_confirmed": self.authorization_confirmed,
    "authorization_confirmed_at": _iso(self.authorization_confirmed_at),
    "monitoring_enabled": self.monitoring_enabled,
    "scan_interval_seconds": self.scan_interval_seconds,
    "last_scan_at": _iso(self.last_scan_at),
    "next_scan_at": _iso(self.next_scan_at),
    "open_findings": None,
    "last_scan_status": None,
    "created_at": _iso(self.created_at),
    "updated_at": _iso(self.updated_at),
}

Scan.to_json = lambda self: {
    "id": _uuid_str(self.id),
    "asset_id": _uuid_str(self.asset_id),
    "status": self.status,
    "scanner_version": self.scanner_version,
    "started_at": _iso(self.started_at),
    "completed_at": _iso(self.completed_at),
    "duration_seconds": self.duration_seconds,
    "celery_task_id": self.celery_task_id,
    "summary": self.summary,
    "error": self.error,
    "error_code": self.error_code,
    "created_at": _iso(self.created_at),
}

Finding.to_json = lambda self: {
    "id": _uuid_str(self.id),
    "asset_id": _uuid_str(self.asset_id),
    "scan_id": _uuid_str(self.scan_id),
    "vulnerability_id": self.vulnerability_id,
    "title": self.title,
    "severity": self.severity,
    "cvss": float(self.cvss) if self.cvss is not None else None,
    "confidence": self.confidence,
    "status": self.status,
    "state": self.state,
    "summary": self.summary,
    "impact": self.impact,
    "remediation": self.remediation,
    "detected_version": self.detected_version,
    "fixed_version": self.fixed_version,
    "vendor_patch_possible": self.vendor_patch_possible,
    "detection_method": self.detection_method,
    "scanner_version": self.scanner_version,
    "references": self.references,
    "first_seen": _iso(self.first_seen),
    "last_seen": _iso(self.last_seen),
    "resolved_at": _iso(self.resolved_at),
    "created_at": _iso(self.created_at),
}

Disclosure.to_json = lambda self: {
    "id": _uuid_str(self.id),
    "finding_id": _uuid_str(self.finding_id),
    "contact_id": _uuid_str(self.contact_id),
    "asset_id": _uuid_str(self.asset_id),
    "user_id": _uuid_str(self.user_id),
    "status": self.status,
    "delivery_status": self.delivery_status,
    "subject": self.subject,
    "body": self.body,
    "recipient_email": self.recipient_email,
    "recipient_source": self.recipient_source,
    "created_at": _iso(self.created_at),
    "approved_at": _iso(self.approved_at),
    "approved_by": _uuid_str(self.approved_by),
    "sent_at": _iso(self.sent_at),
    "last_sent_at": _iso(self.last_sent_at),
    "error": self.error,
}
