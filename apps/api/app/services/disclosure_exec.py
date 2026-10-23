from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from app.models import Disclosure, utcnow
from app.services import observability
from app.services.email import EmailMessage, get_email_provider

log = logging.getLogger("sentinel.disclosure")


def _send_smtp_sync(to_email: str, subject: str, body_text: str) -> str:
    provider = get_email_provider()
    message = EmailMessage(to_email=to_email, subject=subject, body_text=body_text)
    return asyncio.run(provider.send(message))


def execute_disclosure_send(db: Session, disclosure_id: str) -> dict:
    d = db.get(Disclosure, _uuid(disclosure_id))
    if d is None:
        return {"error": "disclosure_not_found"}
    if d.status not in ("APPROVED",):
        return {"error": "NOT_APPROVED", "status": d.status}
    try:
        _send_smtp_sync(d.recipient_email, d.subject, d.body)
        d.status = "DELIVERED"
        d.delivery_status = "250"
        d.sent_at = utcnow()
        d.last_sent_at = utcnow()
        d.error = None
        observability.audit(user_id=d.user_id, asset_id=d.asset_id,
                            action="DISCLOSURE_SENT", resource_type="disclosure",
                            resource_id=d.id,
                            detail={"recipient": d.recipient_email,
                                    "finding_id": str(d.finding_id)})
        observability.notify(
            user_id=d.user_id, type_="disclosure",
            title="Responsible disclosure sent",
            message=f"Sent to {d.recipient_email} for finding {d.finding_id}.",
            data={"disclosure_id": str(d.id), "finding_id": str(d.finding_id)},
        )
        db.commit()
        return {"disclosure_id": str(d.id), "status": "DELIVERED"}
    except Exception as exc:
        d.status = "FAILED"
        d.delivery_status = "SMTP_ERROR"
        d.error = f"{type(exc).__name__}: see server logs"[:400]
        db.commit()
        observability.audit(user_id=d.user_id, asset_id=d.asset_id,
                            action="DISCLOSURE_SEND_FAILED",
                            resource_type="disclosure", resource_id=d.id,
                            detail={"error_type": type(exc).__name__})
        log.exception("disclosure send failed")
        db.commit()
        return {"disclosure_id": str(d.id), "status": "FAILED",
                "error": d.error}


def execute_test_email(db: Session, disclosure_id: str) -> dict:
    d = db.get(Disclosure, _uuid(disclosure_id))
    if d is None:
        return {"error": "disclosure_not_found"}
    user = d.user_id
    user_row = _user_email(db, user)
    if user_row is None:
        return {"error": "USER_NOT_FOUND"}
    subject = "[TEST] " + d.subject
    try:
        _send_smtp_sync(user_row, subject, d.body)
        observability.audit(user_id=d.user_id, action="TEST_EMAIL_SENT",
                            resource_type="disclosure", resource_id=d.id,
                            detail={"to": user_row})
        db.commit()
        return {"sent": True, "to": user_row}
    except Exception as exc:
        observability.audit(user_id=d.user_id, action="TEST_EMAIL_FAILED",
                            detail={"error_type": type(exc).__name__})
        log.exception("test email failed")
        return {"sent": False, "error": type(exc).__name__}


def _user_email(db: Session, user_id) -> str | None:
    from app.models import User

    u = db.get(User, user_id)
    return u.email if u else None


def _uuid(value: str):
    import uuid
    return uuid.UUID(str(value))
