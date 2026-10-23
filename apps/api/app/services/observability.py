from __future__ import annotations

from app.core.db import SessionFactory
from app.models import AuditLog, Notification


def audit(user_id=None, asset_id=None, action: str = "", resource_type: str | None = None,
          resource_id=None, ip_address: str | None = None, detail: dict | None = None,
          db=None) -> None:
    """Persist an audit event. Uses its own session when none is supplied
    (e.g., from worker context)."""
    entry = AuditLog(
        user_id=user_id, asset_id=asset_id, action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=ip_address, detail=detail,
    )
    if db is not None:
        db.add(entry)
        return
    session = SessionFactory()
    try:
        session.add(entry)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def notify(user_id, type_: str, title: str, message: str | None = None,
           data: dict | None = None, db=None) -> None:
    n = Notification(user_id=user_id, type=type_, title=title, message=message, data=data)
    if db is not None:
        db.add(n)
        return
    session = SessionFactory()
    try:
        session.add(n)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()
