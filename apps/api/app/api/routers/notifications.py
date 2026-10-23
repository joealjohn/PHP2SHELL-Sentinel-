from __future__ import annotations

from uuid import UUID as UUIDT

from app.api import deps
from app.core.db import get_db
from app.models import Notification, User, utcnow
from app.schemas.v1 import NotificationOut
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter(prefix="/notifications", tags=["notifications"],
                   dependencies=[Depends(deps.require_csrf)])


@router.get("")
def list_notifications(db: Session = Depends(get_db),
                       user: User = Depends(deps.get_current_user)):
    items = (
        db.query(Notification).filter(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc()).limit(100).all()
    )
    unread = sum(1 for i in items if i.read_at is None)
    return {"notifications": [NotificationOut.model_validate(i).to_json() for i in items],
            "unread": unread}


@router.get("/unread-count")
def unread_count(db: Session = Depends(get_db), user: User = Depends(deps.get_current_user)):
    count = (db.query(Notification)
             .filter(Notification.user_id == user.id, Notification.read_at.is_(None))
             .count())
    return {"unread": count}


@router.post("/{notification_id}/read")
def mark_read(notification_id: str, db: Session = Depends(get_db),
              user: User = Depends(deps.get_current_user)):
    try:
        nid = UUIDT(notification_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Notification not found."})
    n = db.get(Notification, nid)
    if n is None or n.user_id != user.id:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Notification not found."})
    n.read_at = utcnow()
    db.commit()
    return {"ok": True}


@router.post("/read-all")
def mark_all_read(db: Session = Depends(get_db), user: User = Depends(deps.get_current_user)):
    db.query(Notification).filter(
        Notification.user_id == user.id, Notification.read_at.is_(None)
    ).update({"read_at": utcnow()}, synchronize_session=False)
    db.commit()
    return {"ok": True}
