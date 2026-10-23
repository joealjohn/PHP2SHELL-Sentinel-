from __future__ import annotations

from app.api import deps
from app.core.db import get_db
from app.models import AuditLog
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit(db: Session = Depends(get_db), user=Depends(deps.get_current_user),
               limit: int = 100):
    items = (
        db.query(AuditLog).filter(AuditLog.user_id == user.id)
        .order_by(AuditLog.created_at.desc()).limit(min(limit, 500)).all()
    )
    from app.schemas.v1 import AuditOut
    return {"audit_logs": [AuditOut.model_validate(i).to_json() for i in items]}
