from __future__ import annotations

from app.api import deps
from app.core.db import get_db
from app.models import DisclosureContact, User
from app.schemas.v1 import ContactOut
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

router = APIRouter(prefix="/assets", tags=["contacts"],
                   dependencies=[Depends(deps.require_csrf)])


@router.get("/{asset_id}/contacts")
def list_contacts(asset_id: str, db: Session = Depends(get_db),
                  user: User = Depends(deps.get_current_user)):
    asset = deps.get_user_asset_or_403(db, user, asset_id)
    contacts = (
        db.query(DisclosureContact).filter(DisclosureContact.asset_id == asset.id)
        .order_by(DisclosureContact.created_at.desc()).limit(50).all()
    )
    return {"contacts": [ContactOut.model_validate(c).to_json() for c in contacts]}


@router.post("/{asset_id}/contacts/discover", status_code=202)
def trigger_discovery(asset_id: str, db: Session = Depends(get_db),
                      user: User = Depends(deps.get_current_user)):
    asset = deps.get_user_asset_or_403(db, user, asset_id)
    deps.require_authorized_asset(asset)
    from app.workers.tasks import discover_contact
    task = discover_contact.apply_async(args=[str(asset.id)])
    return {"task_id": task.id, "status": "QUEUED"}
