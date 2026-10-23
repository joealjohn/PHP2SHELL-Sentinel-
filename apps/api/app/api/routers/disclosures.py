from __future__ import annotations

from uuid import UUID as UUIDT

from app.api import deps
from app.core.db import get_db
from app.core.rate_limit import enforce
from app.models import (
    Asset,
    Disclosure,
    DisclosureContact,
    Finding,
    User,
    utcnow,
)
from app.schemas.v1 import DisclosureUpdate
from app.services import observability
from app.services.reports import (
    build_disclosure_email,
    build_subject,
)
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

router = APIRouter(prefix="/disclosures", tags=["disclosures"],
                   dependencies=[Depends(deps.require_csrf)])


def _own_disclosure(db: Session, user: User, disclosure_id: str) -> Disclosure:
    try:
        did = UUIDT(disclosure_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Disclosure not found."})
    d = db.get(Disclosure, did)
    if d is None or d.user_id != user.id:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Disclosure not found."})
    return d


def _find_evidence(db: Session, finding_id) -> list:
    from app.models import Evidence
    return (db.query(Evidence).filter(Evidence.finding_id == finding_id)
            .order_by(Evidence.collected_at).all())


@router.get("")
def list_disclosures(request: Request, db: Session = Depends(get_db),
                     user: User = Depends(deps.get_current_user)):
    enforce(request, action="disclosure-read", max_requests=120, window_seconds=60,
            user_scope=str(user.id))
    items = (
        db.query(Disclosure).filter(Disclosure.user_id == user.id)
        .order_by(Disclosure.created_at.desc()).limit(200).all()
    )
    out = []
    for d in items:
        data = d.to_json()
        f = db.get(Finding, d.finding_id)
        a = db.get(Asset, d.asset_id)
        data["finding_title"] = f.title if f else None
        data["asset_name"] = a.name if a else None
        out.append(data)
    return {"disclosures": out}


@router.get("/{disclosure_id}")
def get_disclosure(disclosure_id: str, db: Session = Depends(get_db),
                   user: User = Depends(deps.get_current_user)):
    d = _own_disclosure(db, user, disclosure_id)
    data = d.to_json()
    f = db.get(Finding, d.finding_id)
    a = db.get(Asset, d.asset_id)
    data["finding_title"] = f.title if f else None
    data["asset_name"] = a.name if a else None
    return data


draft_router = APIRouter(tags=["disclosures"],
                         dependencies=[Depends(deps.require_csrf)])


@draft_router.post("/findings/{finding_id}/disclosure", status_code=201)
def create_disclosure(finding_id: str, request: Request,
                      db: Session = Depends(get_db),
                      user: User = Depends(deps.get_current_user)):
    enforce(request, action="disclosure-create", max_requests=20, window_seconds=600,
            user_scope=str(user.id))
    import uuid as uuid_lib
    try:
        fid = uuid_lib.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Finding not found."})
    finding = db.get(Finding, fid)
    if finding is None or finding.user_id != user.id:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND",
                                                     "message": "Finding not found."})
    asset = db.get(Asset, finding.asset_id)

    contact = (
        db.query(DisclosureContact)
        .filter(DisclosureContact.asset_id == asset.id,
                DisclosureContact.email.isnot(None))
        .order_by(DisclosureContact.confidence.desc(), DisclosureContact.discovered_at.desc())
        .first()
    )
    if contact is None:
        raise HTTPException(status_code=409, detail={
            "code": "NO_CONTACT",
            "message": "No security contact discovered for this asset. Run contact "
                       "discovery first.",
        })
    recipient = contact.email

    # duplicate protection: no automatic repeats for the same finding+recipient
    existing = db.query(Disclosure).filter(
        Disclosure.finding_id == finding.id,
        Disclosure.recipient_email == recipient).all()
    if any(x.status in ("SENT", "DELIVERED") for x in existing):
        raise HTTPException(status_code=409, detail={
            "code": "DUPLICATE_DISCLOSURE",
            "message": "A disclosure for this finding already went out to this "
                       "recipient. Use the resend flow to send again.",
        })

    subject = build_subject(finding, asset)
    body = build_disclosure_email(
        finding, asset, _find_evidence(db, finding.id))
    d = Disclosure(
        finding_id=finding.id, contact_id=contact.id, user_id=user.id,
        asset_id=asset.id, status="DRAFT", subject=subject, body=body,
        recipient_email=recipient, recipient_source=contact.source,
    )
    db.add(d)
    db.flush()
    observability.audit(user_id=user.id, asset_id=asset.id, action="DISCLOSURE_DRAFT_CREATED",
                        resource_type="disclosure", resource_id=d.id,
                        detail={"finding_id": str(finding.id),
                                "recipient_source": contact.source})
    db.commit()
    data = d.to_json()
    data["finding_title"] = finding.title
    data["asset_name"] = asset.name
    return data


@router.patch("/{disclosure_id}")
def edit_disclosure(disclosure_id: str, payload: DisclosureUpdate,
                    db: Session = Depends(get_db), user: User = Depends(deps.get_current_user)):
    d = _own_disclosure(db, user, disclosure_id)
    if d.status in ("SENT", "DELIVERED"):
        raise HTTPException(status_code=409, detail={
            "code": "DISCLOSURE_SENT", "message": "This disclosure already left Sentinel."})
    d.subject = payload.subject.strip()
    d.body = payload.body.strip()
    db.commit()
    return d.to_json()


@router.post("/{disclosure_id}/mark-pending")
def mark_pending(disclosure_id: str, db: Session = Depends(get_db),
                 user: User = Depends(deps.get_current_user)):
    d = _own_disclosure(db, user, disclosure_id)
    if d.status not in ("DRAFT",):
        raise HTTPException(status_code=409, detail={
            "code": "INVALID_TRANSITION",
            "message": "Only DRAFT disclosures can be marked for approval."})
    d.status = "PENDING_APPROVAL"
    observability.audit(user_id=user.id, asset_id=d.asset_id, action="DISCLOSURE_MARKED_PENDING",
                        resource_type="disclosure", resource_id=d.id)
    db.commit()
    return d.to_json()


@router.post("/{disclosure_id}/test-email", status_code=202)
def send_test_email(disclosure_id: str, request: Request,
                    db: Session = Depends(get_db),
                    user: User = Depends(deps.get_current_user)):
    enforce(request, action="test-email", max_requests=5, window_seconds=600,
            user_scope=str(user.id))
    d = _own_disclosure(db, user, disclosure_id)
    # test mail is bound to the *authenticated user's* own email — never the target
    import datetime as _dt
    d.character_set = "utf-8"
    observability.audit(user_id=user.id, action="TEST_EMAIL_QUEUED",
                        resource_type="disclosure", resource_id=d.id,
                        detail={"to": user.email})
    db.commit()
    from app.workers.tasks import send_test_email as task_send_test
    task_send_test.apply_async(args=[str(d.id)], task_id=None)
    return {"ok": True, "sent_to": user.email, "queued": True,
            "when": _dt.datetime.now(_dt.UTC).isoformat()}


@router.post("/{disclosure_id}/approve", status_code=202)
def approve_and_send(disclosure_id: str, request: Request,
                     db: Session = Depends(get_db),
                     user: User = Depends(deps.get_current_user)):
    enforce(request, action="disclosure-send", max_requests=10, window_seconds=600,
            user_scope=str(user.id))
    d = _own_disclosure(db, user, disclosure_id)
    if d.status not in ("PENDING_APPROVAL", "DRAFT"):
        raise HTTPException(status_code=409, detail={
            "code": "INVALID_TRANSITION",
            "message": f"Cannot approve a disclosure in state {d.status}."})
    duplicate = db.query(Disclosure).filter(
        Disclosure.finding_id == d.finding_id,
        Disclosure.recipient_email == d.recipient_email,
        Disclosure.id != d.id,
        Disclosure.status.in_(["SENT", "DELIVERED"])).first()
    if duplicate:
        raise HTTPException(status_code=409, detail={
            "code": "DUPLICATE_DISCLOSURE",
            "message": "An identical disclosure was already sent to this recipient."})
    d.status = "APPROVED"
    d.approved_at = utcnow()
    d.approved_by = user.id
    observability.audit(user_id=user.id, asset_id=d.asset_id, action="DISCLOSURE_APPROVED",
                        resource_type="disclosure", resource_id=d.id,
                        detail={"recipient": d.recipient_email})
    db.commit()
    from app.workers.tasks import send_disclosure
    send_disclosure.apply_async(args=[str(d.id)])
    return d.to_json()


@router.post("/{disclosure_id}/send-now", status_code=202)
def send_now(disclosure_id: str, request: Request, db: Session = Depends(get_db),
             user: User = Depends(deps.get_current_user)):
    """Explicit resend requested by the user (duplicate protection opt-in)."""
    enforce(request, action="disclosure-send", max_requests=10, window_seconds=600,
            user_scope=str(user.id))
    d = _own_disclosure(db, user, disclosure_id)
    d.status = "APPROVED"
    d.error = None
    db.commit()
    observability.audit(user_id=user.id, asset_id=d.asset_id, action="DISCLOSURE_RESEND",
                        resource_type="disclosure", resource_id=d.id)
    db.commit()
    from app.workers.tasks import send_disclosure
    send_disclosure.apply_async(args=[str(d.id)])
    return d.to_json()


@router.post("/{disclosure_id}/cancel")
def cancel_disclosure(disclosure_id: str, db: Session = Depends(get_db),
                      user: User = Depends(deps.get_current_user)):
    d = _own_disclosure(db, user, disclosure_id)
    if d.status in ("SENT", "DELIVERED"):
        raise HTTPException(status_code=409, detail={
            "code": "INVALID_TRANSITION", "message": "Already sent — cannot cancel."})
    d.status = "CANCELLED"
    observability.audit(user_id=user.id, asset_id=d.asset_id, action="DISCLOSURE_CANCELLED",
                        resource_type="disclosure", resource_id=d.id)
    db.commit()
    return d.to_json()
