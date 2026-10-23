from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from app.models import Asset, DisclosureContact, utcnow

log = logging.getLogger("sentinel.contacts")


def execute_contact_discovery(db: Session, asset_id: str) -> dict:
    asset = db.get(Asset, _uuid(asset_id))
    if asset is None:
        return {"error": "asset_not_found"}
    try:
        from sentinel_scanner.core.config import ScannerConfig
        from sentinel_scanner.http.client import SentinelHttpClient

        from app.services.contact_discovery import discover_contacts

        cfg = ScannerConfig.from_env()

        async def run() -> list:
            async with SentinelHttpClient(cfg) as client:
                return await discover_contacts(asset.normalized_url, client)

        candidates = asyncio.run(run())
    except Exception as exc:
        from app.services import observability
        observability.audit(user_id=asset.user_id, asset_id=asset.id,
                            action="CONTACT_DISCOVERY_FAILED",
                            resource_type="asset", resource_id=asset.id,
                            detail={"error": f"{type(exc).__name__}"})
        db.commit()
        return {"error": "DISCOVERY_FAILED", "detail": f"{type(exc).__name__}"}

    best_score = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    candidates.sort(key=lambda c: best_score.get(c.confidence, 0), reverse=True)

    for old in db.query(DisclosureContact).filter(
            DisclosureContact.asset_id == asset.id).all():
        db.delete(old)

    stored = []
    for c in candidates[:8]:
        row = DisclosureContact(
            user_id=asset.user_id, asset_id=asset.id,
            email=c.email, contact_url=c.contact_url,
            source=c.source, source_url=c.source_url, confidence=c.confidence,
            policy_url=c.policy_url, encryption_url=c.encryption_url,
            preferred_languages=c.preferred_languages,
            mx_verified=bool(c.mx_verified),
            discovered_at=utcnow(),
        )
        db.add(row)
        stored.append(row)
    db.commit()

    from app.services import observability
    best = stored[0] if stored else None
    observability.audit(user_id=asset.user_id, asset_id=asset.id,
                        action="CONTACT_DISCOVERY_COMPLETED",
                        resource_type="asset", resource_id=asset.id,
                        detail={"count": len(stored),
                                "best_source": best.source if best else None})
    if best is not None and best.confidence == "HIGH":
        observability.notify(
            user_id=asset.user_id, type_="contact",
            title="Security contact discovered",
            message=(f"{best.source_url or best.email} ({best.confidence}) for "
                     f"{asset.host}"),
            data={"contact_id": str(best.id), "asset_id": str(asset.id)},
        )
    db.commit()
    return {"asset_id": str(asset.id), "contacts_found": len(stored)}


def _uuid(value: str):
    import uuid
    return uuid.UUID(str(value))
