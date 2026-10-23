from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session

from app.models import UserSession, utcnow

_hasher = PasswordHasher()

SESSION_COOKIE = "sentinel_session"
CSRF_COOKIE = "sentinel_csrf"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def new_token_prefix(nbytes: int = 48) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_session(
    db: Session,
    user_id,
    ip_address: str | None = None,
    user_agent: str | None = None,
    ttl_days: int = 14,
) -> UserSession:
    raw = new_token_prefix()
    session = UserSession(
        user_id=user_id,
        token_hash=sha256_hex(raw),
        csrf_token=secrets.token_hex(32),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:250],
        expires_at=datetime.now(UTC) + timedelta(days=ttl_days),
    )
    db.add(session)
    db.flush()
    session.raw_token = raw
    return session


def revoke_session(db: Session, token_raw: str) -> bool:
    h = sha256_hex(token_raw)
    s = db.query(UserSession).filter(UserSession.token_hash == h,
                                     UserSession.revoked_at.is_(None)).first()
    if s is None:
        return False
    s.revoked_at = utcnow()
    return True


def revoke_all_for_user(db: Session, user_id) -> int:
    count = 0
    for s in db.query(UserSession).filter(
            UserSession.user_id == user_id, UserSession.revoked_at.is_(None)).all():
        s.revoked_at = utcnow()
        count += 1
    return count


def session_from_token(db: Session, token_raw: str) -> UserSession | None:
    if not token_raw:
        return None
    h = sha256_hex(token_raw)
    s = db.query(UserSession).filter(UserSession.token_hash == h).first()
    if s is None or s.revoked_at is not None:
        return None
    if s.expires_at and _aware(s.expires_at) < _aware(utcnow()):
        return None
    return s


def _aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
