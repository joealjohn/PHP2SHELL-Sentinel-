from __future__ import annotations

from app.api import deps
from app.core import security
from app.core.config import get_settings
from app.core.db import get_db
from app.core.rate_limit import client_ip, enforce
from app.models import User, utcnow
from app.schemas.v1 import IUser, LoginIn, PasswordChange, RegisterIn
from app.services import observability
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookies(response: Response, raw_token: str, csrf_token: str) -> None:
    s = get_settings()
    response.set_cookie(
        security.SESSION_COOKIE, raw_token,
        max_age=s.session_ttl_days * 86400, httponly=True,
        secure=s.cookie_secure, samesite="lax", path="/",
    )
    response.set_cookie(
        security.CSRF_COOKIE, csrf_token, max_age=s.session_ttl_days * 86400,
        httponly=False, secure=s.cookie_secure, samesite="lax", path="/",
    )


@router.post("/register", status_code=201, response_model=IUser)
def register(payload: RegisterIn, request: Request, response: Response,
             db: Session = Depends(get_db)):
    enforce(request, action="register", max_requests=5, window_seconds=3600)
    email = payload.email.lower().strip()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail={
            "code": "EMAIL_TAKEN",
            "message": "An account with this email already exists.",
        })
    user = User(
        email=email,
        password_hash=security.hash_password(payload.password),
    )
    db.add(user)
    db.flush()
    session = security.create_session(db, user.id, ip_address=client_ip(request),
                                      user_agent=request.headers.get("user-agent"),
                                      ttl_days=get_settings().session_ttl_days)
    observability.audit(user_id=user.id, action="USER_REGISTERED", resource_type="user",
                        resource_id=user.id, ip_address=client_ip(request), db=db)
    db.commit()
    _set_session_cookies(response, session.raw_token, session.csrf_token)
    return user


@router.post("/login", response_model=IUser)
def login(payload: LoginIn, request: Request, response: Response,
          db: Session = Depends(get_db)):
    enforce(request, action="login", max_requests=10, window_seconds=300)
    email = payload.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()
    invalid = HTTPException(status_code=401, detail={
        "code": "INVALID_CREDENTIALS",
        "message": "Email or password is incorrect.",
    })
    if user is None or not user.is_active:
        raise invalid
    if not security.verify_password(payload.password, user.password_hash):
        del user.password_hash
        observability.audit(user_id=user.id, action="LOGIN_FAILED",
                            ip_address=client_ip(request), db=db)
        db.commit()
        raise invalid
    session = security.create_session(db, user.id, ip_address=client_ip(request),
                                      user_agent=request.headers.get("user-agent"),
                                      ttl_days=get_settings().session_ttl_days)
    observability.audit(user_id=user.id, action="LOGIN_SUCCESS", ip_address=client_ip(request),
                        db=db)
    db.commit()
    _set_session_cookies(response, session.raw_token, session.csrf_token)
    return user


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db),
           pair=Depends(deps.get_session)):
    pair[1].revoked_at = utcnow()
    observability.audit(user_id=pair[0].id, action="LOGOUT", ip_address=client_ip(request),
                        db=db)
    db.commit()
    response.delete_cookie(security.SESSION_COOKIE, path="/")
    response.delete_cookie(security.CSRF_COOKIE, path="/")
    return {"ok": True}


@router.get("/me", response_model=IUser)
def me(user: User = Depends(deps.get_current_user)):
    return user


@router.post("/change-password")
def change_password(payload: PasswordChange, db: Session = Depends(get_db),
                    pair=Depends(deps.get_session)):
    if not security.verify_password(payload.current_password, pair[0].password_hash):
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_CREDENTIALS",
            "message": "Current password is incorrect.",
        })
    pair[0].password_hash = security.hash_password(payload.new_password)
    security.revoke_all_for_user(db, pair[0].id)
    pair[1].revoked_at = utcnow()
    observability.audit(user_id=pair[0].id, action="PASSWORD_CHANGED", db=db)
    db.commit()
    return {"ok": True}
