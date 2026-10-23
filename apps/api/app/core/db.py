from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
_url = _settings.database_url

_engine_kwargs: dict = {"pool_pre_ping": True, "pool_recycle": 1800}
if _url.startswith("sqlite"):
    from sqlalchemy.pool import StaticPool

    _engine_kwargs = {"pool_pre_ping": False, "poolclass": StaticPool,
                      "connect_args": {"check_same_thread": False}}

engine = create_engine(_url, **_engine_kwargs)

SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionFactory()
    try:
        yield db
    finally:
        db.close()
