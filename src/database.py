from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

engine = create_engine("sqlite:///sentinel.db", future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True)
    mac = Column(String, unique=True, index=True, nullable=False)
    vendor = Column(String)
    protocol = Column(String)
    last_seen = Column(DateTime, default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)
