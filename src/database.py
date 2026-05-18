from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, create_engine, text
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
    mac = Column(String, index=True, nullable=False, unique=True)
    vendor = Column(String)
    protocol = Column(String)
    last_seen = Column(DateTime, default=utcnow)

class DHCPEvent(Base):
    __tablename__ = "dhcp_events"
    id = Column(Integer, primary_key=True)
    mac = Column(String, index=True, nullable=False)
    requested_ip = Column(String)
    hostname = Column(String)
    message_type = Column(String)
    parameter_request_list = Column(String)
    predicted_os = Column(String)
    timestamp = Column(DateTime, default=utcnow)

class mDNSEvent(Base):
    __tablename__ = "mdns_events"
    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True)
    mac = Column(String, index=True)
    hostname = Column(String)
    services = Column(String)
    timestamp = Column(DateTime, default=utcnow)

class SSDPEvent(Base):
    __tablename__ = "ssdp_events"
    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True)
    message_type = Column(String)
    server = Column(String)
    location = Column(String)
    service_type = Column(String)
    usn = Column(String, index=True)
    timestamp = Column(DateTime, default=utcnow)

class DNSEvent(Base):
    __tablename__ = "dns_events"
    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True)
    resolver_ip = Column(String, index=True)
    query_name = Column(String, index=True)
    query_type = Column(String)
    timestamp = Column(DateTime, default=utcnow)

class TLSEvent(Base):
    __tablename__ = "tls_events"
    id = Column(Integer, primary_key=True)
    ip = Column(String, index=True)
    sni = Column(String, index=True)
    alpn = Column(String)
    ja3 = Column(String, index=True)
    timestamp = Column(DateTime, default=utcnow)

# Idempotentne migracje dla istniejących plików sentinel.db, w których
# nowo dodane kolumny jeszcze nie istnieją. SQLite zgłasza błąd, jeśli kolumna
# już jest — opakowujemy każde ALTER w osobny try/except.
_ADD_COLUMN_MIGRATIONS = [
    "ALTER TABLE ssdp_events ADD COLUMN message_type TEXT",
    "ALTER TABLE ssdp_events ADD COLUMN usn TEXT",
    "ALTER TABLE dns_events  ADD COLUMN resolver_ip TEXT",
    "ALTER TABLE tls_events  ADD COLUMN alpn TEXT",
]


def init_db() -> None:
    Base.metadata.create_all(engine)
    for sql in _ADD_COLUMN_MIGRATIONS:
        try:
            with engine.begin() as conn:
                conn.execute(text(sql))
        except Exception:
            pass
