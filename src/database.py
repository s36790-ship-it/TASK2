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
    mac = Column(String, index=True, nullable=False)
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

def init_db() -> None:
    Base.metadata.create_all(engine)