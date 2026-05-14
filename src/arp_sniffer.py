import threading

from scapy.all import ARP, sniff

from database import Device, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background"]


def _upsert(ip: str, mac: str) -> None:
    with SessionLocal() as session:
        device = session.query(Device).filter_by(mac=mac).first()
        if device is None:
            session.add(Device(ip=ip, mac=mac, protocol="ARP", last_seen=utcnow()))
        else:
            device.ip = ip
            device.last_seen = utcnow()
        session.commit()


def _handle(packet) -> None:
    if ARP in packet and packet[ARP].op in (1, 2):
        _upsert(packet[ARP].psrc, packet[ARP].hwsrc)


def start(iface: str | None = None) -> None:
    sniff(filter="arp", prn=_handle, store=False, iface=iface)


def start_in_background(iface: str | None = None) -> threading.Thread:
    thread = threading.Thread(target=start, kwargs={"iface": iface}, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    init_db()
    start()
