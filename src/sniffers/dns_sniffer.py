# Pasywny sniffer zapytań DNS: nasłuchuje pakietów DNS na UDP/53
# i zapisuje każde zapytanie (kto, o co, jaki typ rekordu) do bazy SQLite.

import threading

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.sendrecv import AsyncSniffer, sniff

from database import DNSEvent, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background", "set_iface"]

# Najpopularniejsze typy rekordów DNS — reszta pójdzie jako numer.
_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 65: "HTTPS", 257: "CAA",
}

_BPF = "udp port 53"

_lock = threading.Lock()
_current: AsyncSniffer | None = None


def _upsert(ip: str, resolver_ip: str, query_name: str, query_type: str) -> None:
    with SessionLocal() as session:
        session.add(DNSEvent(
            ip=ip,
            resolver_ip=resolver_ip,
            query_name=query_name,
            query_type=query_type,
            timestamp=utcnow(),
        ))
        session.commit()


def _handle(packet) -> None:
    # qr == 0 oznacza zapytanie (query). qr == 1 to odpowiedź — pomijamy.
    if DNS not in packet or packet[DNS].qr != 0 or packet[DNS].qdcount == 0:
        return
    question = packet[DNSQR] if DNSQR in packet else None
    if question is None:
        return
    qname = question.qname.decode("utf-8", errors="ignore").rstrip(".")
    if not qname:
        return
    qtype = _QTYPES.get(int(question.qtype), str(int(question.qtype)))
    src_ip = packet[IP].src if IP in packet else ""
    # Resolver to adres docelowy zapytania DNS — pokazuje, do kogo urządzenie
    # kieruje pytania (router lokalny, 1.1.1.1, 8.8.8.8, ...). Sygnał konfiguracji DNS.
    dst_ip = packet[IP].dst if IP in packet else ""
    _upsert(src_ip, dst_ip, qname, qtype)


def start(iface: str | None = None) -> None:
    sniff(filter=_BPF, prn=_handle, store=False, iface=iface)


def start_in_background(iface: str | None = None) -> None:
    global _current
    with _lock:
        if _current is not None:
            return
        _current = AsyncSniffer(filter=_BPF, prn=_handle, store=False, iface=iface)
        _current.start()


def set_iface(iface: str | None) -> None:
    global _current
    with _lock:
        if _current is not None:
            try:
                _current.stop()
            except Exception:
                pass
        _current = AsyncSniffer(filter=_BPF, prn=_handle, store=False, iface=iface)
        _current.start()


if __name__ == "__main__":
    init_db()
    start()
