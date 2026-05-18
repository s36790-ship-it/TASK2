# Pasywny sniffer SSDP: nasłuchuje multicastowych pakietów SSDP/UPnP
# (NOTIFY, M-SEARCH, odpowiedzi HTTP 200) na UDP/1900
# i zapisuje rozgłaszane usługi do bazy SQLite.

import threading

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer, sniff

from database import SSDPEvent, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background", "set_iface"]

_BPF = "udp port 1900"

_lock = threading.Lock()
_current: AsyncSniffer | None = None


def _upsert(ip: str, message_type: str, server: str, location: str, service_type: str, usn: str) -> None:
    with SessionLocal() as session:
        session.add(SSDPEvent(
            ip=ip,
            message_type=message_type,
            server=server,
            location=location,
            service_type=service_type,
            usn=usn,
            timestamp=utcnow(),
        ))
        session.commit()


def _parse_start_line(line: str) -> str:
    # Pierwsza linia rozróżnia trzy rodzaje wiadomości SSDP:
    # "NOTIFY * HTTP/1.1" — urządzenie ogłasza się w sieci,
    # "M-SEARCH * HTTP/1.1" — ktoś pyta "kto tu jest?",
    # "HTTP/1.1 200 OK" — odpowiedź na M-SEARCH.
    upper = line.upper()
    if upper.startswith("NOTIFY"):
        return "NOTIFY"
    if upper.startswith("M-SEARCH"):
        return "M-SEARCH"
    if upper.startswith("HTTP/"):
        return "RESPONSE"
    return ""


def _parse_headers(payload: str) -> tuple[str, dict[str, str]]:
    lines = payload.split("\r\n")
    start_line = _parse_start_line(lines[0]) if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().upper()] = value.strip()
    return start_line, headers


def _handle(packet) -> None:
    if UDP not in packet or Raw not in packet:
        return
    if packet[UDP].dport != 1900 and packet[UDP].sport != 1900:
        return
    payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
    message_type, headers = _parse_headers(payload)
    server = headers.get("SERVER", "")
    location = headers.get("LOCATION", "")
    # NT pojawia się w NOTIFY, ST w M-SEARCH i odpowiedziach — interesuje nas jedno albo drugie.
    service_type = headers.get("NT") or headers.get("ST") or ""
    usn = headers.get("USN", "")
    if not (server or location or service_type or usn):
        return
    src_ip = packet[IP].src if IP in packet else ""
    _upsert(src_ip, message_type, server, location, service_type, usn)


def start(iface: str | None = None) -> None:
    # Filtr BPF "udp port 1900" ogranicza ruch do SSDP (zarówno multicast jak i odpowiedzi unicast).
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
    # Tryb samodzielny do testów. Wymaga uprawnień root/admin (surowe gniazda).
    init_db()
    start()
