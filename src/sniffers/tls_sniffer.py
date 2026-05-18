# Pasywny sniffer TLS ClientHello: wyciąga SNI (nazwę hosta, do którego klient się łączy)
# i liczy fingerprint JA3 (https://github.com/salesforce/ja3) z pól ClientHello.

import hashlib
import struct
import threading

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer, sniff

from database import TLSEvent, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background", "set_iface"]

_BPF = "tcp port 443"

_lock = threading.Lock()
_current: AsyncSniffer | None = None

# Wartości GREASE (RFC 8701) — Chrome i inne klienty losowo wstrzykują je do listy
# szyfrów/rozszerzeń/krzywych. JA3 musi je pominąć, inaczej fingerprint zmienia się przy każdym
# połączeniu.
_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def _u16(b: bytes, i: int) -> int:
    return struct.unpack(">H", b[i:i + 2])[0]


def _parse_client_hello(data: bytes) -> tuple[str, str, str] | None:
    # Rekord TLS: content_type(1) + version(2) + length(2). 0x16 = Handshake.
    # UWAGA: jeśli ClientHello jest rozbity na kilka segmentów TCP (np. duże rozszerzenia,
    # ECH/ESNI), drugi segment trafia tu jako "dane po record header" i parser go pominie.
    # Pełna obsługa wymagałaby ponownego składania strumienia TCP — pomijamy, bo
    # w praktyce >99% ClientHello mieści się w jednym segmencie.
    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
        return None  # 0x01 = ClientHello w nagłówku Handshake
    try:
        pos = 9
        version = _u16(data, pos); pos += 2
        pos += 32  # random
        sid_len = data[pos]; pos += 1 + sid_len
        cs_len = _u16(data, pos); pos += 2
        ciphers = [_u16(data, pos + i) for i in range(0, cs_len, 2) if _u16(data, pos + i) not in _GREASE]
        pos += cs_len
        cm_len = data[pos]; pos += 1 + cm_len
        ext_total = _u16(data, pos); pos += 2
        end = pos + ext_total

        exts: list[int] = []
        curves: list[int] = []
        formats: list[int] = []
        sni = ""
        alpn_protos: list[str] = []

        while pos + 4 <= end:
            etype = _u16(data, pos)
            elen = _u16(data, pos + 2)
            edata = data[pos + 4:pos + 4 + elen]
            pos += 4 + elen
            if etype in _GREASE:
                continue
            exts.append(etype)
            if etype == 0x0000 and len(edata) >= 5:
                # SNI: list_len(2) + entry_type(1) + name_len(2) + name
                name_len = _u16(edata, 3)
                sni = edata[5:5 + name_len].decode("utf-8", errors="ignore")
            elif etype == 0x0010 and len(edata) >= 2:
                # ALPN: list_len(2) + entries [str_len(1) + str_bytes]. Silny sygnał klasy
                # urządzenia — przeglądarki zwykle proponują "h2"+"http/1.1", aplikacje
                # mobilne często tylko jedną wartość.
                list_len = _u16(edata, 0)
                i = 2
                while i < 2 + list_len and i < len(edata):
                    s_len = edata[i]
                    alpn_protos.append(edata[i + 1:i + 1 + s_len].decode("ascii", errors="ignore"))
                    i += 1 + s_len
            elif etype == 0x000a and len(edata) >= 2:
                # supported_groups (krzywe eliptyczne): list_len(2) + uint16[]
                gl = _u16(edata, 0)
                for i in range(0, gl, 2):
                    g = _u16(edata, 2 + i)
                    if g not in _GREASE:
                        curves.append(g)
            elif etype == 0x000b and len(edata) >= 1:
                # ec_point_formats: list_len(1) + uint8[]
                fl = edata[0]
                formats.extend(edata[1:1 + fl])

        ja3_str = "{},{},{},{},{}".format(
            version,
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in exts),
            "-".join(str(c) for c in curves),
            "-".join(str(f) for f in formats),
        )
        alpn = ",".join(alpn_protos)
        return sni, alpn, hashlib.md5(ja3_str.encode()).hexdigest()
    except (struct.error, IndexError):
        return None


def _upsert(ip: str, sni: str, alpn: str, ja3: str) -> None:
    with SessionLocal() as session:
        session.add(TLSEvent(ip=ip, sni=sni, alpn=alpn, ja3=ja3, timestamp=utcnow()))
        session.commit()


def _handle(packet) -> None:
    if TCP not in packet or Raw not in packet:
        return
    result = _parse_client_hello(bytes(packet[Raw].load))
    if result is None:
        return
    sni, alpn, ja3 = result
    src_ip = packet[IP].src if IP in packet else ""
    _upsert(src_ip, sni, alpn, ja3)


def start(iface: str | None = None) -> None:
    # Filtr BPF zawęża do TCP/443 — parser i tak odrzuca pakiety, które nie są ClientHello.
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
