# Pasywny sniffer ARP: nasłuchuje w sieci lokalnej pakiety ARP
# i zapisuje każde urządzenie (IP + MAC) do bazy SQLite.
# "Pasywny" = tylko czytamy pakiety, niczego nie wysyłamy.

import threading
from functools import lru_cache

from scapy.layers.l2 import ARP
from scapy.sendrecv import AsyncSniffer, sniff

from database import Device, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background", "set_iface"]

# Filtr BPF "arp" sprawia, że jądro przekazuje nam tylko pakiety ARP.
_BPF = "arp"

# Pojedyncza instancja snifera w tle — pozwala GUI go zatrzymać i wystartować
# ponownie na innym interfejsie bez restartu całego programu.
_lock = threading.Lock()
_current: AsyncSniffer | None = None


@lru_cache(maxsize=4096)
def _lookup_vendor(mac: str) -> str | None:
    # Korzysta z bazy OUI dołączonej do scapy. lookup() zwraca (krótka, długa nazwa)
    # albo coś w stylu ("UNKNOWN", "UNKNOWN") dla nieznanych prefiksów.
    try:
        from scapy.config import conf
        if conf.manufdb is None:
            return None
        result = conf.manufdb.lookup(mac)
    except Exception:
        return None
    if not result:
        return None
    if isinstance(result, tuple):
        long_name = result[1] if len(result) > 1 else None
        short_name = result[0] if len(result) > 0 else None
        name = long_name or short_name
    else:
        name = result
    if not name or name == "UNKNOWN":
        return None
    return name


def _upsert(ip: str, mac: str) -> None:
    # Prawdziwy upsert: jedna linia per urządzenie. Pierwsze widzenie wstawia, kolejne
    # tylko aktualizują IP i last_seen — vendor lookup robimy raz przy pierwszym wpisie.
    with SessionLocal() as session:
        device = session.query(Device).filter_by(mac=mac).one_or_none()
        if device is None:
            session.add(Device(
                ip=ip,
                mac=mac,
                vendor=_lookup_vendor(mac),
                protocol="ARP",
                last_seen=utcnow(),
            ))
        else:
            device.ip = ip
            device.last_seen = utcnow()
            if not device.vendor:
                device.vendor = _lookup_vendor(mac)
        session.commit()


def _handle(packet) -> None:
    # op 1 = zapytanie ARP ("kto ma IP X?"), op 2 = odpowiedź ARP ("ja mam IP X").
    if ARP in packet and packet[ARP].op in (1, 2):
        _upsert(packet[ARP].psrc, packet[ARP].hwsrc)


def start(iface: str | None = None) -> None:
    # Wywołanie blokujące — używane przez tryb samodzielny w if __name__ == "__main__".
    sniff(filter=_BPF, prn=_handle, store=False, iface=iface)


def start_in_background(iface: str | None = None) -> None:
    global _current
    with _lock:
        if _current is not None:
            return
        _current = AsyncSniffer(filter=_BPF, prn=_handle, store=False, iface=iface)
        _current.start()


def set_iface(iface: str | None) -> None:
    """Zatrzymuje bieżący sniffer i startuje go ponownie na wskazanym interfejsie."""
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
    # Tryb samodzielny: przydatny do testów sniffera bez uruchamiania GUI.
    # UWAGA: wymaga uprawnień root/admin (surowe gniazda) — odpalaj przez `sudo`.
    init_db()
    start()
