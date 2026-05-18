# Pasywny sniffer ARP: nasłuchuje w sieci lokalnej pakiety ARP
# i zapisuje każde urządzenie (IP + MAC) do bazy SQLite.
# "Pasywny" = tylko czytamy pakiety, niczego nie wysyłamy.

import threading

from scapy.all import ARP, sniff

from database import Device, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background"]


    # Dodaje nowe urządzenie, albo aktualizuje IP + last_seen, jeśli MAC już jest w bazie.
def _upsert(ip: str, mac: str) -> None:
    with SessionLocal() as session:
        session.add(Device(ip=ip, mac=mac, protocol="ARP", last_seen=utcnow()))
        session.commit()


def _handle(packet) -> None:
    # scapy wywołuje tę funkcję dla każdego przechwyconego pakietu.
    # op 1 = zapytanie ARP ("kto ma IP X?"), op 2 = odpowiedź ARP ("ja mam IP X").
    # W obu przypadkach mamy IP nadawcy (psrc) i MAC nadawcy (hwsrc) — tyle nam wystarczy.
    if ARP in packet and packet[ARP].op in (1, 2):
        _upsert(packet[ARP].psrc, packet[ARP].hwsrc)


def start(iface: str | None = None) -> None:
    # Wywołanie blokujące. Filtr BPF "arp" sprawia, że jądro przekazuje nam tylko pakiety ARP.
    # store=False, żeby scapy nie trzymał pakietów w pamięci — i tak już zapisaliśmy to, co trzeba.
    # iface=None pozwala scapy wybrać domyślny interfejs sieciowy.
    sniff(filter="arp", prn=_handle, store=False, iface=iface)


def start_in_background(iface: str | None = None) -> threading.Thread:
    # Uruchamia sniffer w wątku daemon, żeby nie blokował GUI
    # i zamknął się automatycznie razem z głównym programem.
    thread = threading.Thread(target=start, kwargs={"iface": iface}, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    # Tryb samodzielny: przydatny do testów sniffera bez uruchamiania GUI.
    # UWAGA: wymaga uprawnień root/admin (surowe gniazda) — odpalaj przez `sudo`.
    init_db()
    start()
