# Pasywny sniffer mDNS / DNS-SD: nasłuchuje lokalne rozgłoszenia mDNS
# i zapisuje każde urządzenie (IP + MAC) do bazy SQLite.
# "Pasywny" = tylko czytamy pakiety, niczego nie wysyłamy.

import threading

from scapy.all import Ether, IP, sniff

from database import Device, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background"]


def _upsert(ip: str, mac: str) -> None:
    with SessionLocal() as session:
        session.add(Device(
            ip=ip, 
            mac=mac, 
            protocol="mDNS", 
            last_seen=utcnow()
        ))
        session.commit()


def _handle(packet) -> None:
    # Scapy wywołuje tę funkcję dla każdego pakietu UDP na porcie 5353.
    # Sprawdzamy czy pakiet ma warstwę Ethernet (MAC) oraz IP.
    if Ether in packet and IP in packet:
        ip_src = packet[IP].src
        mac_src = packet[Ether].src
        
        # Ignorujemy pakiety od nas samych (opcjonalnie, ale bazujemy na IP źródłowym)
        # mDNS wysyła zapytania/odpowiedzi z IP urządzenia na adres multicastowy.
        if ip_src and mac_src:
            _upsert(ip_src, mac_src)


def start(iface: str | None = None) -> None:
    # Filtr BPF "udp port 5353" przechwytuje tylko ruch Multicast DNS.
    # store=False zapobiega wyciekom pamięci przy ciągłym nasłuchu.
    sniff(filter="udp port 5353", prn=_handle, store=False, iface=iface)


def start_in_background(iface: str | None = None) -> threading.Thread:
    # Uruchamia sniffer w osobnym wątku (daemon)
    thread = threading.Thread(target=start, kwargs={"iface": iface}, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    # Testy lokalne: wymaga sudo / uprawnień administratora
    init_db()
    print("Uruchamiam pasywny sniffer mDNS... Czekam na pakiety.")
    start()