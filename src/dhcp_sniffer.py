# Pasywny sniffer DHCP: nasłuchuje w sieci lokalnej pakiety DHCP
# i zapisuje każde urządzenie (IP + MAC) do bazy SQLite.
# "Pasywny" = tylko czytamy pakiety, niczego nie wysyłamy.

import threading

from scapy.all import DHCP, BOOTP, sniff

from database import Device, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background"]


def _upsert(ip: str, mac: str, protocol: str) -> None:
    with SessionLocal() as session:
        session.add(Device(
            ip=ip,
            mac=mac,
            protocol=protocol,
            last_seen=utcnow()
        ))
        session.commit()


def _handle(packet) -> None:
    # Scapy wywołuje tę funkcję dla każdego przechwyconego pakietu UDP 67/68.
    if DHCP in packet and BOOTP in packet:
        options = packet[DHCP].options
                
        # Wyciągamy typ wiadomości DHCP (np. discover, offer, request, ack)
        msg_type = None
        for opt in options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                msg_type = opt[1]
                break
        
        # Interesują nas głównie Request (3) oraz ACK (5)
        # W nich następuje potwierdzenie przypisania IP do MAC
        if msg_type in (3, 5):
            # Adres MAC klienta jest w warstwie BOOTP (chaddr)
            # Scapy zwraca go w postaci bajtów, musimy go ładnie sformatować do stringa
            mac_raw = packet[BOOTP].chaddr[:6]
            mac = ":".join(f"{b:02x}" for b in mac_raw)
            
            # Adres IP szukamy w opcjach (requested_addr) lub w polu yiaddr (Your IP)
            ip = None
            for opt in options:
                if isinstance(opt, tuple) and opt[0] == 'requested_addr':
                    ip = opt[1]
                    break
            
            # Jeśli nie było go w opcji 'requested_addr', bierzemy z pola 'yiaddr' (serwer przydzielił)
            if not ip and packet[BOOTP].yiaddr != "0.0.0.0":
                ip = packet[BOOTP].yiaddr
                
            # Jeśli udało się zebrać komplet danych i IP nie jest puste, zapisujemy
            print("zapisujemy")
            print(ip, mac)
            if ip and mac and ip != "0.0.0.0":
                _upsert(ip, mac, protocol="DHCP")
                print(f"[DHCP Sniffer] Zapisano urządzenie: {ip} <-> {mac}")


def start(iface: str | None = None) -> None:
    # Filtr BPF "udp port 67 or port 68" przechwytuje tylko ruch DHCP.
    # store=False oszczędza pamięć RAM.
    sniff(filter="udp port 67 or port 68", prn=_handle, store=False, iface=iface)


def start_in_background(iface: str | None = None) -> threading.Thread:
    # Uruchamia sniffer w wątku daemon
    thread = threading.Thread(target=start, kwargs={"iface": iface}, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    # Testy lokalne: wymaga sudo / uprawnień administratora
    init_db()
    print("Uruchamiam pasywny sniffer DHCP... Czekam na pakiety.")
    start()