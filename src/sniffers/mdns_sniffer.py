# Pasywny sniffer mDNS / DNS-SD: nasłuchuje lokalne rozgłoszenia mDNS
# Wyciąga nazwy hostów (.local) oraz typy usług (np. AirPrint, Spotify Connect).

import threading
from scapy.all import sniff, IP, UDP, DNS, Ether
from database import mDNSEvent, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background"]

def _handle(packet):
    # mDNS działa na porcie UDP 5353
    if UDP in packet and packet[UDP].dport == 5353 and DNS in packet:
        ip_src = packet[IP].src if IP in packet else "0.0.0.0"
        mac_src = packet[Ether].src if Ether in packet else "Nieznany"
        
        hostname = "Nieznany"
        services = set()

        # --- ANALIZA REKORDÓW DNS ---
        # Sprawdzamy odpowiedzi (ancount - answer count)
        if packet[DNS].ancount > 0:
            for i in range(packet[DNS].ancount):
                rr = packet[DNS].an[i]
                
                # Typ 12 (PTR) zazwyczaj zawiera nazwy konkretnych usług
                if rr.type == 12:
                    rdata = rr.rdata.decode('utf-8', errors='ignore') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    services.add(rdata)
                
                # Próbujemy wyłuskać nazwę urządzenia kończącą się na .local
                if rr.rrname:
                    name = rr.rrname.decode('utf-8', errors='ignore') if isinstance(rr.rrname, bytes) else str(rr.rrname)
                    if ".local" in name:
                        # Czyścimy kropkę na końcu, jeśli istnieje
                        hostname = name.strip('.')

        # Zapisujemy tylko, jeśli udało się wyciągnąć coś sensownego
        if services or hostname != "Nieznany":
            with SessionLocal() as session:
                session.add(mDNSEvent(
                    ip=ip_src,
                    mac=mac_src,
                    hostname=hostname,
                    services=", ".join(services) if services else "Zapytanie / Rekord standardowy",
                    timestamp=utcnow()
                ))
                session.commit()

def start(iface=None):
    # Filtr BPF ogranicza ruch tylko do mDNS
    sniff(filter="udp port 5353", prn=_handle, store=False, iface=iface)

def start_in_background(iface=None):
    # Wątek typu daemon zamknie się razem z GUI
    thread = threading.Thread(target=start, kwargs={"iface": iface}, daemon=True)
    thread.start()
    return thread

def set_iface(iface):
    # Ta funkcja pozwoli GUI zrestartować sniffer na nowej karcie sieciowej
    return start_in_background(iface=iface)

if __name__ == "__main__":
    init_db()
    print("Uruchamiam ulepszony sniffer mDNS... Czekam na rozgłoszenia usług.")
    start()
