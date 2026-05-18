# Pasywny sniffer DHCP: nasłuchuje w sieci lokalnej pakiety DHCP
# Wykorzystuje fingerprinting opcji 55 do rozpoznawania systemów operacyjnych.

import threading
from scapy.all import sniff, DHCP, Ether, BOOTP
from database import DHCPEvent, SessionLocal, init_db, utcnow

__all__ = ["start", "start_in_background"]

def _handle(packet):
    if DHCP in packet:
        # Wyciąganie MAC z warstwy Ethernet (lepiej niż z BOOTP, bo uwzględnia ramkę sieciową)
        mac = packet[Ether].src if Ether in packet else "Nieznany"
        options = packet[DHCP].options
        
        message_type = "Unknown"
        requested_ip = "0.0.0.0"
        hostname = "Nieznany"
        option55_str = ""
        
        # Słownik typów wiadomości DHCP
        types = {
            1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 
            5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"
        }

        for opt in options:
            if isinstance(opt, tuple):
                key, val = opt[0], opt[1]
                if key == 'message-type':
                    message_type = types.get(val, str(val))
                elif key == 'requested_addr':
                    requested_ip = str(val)
                elif key == 'hostname':
                    hostname = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                elif key == 'param_req_list':
                    option55_str = ",".join(map(str, val))

        # --- FINGERPRINTING OS (Na podstawie listy żądanych parametrów) ---
        predicted_os = "Urządzenie IoT / Linux"  # Domyślny
        if option55_str:
            if "1,3,6,15,31,33,43,44,46,47,119,121,249,252" in option55_str:
                predicted_os = "Windows 10 / 11"
            elif "1,121,3,6,15,114,119,252" in option55_str:
                predicted_os = "Apple iOS / macOS"
            elif "1,3,6,15,26,28,51,58,59,43" in option55_str:
                predicted_os = "Android / Linux"

        # Zapis do nowej tabeli zdarzeń DHCP (DHCPEvent)
        with SessionLocal() as session:
            session.add(DHCPEvent(
                mac=mac,
                requested_ip=requested_ip,
                hostname=hostname,
                message_type=message_type,
                parameter_request_list=option55_str,
                predicted_os=predicted_os,
                timestamp=utcnow()
            ))
            session.commit()

def start(iface=None):
    # Filtr BPF przechwytuje pakiety DHCP (porty 67 i 68)
    sniff(filter="udp port 67 or port 68", prn=_handle, store=False, iface=iface)

def start_in_background(iface=None):
    # Uruchomienie w osobnym wątku, aby nie blokować GUI
    thread = threading.Thread(target=start, kwargs={"iface": iface}, daemon=True)
    thread.start()
    return thread

def set_iface(iface):
    # Ta funkcja pozwoli GUI zrestartować sniffer na nowej karcie sieciowej
    return start_in_background(iface=iface)

if __name__ == "__main__":
    init_db()
    print("Uruchamiam ulepszony sniffer DHCP z OS Fingerprinting...")
    start()
