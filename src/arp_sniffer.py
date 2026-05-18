import threading
from scapy.all import sniff, ARP, DHCP, IP, UDP, DNS, DNSRR
from database import Device, DHCPEvent, mDNSEvent, SessionLocal, init_db, utcnow

def _handle_packet(packet):
    try:
        if ARP in packet and packet[ARP].op in (1, 2):
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            with SessionLocal() as session:
                session.add(Device(ip=ip, mac=mac, protocol="ARP", last_seen=utcnow()))
                session.commit()

        elif DHCP in packet:
            mac = packet[Ether].src if hasattr(packet, 'Ether') else "Nieznany"
            options = packet[DHCP].options
            
            message_type = "Unknown"
            requested_ip = "0.0.0.0"
            hostname = "Nieznany"
            option55_str = ""
            
            for opt in options:
                if isinstance(opt, tuple):
                    key = opt[0]
                    val = opt[1]
                    if key == 'message-type':
                        types = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
                        message_type = types.get(val, str(val))
                    elif key == 'requested_addr':
                        requested_ip = str(val)
                    elif key == 'hostname':
                        hostname = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
                    elif key == 'param_req_list':
                        option55_str = ",".join(map(str, val))

            if option55_str:
                if "1,3,6,15,31,33,43,44,46,47,119,121,249,252" in option55_str:
                    predicted_os = "Windows 10 / 11"
                elif "1,121,3,6,15,114,119,252" in option55_str:
                    predicted_os = "Apple iOS / macOS"
                elif "1,3,6,15,26,28,51,58,59,43" in option55_str:
                    predicted_os = "Android / Linux"
                else:
                    predicted_os = "Urządzenie IoT / Linux"

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

        elif UDP in packet and packet[UDP].dport == 5353:
            if DNS in packet:
                ip_src = packet[IP].src if IP in packet else "0.0.0.0"
                mac_src = packet[Ether].src if hasattr(packet, 'Ether') else "Nieznany"
                
                hostname = "Nieznany"
                services = set()

                if packet[DNS].ancount > 0:
                    for i in range(packet[DNS].ancount):
                        rr = packet[DNS].an[i]
                        if rr.type == 12:
                            rdata = rr.rdata.decode('utf-8', errors='ignore') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                            services.add(rdata)
                        if rr.rrname:
                            name = rr.rrname.decode('utf-8', errors='ignore') if isinstance(rr.rrname, bytes) else str(rr.rrname)
                            if ".local" in name:
                                hostname = name.strip('.')

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

    except Exception as e:
        print(f"Błąd parsowania pakietu: {e}")

def start(iface=None):
    filter_bpf = "arp or port 67 or port 68 or port 5353"
    sniff(filter=filter_bpf, prn=_handle_packet, store=False, iface=iface)

def start_in_background(iface=None):
    thread = threading.Thread(target=start, kwargs={"iface": iface}, daemon=True)
    thread.start()
    return thread