import customtkinter as ctk
from tkinter import ttk
import csv
import os
import ctypes
import subprocess
import sys
import threading
from PIL import Image
from tkinter import filedialog, messagebox
from plyer import notification

# Maksymalna liczba wierszy ładowanych z bazy do każdej tabeli przy każdym odświeżeniu.
# Bez tego limit każde update_data() (co 5s) skanuje pełną historię bazy.
_ROW_LIMIT = 500

import sniffers.arp_sniffer as arp_sniffer
import sniffers.dhcp_sniffer as dhcp_sniffer
import sniffers.dns_sniffer as dns_sniffer
import sniffers.mdns_sniffer as mdns_sniffer
import sniffers.ssdp_sniffer as ssdp_sniffer
import sniffers.tls_sniffer as tls_sniffer
from database import Device, DHCPEvent, DNSEvent, mDNSEvent, SSDPEvent, TLSEvent, SessionLocal, init_db


def _detect_ifaces() -> dict[str, str | None]:
    """Zwraca uporządkowane mapowanie {etykieta wyświetlana: nazwa interfejsu lub None}.
    Pierwsza pozycja zawsze pozwala scapy wybrać domyślny interfejs."""
    mapping: dict[str, str | None] = {"Automatyczny (domyślny)": None}

    if sys.platform == "darwin":
        # networksetup -listallhardwareports zwraca pary "Hardware Port" → "Device" dla każdej karty.
        try:
            output = subprocess.check_output(
                ["networksetup", "-listallhardwareports"], text=True, timeout=5
            )
        except Exception:
            output = ""
        current_port: str | None = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_port = line.split(":", 1)[1].strip()
            elif line.startswith("Device:") and current_port:
                device = line.split(":", 1)[1].strip()
                if device.startswith("en"):
                    mapping[f"{current_port} ({device})"] = device
                current_port = None
        mapping["Loopback (lo0)"] = "lo0"
    elif sys.platform.startswith("linux"):
        try:
            for iface in sorted(os.listdir("/sys/class/net")):
                if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                    kind = "Wi-Fi"
                elif iface == "lo":
                    kind = "Loopback"
                else:
                    kind = "Ethernet"
                mapping[f"{kind} ({iface})"] = iface
        except Exception:
            pass
    else:
        # Windows i pozostałe: pokazujemy listę interfejsów znanych scapy bez prób klasyfikacji.
        try:
            from scapy.interfaces import get_working_ifaces
            for iface in get_working_ifaces():
                name = getattr(iface, "name", str(iface))
                mapping[name] = name
        except Exception:
            pass

    return mapping

try:
    myappid = "pjatk.passivenetworksentinel.project.1.0"
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except Exception as e:
    print(f"Nie udało się ustawić AppUserModelID: {e}")

try:
    myappid = "pjatk.passivenetworksentinel.project.1.0"
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except Exception as e:
    print(f"Nie udało się ustawić AppUserModelID: {e}")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class NetworkScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Passive Network Sentinel - PJATK Project")
        self.geometry("1200x700")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.last_device_count = 0

        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../logo-rnd.png")
        try:
            self.logo_image = ctk.CTkImage(light_image=Image.open(image_path), dark_image=Image.open(image_path), size=(300, 150))
        except Exception as e:
            print(f"Błąd logo: {e}")
            self.logo_image = None

        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        if self.logo_image:
            self.logo_label = ctk.CTkLabel(self.sidebar, image=self.logo_image, text="")
            self.logo_label.pack(pady=(20, 10), padx=20)

        self.btn_dashboard = ctk.CTkButton(self.sidebar, text="Dashboard (Ogólny)", fg_color="#1f538d", command=self.show_dashboard)
        self.btn_dashboard.pack(pady=8, padx=20, fill="x")

        self.btn_dhcp = ctk.CTkButton(self.sidebar, text="Analiza DHCP (OS)", fg_color="transparent", command=self.show_dhcp)
        self.btn_dhcp.pack(pady=8, padx=20, fill="x")

        self.btn_mdns = ctk.CTkButton(self.sidebar, text="Usługi mDNS", fg_color="transparent", command=self.show_mdns)
        self.btn_mdns.pack(pady=8, padx=20, fill="x")

        self.btn_ssdp = ctk.CTkButton(self.sidebar, text="Usługi SSDP", fg_color="transparent", command=self.show_ssdp)
        self.btn_ssdp.pack(pady=8, padx=20, fill="x")

        self.btn_dns = ctk.CTkButton(self.sidebar, text="Zapytania DNS", fg_color="transparent", command=self.show_dns)
        self.btn_dns.pack(pady=8, padx=20, fill="x")

        self.btn_tls = ctk.CTkButton(self.sidebar, text="TLS ClientHello (SNI/JA3)", fg_color="transparent", command=self.show_tls)
        self.btn_tls.pack(pady=8, padx=20, fill="x")

        self.btn_settings = ctk.CTkButton(self.sidebar, text="Ustawienia Skanera", fg_color="transparent", command=self.show_settings)
        self.btn_settings.pack(pady=8, padx=20, fill="x")

        self.btn_clear = ctk.CTkButton(self.sidebar, text="Wyczyść historię", fg_color="transparent", hover_color="#c0392b", border_color="#e74c3c", border_width=1, command=self.clear_database_action)
        self.btn_clear.pack(pady=20, padx=20, fill="x")

        self.status_label = ctk.CTkLabel(
            self.sidebar, 
            text="● Skanowanie aktywne", 
            text_color="#2ecc71",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="bottom", pady=20)

        self.iface_map = _detect_ifaces()
        self.current_iface_label = next(iter(self.iface_map))

        self.dashboard_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.dhcp_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.mdns_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.ssdp_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.dns_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.tls_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.settings_frame = ctk.CTkFrame(self, fg_color="transparent")

        self.build_dashboard_view()
        self.build_dhcp_view()
        self.build_mdns_view()
        self.build_ssdp_view()
        self.build_dns_view()
        self.build_tls_view()
        self.build_settings_view()

        self.setup_table_style()
        self.show_dashboard()

        init_db()
        arp_sniffer.start_in_background()
        dhcp_sniffer.start_in_background()
        mdns_sniffer.start_in_background()
        ssdp_sniffer.start_in_background()
        dns_sniffer.start_in_background()
        tls_sniffer.start_in_background()
        self.update_data()

    def build_dashboard_view(self):
        self.stats_frame = ctk.CTkFrame(self.dashboard_frame, height=80)
        self.stats_frame.pack(fill="x", pady=(0, 10))

        self.show_dashboard()

    def build_dashboard_view(self):
        self.stats_frame = ctk.CTkFrame(self.dashboard_frame, height=80)
        self.stats_frame.pack(fill="x", pady=(0, 10))
        
        self.device_count_label = ctk.CTkLabel(
            self.stats_frame, 
            text="Wykryte urządzenia: 0", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.device_count_label.pack(side="left", padx=30, pady=20)

        self.stats_frame2 = ctk.CTkFrame(self.dashboard_frame, height=80)
        self.stats_frame2.pack(fill="x", pady=(0, 10))

        self.total_events_label = ctk.CTkLabel(
            self.stats_frame2,
            text="Wszystkie zdarzenia: 0",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.total_events_label.pack(side="left", padx=30, pady=20)

        self.table_container = ctk.CTkFrame(self.dashboard_frame)
        self.table_container.pack(fill="both", expand=True)

        self.table = ttk.Treeview(
            self.table_container, 
            columns=("IP", "MAC", "Vendor", "Protocol", "Last Seen"), 
            show="headings"
        )
        
        self.table.heading("IP", text="Adres IP")
        self.table.heading("MAC", text="Adres MAC")
        self.table.heading("Vendor", text="Producent")
        self.table.heading("Protocol", text="Protokół")
        self.table.heading("Last Seen", text="Aktywność")

        self.table.column("IP", width=130, anchor="center")
        self.table.column("MAC", width=140, anchor="center")
        self.table.column("Vendor", width=150, anchor="center")
        self.table.column("Protocol", width=90, anchor="center")
        self.table.column("Last Seen", width=100, anchor="center")

        self.table.pack(fill="both", expand=True, padx=5, pady=5)

        self.export_btn = ctk.CTkButton(
            self.dashboard_frame,
            text="Eksportuj Raport do CSV",
            command=self.export_data,
            fg_color="#1f538d",
            hover_color="#14375e"
        )
        self.export_btn.pack(pady=(20, 0))

    def build_dhcp_view(self):
        lbl = ctk.CTkLabel(self.dhcp_frame, text="Głęboka Inspekcja DHCP i Rozpoznawanie Systemów (OS Fingerprinting)", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(pady=10, anchor="w", padx=10)

        self.table_dhcp = ttk.Treeview(self.dhcp_frame, columns=("MAC", "ReqIP", "Hostname", "Type", "Option55", "OS", "Time"), show="headings")
        self.table_dhcp.heading("MAC", text="Adres MAC")
        self.table_dhcp.heading("ReqIP", text="Żądane IP")
        self.table_dhcp.heading("Hostname", text="Nazwa urządzenia")
        self.table_dhcp.heading("Type", text="Typ komunikatu")
        self.table_dhcp.heading("Option55", text="Opcja 55 (PRL)")
        self.table_dhcp.heading("OS", text="Wykryty System OS")
        self.table_dhcp.heading("Time", text="Czas zdarzenia")

        self.table_dhcp.column("Option55", width=150, stretch=False, anchor="center")
        self.table_dhcp.column("OS", width=150, stretch=False, anchor="center")
        self.table_dhcp.pack(fill="both", expand=True, padx=10, pady=10)

    def build_mdns_view(self):
        lbl = ctk.CTkLabel(self.mdns_frame, text="Wykryte Rekordy mDNS i Rozgłaszane Usługi Sieciowe", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(pady=10, anchor="w", padx=10)

        self.table_mdns = ttk.Treeview(self.mdns_frame, columns=("IP", "MAC", "Hostname", "Services", "Time"), show="headings")
        self.table_mdns.heading("IP", text="Adres IP")
        self.table_mdns.heading("MAC", text="Adres MAC")
        self.table_mdns.heading("Hostname", text="Nazwa domeny (.local)")
        self.table_mdns.heading("Services", text="Aktywne usługi na urządzeniu")
        self.table_mdns.heading("Time", text="Czas")

        self.table_mdns.column("Services", width=400, stretch=True)
        self.table_mdns.pack(fill="both", expand=True, padx=10, pady=10)

    def build_ssdp_view(self):
        lbl = ctk.CTkLabel(self.ssdp_frame, text="Wykryte Usługi SSDP / UPnP (multicast 239.255.255.250:1900)", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(pady=10, anchor="w", padx=10)

        self.table_ssdp = ttk.Treeview(self.ssdp_frame, columns=("IP", "Msg", "Server", "Service", "USN", "Location", "Time"), show="headings")
        self.table_ssdp.heading("IP", text="Adres IP")
        self.table_ssdp.heading("Msg", text="Typ wiadomości")
        self.table_ssdp.heading("Server", text="Server")
        self.table_ssdp.heading("Service", text="Typ usługi (NT/ST)")
        self.table_ssdp.heading("USN", text="USN (identyfikator urządzenia)")
        self.table_ssdp.heading("Location", text="Lokalizacja (URL)")
        self.table_ssdp.heading("Time", text="Czas")

        self.table_ssdp.column("IP", width=120, anchor="center")
        self.table_ssdp.column("Msg", width=110, anchor="center")
        self.table_ssdp.column("Server", width=180)
        self.table_ssdp.column("Service", width=180)
        self.table_ssdp.column("USN", width=240)
        self.table_ssdp.column("Location", width=240, stretch=True)
        self.table_ssdp.column("Time", width=90, anchor="center")
        self.table_ssdp.pack(fill="both", expand=True, padx=10, pady=10)

    def build_dns_view(self):
        lbl = ctk.CTkLabel(self.dns_frame, text="Przechwycone Zapytania DNS (UDP/53)", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(pady=10, anchor="w", padx=10)

        self.table_dns = ttk.Treeview(self.dns_frame, columns=("IP", "Resolver", "Query", "Type", "Time"), show="headings")
        self.table_dns.heading("IP", text="Adres IP klienta")
        self.table_dns.heading("Resolver", text="Resolver (DNS docelowy)")
        self.table_dns.heading("Query", text="Zapytana domena")
        self.table_dns.heading("Type", text="Typ rekordu")
        self.table_dns.heading("Time", text="Czas")

        self.table_dns.column("IP", width=130, anchor="center")
        self.table_dns.column("Resolver", width=160, anchor="center")
        self.table_dns.column("Query", width=360, stretch=True)
        self.table_dns.column("Type", width=110, anchor="center")
        self.table_dns.column("Time", width=90, anchor="center")
        self.table_dns.pack(fill="both", expand=True, padx=10, pady=10)

    def build_tls_view(self):
        lbl = ctk.CTkLabel(self.tls_frame, text="Przechwycone TLS ClientHello (SNI + fingerprint JA3)", font=ctk.CTkFont(size=18, weight="bold"))
        lbl.pack(pady=10, anchor="w", padx=10)

        self.table_tls = ttk.Treeview(self.tls_frame, columns=("IP", "SNI", "ALPN", "JA3", "Time"), show="headings")
        self.table_tls.heading("IP", text="Adres IP klienta")
        self.table_tls.heading("SNI", text="SNI (host docelowy)")
        self.table_tls.heading("ALPN", text="ALPN (protokoły)")
        self.table_tls.heading("JA3", text="Fingerprint JA3")
        self.table_tls.heading("Time", text="Czas")

        self.table_tls.column("IP", width=130, anchor="center")
        self.table_tls.column("SNI", width=260, stretch=True)
        self.table_tls.column("ALPN", width=130, anchor="center")
        self.table_tls.column("JA3", width=250, anchor="center")
        self.table_tls.column("Time", width=90, anchor="center")
        self.table_tls.pack(fill="both", expand=True, padx=10, pady=10)

    def build_settings_view(self):
        title = ctk.CTkLabel(self.settings_frame, text="Ustawienia Skanera", font=ctk.CTkFont(size=18, weight="bold"))
        title.pack(pady=10, padx=10, anchor="w")

        card = ctk.CTkFrame(self.settings_frame)
        card.pack(fill="x", padx=20, pady=10)

        label_iface = ctk.CTkLabel(
            card,
            text="Wybierz interfejs sieciowy do nasłuchu:",
            font=ctk.CTkFont(size=14)
        )
        label_iface.pack(pady=(20, 5), padx=20, anchor="w")

        self.iface_switch = ctk.CTkOptionMenu(
            card,
            values=list(self.iface_map.keys()),
            width=320,
        )
        self.iface_switch.set(self.current_iface_label)
        self.iface_switch.pack(pady=(0, 20), padx=20, anchor="w")

        self.switch_notifications = ctk.CTkSwitch(
            card,
            text="Powiadomienia systemowe o nowym MAC",
            font=ctk.CTkFont(size=14)
        )
        self.switch_notifications.pack(pady=20, padx=20, anchor="w")

        self.btn_save = ctk.CTkButton(
            self.settings_frame,
            text="Zapisz i zrestartuj skaner",
            fg_color="#2ecc71",
            hover_color="#27ae60",
            command=self.save_settings_action,
        )
        self.btn_save.pack(pady=30, padx=20, anchor="w")

    def hide_all_frames(self):
        """Pomocnicza metoda ukrywająca wszystkie widoki przed przełączeniem"""
        for frame in [self.dashboard_frame, self.dhcp_frame, self.mdns_frame, self.ssdp_frame, self.dns_frame, self.tls_frame, self.settings_frame]:
            frame.grid_forget()

    def clear_active_buttons(self):
        """Resetuje kolor tła wszystkich przycisków w menu bocznym"""
        for btn in [self.btn_dashboard, self.btn_dhcp, self.btn_mdns, self.btn_ssdp, self.btn_dns, self.btn_tls, self.btn_settings]:
            btn.configure(fg_color="transparent")

    def show_dashboard(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.dashboard_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_dashboard.configure(fg_color="#1f538d")

    def show_dhcp(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.dhcp_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_dhcp.configure(fg_color="#1f538d")

    def show_mdns(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.mdns_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_mdns.configure(fg_color="#1f538d")

    def show_ssdp(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.ssdp_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_ssdp.configure(fg_color="#1f538d")

    def show_dns(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.dns_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_dns.configure(fg_color="#1f538d")

    def show_tls(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.tls_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_tls.configure(fg_color="#1f538d")

    def show_settings(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.settings_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_settings.configure(fg_color="#1f538d")

    def save_settings_action(self):
        selected_label = self.iface_switch.get()
        if selected_label not in self.iface_map:
            messagebox.showerror("Ustawienia Skanera", f"Nieznany interfejs: {selected_label}")
            return
        iface = self.iface_map[selected_label]

        # set_iface() blokuje na czas AsyncSniffer.stop() (czeka na join wątku snifera,
        # czasem 1-2s). Odpalamy całość w tle, żeby GUI nie zamarzało.
        self.btn_save.configure(state="disabled", text="Restartowanie snifferów…")

        def worker() -> None:
            errors: list[str] = []
            for name, mod in [
                ("ARP", arp_sniffer),
                ("DHCP", dhcp_sniffer),
                ("mDNS", mdns_sniffer),
                ("SSDP", ssdp_sniffer),
                ("DNS", dns_sniffer),
                ("TLS", tls_sniffer),
            ]:
                try:
                    mod.set_iface(iface)
                except Exception as e:
                    errors.append(f"{name}: {e}")
            self.after(0, lambda: self._on_save_settings_done(selected_label, iface, errors))

        threading.Thread(target=worker, daemon=True).start()

    def _on_save_settings_done(self, selected_label: str, iface: str | None, errors: list[str]) -> None:
        self.btn_save.configure(state="normal", text="Zapisz i zrestartuj skaner")

        if errors:
            messagebox.showerror(
                "Ustawienia Skanera",
                "Część snifferów nie wystartowała na nowym interfejsie:\n\n" + "\n".join(errors),
            )
            return

        self.current_iface_label = selected_label

        if self.switch_notifications.get() == 1:
            try:
                notification.notify(
                    title="Passive Sentinel",
                    message=f"Skaner przeładowany dla interfejsu: {selected_label}",
                    app_name="Passive Sentinel",
                    timeout=5,
                )
            except Exception as e:
                print(f"Błąd wysyłania powiadomienia systemowego: {e}")

        iface_human = iface if iface is not None else "domyślny (scapy wybiera)"
        messagebox.showinfo(
            "Ustawienia Skanera",
            f"Zapisano ustawienia!\nInterfejs: {selected_label}\nNazwa systemowa: {iface_human}\nSkaner został przeładowany.",
        )

    def clear_database_action(self):
        confirm = messagebox.askyesno(
            "Potwierdzenie czyszczenia",
            "Czy na pewno chcesz bezpowrotnie usunąć całą historię ze wszystkich tabel bazy danych?"
        )
        if confirm:
            try:
                with SessionLocal() as session:
                    session.query(Device).delete()
                    session.query(DHCPEvent).delete()
                    session.query(mDNSEvent).delete()
                    session.query(SSDPEvent).delete()
                    session.query(DNSEvent).delete()
                    session.query(TLSEvent).delete()
                    session.commit()

                for t in [self.table, self.table_dhcp, self.table_mdns, self.table_ssdp, self.table_dns, self.table_tls]:
                    for i in t.get_children():
                        t.delete(i)

                self.device_count_label.configure(text="Wykryte urządzenia: 0")
                self.total_events_label.configure(text="Wszystkie zdarzenia: 0")
                self.last_device_count = 0

                messagebox.showinfo("Sukces", "Wszystkie bazy danych i listy zostały wyczyszczone!")
            except Exception as e:
                messagebox.showerror("Błąd", f"Nie udało się wyczyścić baz danych: {e}")

    def setup_table_style(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background="#2b2b2b",
            foreground="white",
            fieldbackground="#2b2b2b",
            rowheight=30,
            borderwidth=0
        )
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', '#1f538d')])

    def update_data(self):
        for t in [self.table, self.table_dhcp, self.table_mdns, self.table_ssdp, self.table_dns, self.table_tls]:
            for i in t.get_children():
                t.delete(i)

        unique_macs = set()
        total_events = 0

        try:
            with SessionLocal() as session:
                # Device: jedna linia per MAC (sniffer robi prawdziwy upsert),
                # więc tabela jest naturalnie ograniczona liczbą urządzeń.
                devices = session.query(Device).order_by(Device.last_seen.desc()).all()
                for d in devices:
                    formatted_time = d.last_seen.strftime("%H:%M:%S") if d.last_seen else "Nieznana"
                    vendor_name = d.vendor if d.vendor else "Nieznany"
                    row = (d.ip, d.mac, vendor_name, d.protocol, formatted_time)
                    self.table.insert("", "end", values=row)
                    unique_macs.add(d.mac)
                    total_events += 1

                # Pozostałe tabele to logi zdarzeń — bierzemy ostatnie _ROW_LIMIT rekordów.
                dhcp_records = (
                    session.query(DHCPEvent)
                    .order_by(DHCPEvent.id.desc())
                    .limit(_ROW_LIMIT)
                    .all()
                )
                for dhcp in dhcp_records:
                    t_time = dhcp.timestamp.strftime("%H:%M:%S") if dhcp.timestamp else "Nieznana"
                    row_dhcp = (dhcp.mac, dhcp.requested_ip, dhcp.hostname, dhcp.message_type, dhcp.parameter_request_list, dhcp.predicted_os, t_time)
                    self.table_dhcp.insert("", "end", values=row_dhcp)
                    unique_macs.add(dhcp.mac)

                mdns_records = (
                    session.query(mDNSEvent)
                    .order_by(mDNSEvent.id.desc())
                    .limit(_ROW_LIMIT)
                    .all()
                )
                for mdns in mdns_records:
                    m_time = mdns.timestamp.strftime("%H:%M:%S") if mdns.timestamp else "Nieznana"
                    row_mdns = (mdns.ip, mdns.mac, mdns.hostname, mdns.services, m_time)
                    self.table_mdns.insert("", "end", values=row_mdns)
                    if mdns.mac:
                        unique_macs.add(mdns.mac)

                ssdp_records = (
                    session.query(SSDPEvent)
                    .order_by(SSDPEvent.id.desc())
                    .limit(_ROW_LIMIT)
                    .all()
                )
                for ssdp in ssdp_records:
                    s_time = ssdp.timestamp.strftime("%H:%M:%S") if ssdp.timestamp else "Nieznana"
                    row_ssdp = (ssdp.ip, ssdp.message_type, ssdp.server, ssdp.service_type, ssdp.usn, ssdp.location, s_time)
                    self.table_ssdp.insert("", "end", values=row_ssdp)
                    total_events += 1

                dns_records = (
                    session.query(DNSEvent)
                    .order_by(DNSEvent.id.desc())
                    .limit(_ROW_LIMIT)
                    .all()
                )
                for dns in dns_records:
                    d_time = dns.timestamp.strftime("%H:%M:%S") if dns.timestamp else "Nieznana"
                    row_dns = (dns.ip, dns.resolver_ip, dns.query_name, dns.query_type, d_time)
                    self.table_dns.insert("", "end", values=row_dns)
                    total_events += 1

                tls_records = (
                    session.query(TLSEvent)
                    .order_by(TLSEvent.id.desc())
                    .limit(_ROW_LIMIT)
                    .all()
                )
                for tls in tls_records:
                    t_time = tls.timestamp.strftime("%H:%M:%S") if tls.timestamp else "Nieznana"
                    row_tls = (tls.ip, tls.sni, tls.alpn, tls.ja3, t_time)
                    self.table_tls.insert("", "end", values=row_tls)
                    total_events += 1

        except Exception as e:
            print(f"Błąd podczas pobierania danych z baz: {e}")

        current_unique_count = len(unique_macs)

        if self.last_device_count > 0 and current_unique_count > self.last_device_count:
            if self.switch_notifications.get() == 1:
                try:
                    notification.notify(
                        title="Wykryto nowe urządzenie!",
                        message="W sieci pojawił się nowy adres MAC. Sprawdź Dashboard.",
                        app_name="Passive Sentinel",
                        timeout=7
                    )
                except Exception as e:
                    print(f"Błąd wysyłania powiadomienia: {e}")

        self.last_device_count = current_unique_count

        self.device_count_label.configure(text=f"Wykryte urządzenia: {current_unique_count}")
        self.total_events_label.configure(text=f"Wszystkie zdarzenia: {total_events}")

        self.after(5000, self.update_data)

    def export_data(self):
        data_to_save = []
        for child in self.table.get_children():
            data_to_save.append(self.table.item(child)["values"])

        if not data_to_save:
            messagebox.showwarning("Eksport", "Brak danych do wyeksportowania")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Pliki CSV", "*.csv")],
            initialfile="raport_zdarzen.csv"
        )

        if file_path:
            try:
                with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["Adres IP", "Adres MAC", "Producent", "Protokół", "Aktywność"])
                    writer.writerows(data_to_save)
                messagebox.showinfo("Sukces", f"Zapisano pomyślnie")
            except Exception as e:
                messagebox.showerror("Błąd", f"Błąd zapisu: {e}")

if __name__ == "__main__":
    app = NetworkScannerGUI()
    app.mainloop()