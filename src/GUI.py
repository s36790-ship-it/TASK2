import customtkinter as ctk
from tkinter import ttk
import csv
import os
import ctypes
from PIL import Image
from tkinter import filedialog, messagebox
from plyer import notification

import arp_sniffer
from database import Device, DHCPEvent, mDNSEvent, SessionLocal, init_db

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

        self.dashboard_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.dhcp_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.mdns_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.settings_frame = ctk.CTkFrame(self, fg_color="transparent")

        self.build_dashboard_view()
        self.build_dhcp_view()
        self.build_mdns_view()
        self.build_settings_view()

        self.setup_table_style()
        self.show_dashboard()

        init_db()
        arp_sniffer.start_in_background()
        self.update_data()

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
            values=["Automatyczny (Domyślna karta)", "Wi-Fi", "Ethernet", "Loopback"],
            width=250
        )
        self.iface_switch.pack(pady=(0, 20), padx=20, anchor="w")

        self.switch_notifications = ctk.CTkSwitch(
            card, 
            text="Powiadomienia systemowe o nowym MAC",
            font=ctk.CTkFont(size=14)
        )
        self.switch_notifications.pack(pady=20, padx=20, anchor="w")

        btn_save = ctk.CTkButton(
            self.settings_frame,
            text="Zapisz i zrestartuj skaner",
            fg_color="#2ecc71",
            hover_color="#27ae60",
            command=self.save_settings_action
        )
        btn_save.pack(pady=30, padx=20, anchor="w")

    def hide_all_frames(self):
        """Pomocnicza metoda ukrywająca wszystkie widoki przed przełączeniem"""
        for frame in [self.dashboard_frame, self.dhcp_frame, self.mdns_frame, self.settings_frame]:
            frame.grid_forget()

    def clear_active_buttons(self):
        """Resetuje kolor tła wszystkich przycisków w menu bocznym"""
        for btn in [self.btn_dashboard, self.btn_dhcp, self.btn_mdns, self.btn_settings]:
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

    def show_settings(self):
        self.hide_all_frames()
        self.clear_active_buttons()
        self.settings_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_settings.configure(fg_color="#1f538d")

    def save_settings_action(self):
        selected_iface = self.iface_switch.get()
        
        if self.switch_notifications.get() == 1:
            try:
                notification.notify(
                    title="Passive Sentinel",
                    message=f"Skaner przeładowany dla interfejsu: {selected_iface}",
                    app_name="Passive Sentinel",
                    timeout=5
                )
            except Exception as e:
                print(f"Błąd wysyłania powiadomienia systemowego: {e}")

        messagebox.showinfo(
            "Ustawienia Skanera", 
            f"Zapisano ustawienia!\nWybrany interfejs: {selected_iface}\nSkaner został przeładowany."
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
                    session.commit()
                
                for t in [self.table, self.table_dhcp, self.table_mdns]:
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
        for t in [self.table, self.table_dhcp, self.table_mdns]:
            for i in t.get_children():
                t.delete(i)
            
        unique_macs = set()
        total_events = 0

        try:
            with SessionLocal() as session:
                devices = session.query(Device).all()
                for d in devices:
                    formatted_time = d.last_seen.strftime("%H:%M:%S") if d.last_seen else "Nieznana"
                    vendor_name = d.vendor if d.vendor else "Wykryto"
                    row = (d.ip, d.mac, vendor_name, d.protocol, formatted_time)
                    self.table.insert("", "end", values=row)
                    
                    unique_macs.add(d.mac)
                    total_events += 1

                dhcp_records = session.query(DHCPEvent).all()
                for dhcp in dhcp_records:
                    t_time = dhcp.timestamp.strftime("%H:%M:%S") if dhcp.timestamp else "Nieznana"
                    row_dhcp = (dhcp.mac, dhcp.requested_ip, dhcp.hostname, dhcp.message_type, dhcp.parameter_request_list, dhcp.predicted_os, t_time)
                    self.table_dhcp.insert("", "end", values=row_dhcp)
                    unique_macs.add(dhcp.mac)

                mdns_records = session.query(mDNSEvent).all()
                for mdns in mdns_records:
                    m_time = mdns.timestamp.strftime("%H:%M:%S") if mdns.timestamp else "Nieznana"
                    row_mdns = (mdns.ip, mdns.mac, mdns.hostname, mdns.services, m_time)
                    self.table_mdns.insert("", "end", values=row_mdns)
                    if mdns.mac:
                        unique_macs.add(mdns.mac)

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
    init_db()
    app = NetworkScannerGUI()
    app.mainloop()