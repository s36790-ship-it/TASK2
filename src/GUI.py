import customtkinter as ctk
from tkinter import ttk
import csv
import os
import ctypes
from PIL import Image
from tkinter import filedialog, messagebox
from plyer import notification

import arp_sniffer
from database import Device, SessionLocal, init_db

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
        self.geometry("1100x650")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.last_device_count = 0

        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../logo-rnd.png")

        try:
            self.logo_image = ctk.CTkImage(
                light_image=Image.open(image_path),
                dark_image=Image.open(image_path),
                size=(300, 150)
            )
        except Exception as e:
            print(f"Błąd ładowania logo: {e}")
            self.logo_image = None

        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        if self.logo_image:
            self.logo_label = ctk.CTkLabel(self.sidebar, image=self.logo_image, text="")
        else:
            self.logo_label = ctk.CTkLabel(self.sidebar, text="[BRAK LOGO]", text_color="red")
        self.logo_label.pack(pady=(20, 10), padx=20)

        self.title_label = ctk.CTkLabel(
            self.sidebar,
            text="PASSIVE SENTINEL",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.title_label.pack(pady=(0, 30))

        self.btn_dashboard = ctk.CTkButton(
            self.sidebar, 
            text="Dashboard", 
            fg_color="#1f538d", 
            border_width=1,
            hover_color="#14375e",
            command=self.show_dashboard
        )
        self.btn_dashboard.pack(pady=10, padx=20, fill="x")

        self.btn_settings = ctk.CTkButton(
            self.sidebar,
            text="Ustawienia Skanera",
            fg_color="transparent",
            border_width=1,
            hover_color="#14375e",
            command=self.show_settings
        )
        self.btn_settings.pack(pady=10, padx=20, fill="x")

        self.btn_clear = ctk.CTkButton(
            self.sidebar,
            text="Wyczyść historię",
            fg_color="transparent",
            border_width=1,
            hover_color="#c0392b",
            border_color="#e74c3c",
            command=self.clear_database_action
        )
        self.btn_clear.pack(pady=10, padx=20, fill="x")

        self.status_label = ctk.CTkLabel(
            self.sidebar, 
            text="● Skanowanie aktywne", 
            text_color="#2ecc71",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="bottom", pady=20)

        self.dashboard_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.settings_frame = ctk.CTkFrame(self, fg_color="transparent")

        self.build_dashboard_view()
        self.build_settings_view()

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

        self.filter_frame = ctk.CTkFrame(self.dashboard_frame, height=40)
        self.filter_frame.pack(fill="x", pady=(0, 15))

        self.filter_label = ctk.CTkLabel(self.filter_frame, text="Filtruj protokoły:", font=ctk.CTkFont(size=12, weight="bold"))
        self.filter_label.pack(side="left", padx=20, pady=10)

        self.filter_arp = ctk.CTkCheckBox(self.filter_frame, text="ARP", command=self.update_data)
        self.filter_arp.pack(side="left", padx=15)
        self.filter_arp.select()

        self.filter_dhcp = ctk.CTkCheckBox(self.filter_frame, text="DHCP", command=self.update_data)
        self.filter_dhcp.pack(side="left", padx=15)
        self.filter_dhcp.select()

        self.filter_mdns = ctk.CTkCheckBox(self.filter_frame, text="mDNS", command=self.update_data)
        self.filter_mdns.pack(side="left", padx=15)
        self.filter_mdns.select()

        self.setup_table_style()

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

    def build_settings_view(self):
        title = ctk.CTkLabel(
            self.settings_frame, 
            text="Ustawienia Pasywnego Skanera sieci", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        title.pack(pady=(10, 30), anchor="w", padx=20)

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

    def show_dashboard(self):
        self.settings_frame.grid_forget()
        self.dashboard_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_dashboard.configure(fg_color="#1f538d")
        self.btn_settings.configure(fg_color="transparent")

    def show_settings(self):
        self.dashboard_frame.grid_forget()
        self.settings_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.btn_settings.configure(fg_color="#1f538d")
        self.btn_dashboard.configure(fg_color="transparent")

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
            "Czy na pewno chcesz bezpowrotnie usunąć wszystkie wykryte urządzenia z bazy danych?"
        )
        if confirm:
            try:
                with SessionLocal() as session:
                    session.query(Device).delete()
                    session.commit()
                
                for i in self.table.get_children():
                    self.table.delete(i)
                
                self.device_count_label.configure(text="Wykryte urządzenia: 0")
                self.total_events_label.configure(text="Wszystkie zdarzenia: 0")
                self.last_device_count = 0
                
                messagebox.showinfo("Sukces", "Baza danych i lista zostały wyczyszczone!")
            except Exception as e:
                messagebox.showerror("Błąd", f"Nie udało się wyczyścić bazy: {e}")

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
        for i in self.table.get_children():
            self.table.delete(i)
            
        allowed_protocols = []
        if self.filter_arp.get() == 1: allowed_protocols.append("ARP")
        if self.filter_dhcp.get() == 1: allowed_protocols.append("DHCP")
        if self.filter_mdns.get() == 1: allowed_protocols.append("mDNS")
        
        unique_macs = set()
        total_events = 0

        try:
            with SessionLocal() as session:
                devices = session.query(Device).all()
                for d in devices:
                    if d.protocol in allowed_protocols:
                        formatted_time = d.last_seen.strftime("%H:%M:%S") if d.last_seen else "Nieznana"
                        vendor_name = d.vendor if d.vendor else "Wykryto"
                        row = (d.ip, d.mac, vendor_name, d.protocol, formatted_time)
                        self.table.insert("", "end", values=row)
                        
                        unique_macs.add(d.mac)
                        total_events += 1
        except Exception as e:
            print(f"Błąd podczas pobierania danych z bazy: {e}")
            
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