import customtkinter as ctk
from tkinter import ttk
import csv
import os
from PIL import Image
from tkinter import filedialog, messagebox

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class NetworkScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Passive Network Sentinel - PJSEC Project")
        self.geometry("1150x650")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "logo-rnd.png")
        
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
        self.sidebar.grid_rowconfigure(4, weight=1)

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
            text="Live Events Feed", 
            fg_color="#1f538d", 
            border_width=1,
            hover_color="#14375e"
        )
        self.btn_dashboard.pack(pady=10, padx=20, fill="x")

        self.btn_settings = ctk.CTkButton(
            self.sidebar, 
            text="Ustawienia Skanera", 
            fg_color="transparent", 
            border_width=1
        )
        self.btn_settings.pack(pady=10, padx=20, fill="x")

        self.status_label = ctk.CTkLabel(
            self.sidebar, 
            text="● Nasłuchiwanie sieci...", 
            text_color="#2ecc71",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="bottom", pady=20)

        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        self.stats_frame = ctk.CTkFrame(self.main_frame, height=80)
        self.stats_frame.pack(fill="x", pady=(0, 20))
        
        self.total_events_label = ctk.CTkLabel(
            self.stats_frame, 
            text="Wszystkie zdarzenia: 0", 
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.total_events_label.pack(side="left", padx=30, pady=20)

        self.unique_devices_label = ctk.CTkLabel(
            self.stats_frame, 
            text="Unikalne urządzenia (MAC): 0", 
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#3498db"
        )
        self.unique_devices_label.pack(side="left", padx=30, pady=20)

        self.setup_table_style()
        
        self.table_container = ctk.CTkFrame(self.main_frame)
        self.table_container.pack(fill="both", expand=True)

        self.table = ttk.Treeview(
            self.table_container, 
            columns=("Time", "Protocol", "MAC", "IP", "Details"), 
            show="headings"
        )
        
        self.table.heading("Time", text="Czas")
        self.table.heading("Protocol", text="Protokół")
        self.table.heading("MAC", text="Źródłowy MAC")
        self.table.heading("IP", text="Wykryty/Przypisany IP")
        self.table.heading("Details", text="Szczegóły zdarzenia")

        self.table.column("Time", width=90, anchor="center")
        self.table.column("Protocol", width=90, anchor="center")
        self.table.column("MAC", width=140, anchor="center")
        self.table.column("IP", width=130, anchor="center")
        self.table.column("Details", width=400, anchor="w")

        self.table.pack(fill="both", expand=True, padx=5, pady=5)

        self.export_btn = ctk.CTkButton(
            self.main_frame, 
            text="Eksportuj Logi do CSV", 
            command=self.export_data,
            fg_color="#1f538d",
            hover_color="#14375e"
        )
        self.export_btn.pack(pady=(20, 0))

        self.update_data()

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
        """TUTAJ BACKEND I DB"""
        for i in self.table.get_children():
            self.table.delete(i)
            
        # Zaktualizowane przykładowe dane pokazujące historię pakietów z DHCP i mDNS
        mock_data = [
            ("17:12:01", "DHCP", "AA:BB:CC:00:11:22", "0.0.0.0", "DHCP Discover (Urządzenie prosi o adres)"),
            ("17:12:03", "DHCP", "AA:BB:CC:00:11:22", "192.168.1.15", "DHCP Request (Przypisano IP przez router)"),
            ("17:12:45", "SSDP", "BB:CC:DD:33:44:55", "192.168.1.42", "Rozgłoszenie usługi UPnP Serwera Mediów"),
            ("17:13:10", "ARP", "00:50:56:C0:00:08", "192.168.1.101", "Who has 192.168.1.1? Tell 192.168.1.101"),
            ("17:13:15", "mDNS", "AA:BB:CC:00:11:22", "192.168.1.15", "Zapytanie o urządzenie: iPhone-Dawida.local")
        ]
        
        for row in mock_data:
            self.table.insert("", "end", values=row)
            
        all_macs = [row[2] for row in mock_data]
        unique_macs_count = len(set(all_macs))
            
        self.total_events_label.configure(text=f"Wszystkie zdarzenia: {len(mock_data)}")
        self.unique_devices_label.configure(text=f"Unikalne urządzenia (MAC): {unique_macs_count}")
        
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
                    writer.writerow(["Czas", "Protokół", "MAC", "IP", "Szczegóły"])
                    writer.writerows(data_to_save)
                messagebox.showinfo("Sukces", f"Zapisano pomyślnie")
            except Exception as e:
                messagebox.showerror("Błąd", f"Błąd zapisu: {e}")

if __name__ == "__main__":
    app = NetworkScannerGUI()
    app.mainloop()