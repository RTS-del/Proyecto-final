import tkinter as tk
from tkinter import ttk
import sqlite3
from scapy.all import *

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aplicación Multi-modulo")
        self.geometry("800x600")

        # Configuración de la base de datos
        self.conn = sqlite3.connect('app.db')
        self.create_tables()

        # Ventana principal con botones para cada módulo
        self.create_main_window()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                          id INTEGER PRIMARY KEY,
                          date TEXT,
                          severity TEXT,
                          source TEXT,
                          message TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS api_data (
                          id INTEGER PRIMARY KEY,
                          endpoint TEXT,
                          data TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS pc_analysis (
                          id INTEGER PRIMARY KEY,
                          timestamp TEXT,
                          cpu_usage REAL,
                          memory_usage REAL,
                          disk_usage REAL,
                          temperature REAL)''')
        self.conn.commit()

    def create_main_window(self):
        ttk.Button(self, text="Calculadora IP", command=self.open_ip_calculator).pack(pady=10)
        ttk.Button(self, text="Log Viewer", command=self.open_log_viewer).pack(pady=10)
        ttk.Button(self, text="Trabajo con API", command=self.open_api_work).pack(pady=10)
        ttk.Button(self, text="Análisis de PC", command=self.open_pc_analysis).pack(pady=10)
        ttk.Button(self, text="Networking", command=self.open_networking).pack(pady=10)

    def open_ip_calculator(self):
        IP_Calculator(self)

    def open_log_viewer(self):
        Log_Viewer(self)

    def open_api_work(self):
        API_Work(self)

    def open_pc_analysis(self):
        PC_Analysis(self)

    def open_networking(self):
        Networking(self)

class IP_Calculator(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Calculadora IP")
class IP_Calculator(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Calculadora IP")
        self.geometry("600x300")

        # Widgets para ingresar la dirección IP y máscara de subred
        self.ip_label = ttk.Label(self, text="Dirección IP:")
        self.ip_label.pack(pady=5)
        self.ip_entry = ttk.Entry(self)
        self.ip_entry.pack(pady=5)

        self.mask_label = ttk.Label(self, text="Máscara de Subred:")
        self.mask_label.pack(pady=5)
        self.mask_entry = ttk.Entry(self)
        self.mask_entry.pack(pady=5)

        self.calculate_button = ttk.Button(self, text="Calcular", command=self.calculate_subnet)
        self.calculate_button.pack(pady=20)

        self.result_text = tk.Text(self, height=10, width=50)
        self.result_text.pack(pady=10)

    def calculate_subnet(self):
        ip = self.ip_entry.get()
        mask = self.mask_entry.get()
        # Aquí iría la lógica de cálculo de subneteo
        # Ejemplo de resultado
        result = f"""
        Dirección IP: {ip}
        Máscara de Subred: {mask}
        Dirección de Red: 192.168.1.0
        Dirección de Broadcast: 192.168.1.255
        Primera Dirección IP Utilizable: 192.168.1.1
        Última Dirección IP Utilizable: 192.168.1.254
        Número de Hosts: 256 (254 utilizables)
        Máscara Wildcard: 0.0.0.255
        Representación Binaria de la IP: 11000000.10101000.00000001.00000001
        Representación Binaria de la Máscara de Subred: 11111111.11111111.11111111.00000000
        Clase de Red: Clase C
        """
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)


class Log_Viewer(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Log Viewer")
class Log_Viewer(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Log Viewer")
        self.geometry("600x400")

        self.load_button = ttk.Button(self, text="Cargar Log", command=self.load_log)
        self.load_button.pack(pady=10)

        self.filter_frame = ttk.LabelFrame(self, text="Filtros")
        self.filter_frame.pack(pady=10, fill="x", expand="yes")

        self.date_label = ttk.Label(self.filter_frame, text="Fecha:")
        self.date_label.grid(row=0, column=0, padx=5, pady=5)
        self.date_entry = ttk.Entry(self.filter_frame)
        self.date_entry.grid(row=0, column=1, padx=5, pady=5)

        self.severity_label = ttk.Label(self.filter_frame, text="Severidad:")
        self.severity_label.grid(row=0, column=2, padx=5, pady=5)
        self.severity_entry = ttk.Entry(self.filter_frame)
        self.severity_entry.grid(row=0, column=3, padx=5, pady=5)

        self.source_label = ttk.Label(self.filter_frame, text="Origen:")
        self.source_label.grid(row=0, column=4, padx=5, pady=5)
        self.source_entry = ttk.Entry(self.filter_frame)
        self.source_entry.grid(row=0, column=5, padx=5, pady=5)

        self.filter_button = ttk.Button(self.filter_frame, text="Filtrar", command=self.filter_logs)
        self.filter_button.grid(row=1, column=0, columnspan=6, pady=10)

        self.log_text = tk.Text(self, height=15, width=70)
        self.log_text.pack(pady=10)

    def load_log(self):
        # Lógica para cargar el archivo de log
        pass

    def filter_logs(self):
        # Lógica para filtrar logs
        pass

class API_Work(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Trabajo con API")
class API_Work(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Trabajo con API")
        self.geometry("600x400")

        self.query_button = ttk.Button(self, text="Realizar Consulta", command=self.query_api)
        self.query_button.pack(pady=10)

        self.result_text = tk.Text(self, height=15, width=70)
        self.result_text.pack(pady=10)

    def query_api(self):
        # Lógica para realizar consulta a la API y almacenar en SQLite
        pass

class PC_Analysis(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Análisis de PC")
import psutil
import time
from threading import Thread

class PC_Analysis(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Análisis de PC")
        self.geometry("600x400")

        self.start_button = ttk.Button(self, text="Iniciar Captura", command=self.start_capture)
        self.start_button.pack(pady=10)
        self.stop_button = ttk.Button(self, text="Detener Captura", command=self.stop_capture)
        self.stop_button.pack(pady=10)
        self.stop_button.config(state=tk.DISABLED)

        self.result_text = tk.Text(self, height=15, width=70)
        self.result_text.pack(pady=10)

        self.capturing = False

    def start_capture(self):
        self.capturing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.capture_thread = Thread(target=self.capture_data)
        self.capture_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.capture_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def capture_data(self):
        while self.capturing:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            cpu_usage = psutil.cpu_percent()
            memory_info = psutil.virtual_memory()
            memory_usage = memory_info.percent
            disk_usage = psutil.disk_usage('/').percent
            temperature = self.get_cpu_temperature()

            data = (timestamp, cpu_usage, memory_usage, disk_usage, temperature)
            self.save_to_db(data)

            result = f"Timestamp: {timestamp}\nCPU Usage: {cpu_usage}%\nMemory Usage: {memory_usage}%\nDisk Usage: {disk_usage}%\nTemperature: {temperature}°C\n"
            self.result_text.insert(tk.END, result + "\n")

            time.sleep(5)

    def get_cpu_temperature(self):
        # Lógica para obtener la temperatura de la CPU (puede variar según el sistema operativo)
        return 0.0

    def save_to_db(self, data):
        cursor = self.master.conn.cursor()
        cursor.execute('''INSERT INTO pc_analysis (timestamp, cpu_usage, memory_usage, disk_usage, temperature)
                          VALUES (?, ?, ?, ?, ?)''', data)
        self.master.conn.commit()


class Networking(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Networking")
        self.geometry("600x400")

        self.ping_button = ttk.Button(self, text="Ping", command=self.ping)
        self.ping_button.pack(pady=10)
        self.scan_button = ttk.Button(self, text="Escaneo de Red", command=self.network_scan)
        self.scan_button.pack(pady=10)
        self.arp_button = ttk.Button(self, text="ARP Request", command=self.arp_request)
        self.arp_button.pack(pady=10)

        self.result_text = tk.Text(self, height=15, width=70)
        self.result_text.pack(pady=10)

    def ping(self):
        self.result_text.insert(tk.END, "Realizando ping...\n")
        result = sr1(IP(dst="8.8.8.8")/ICMP(), timeout=2, verbose=0)
        if result:
            self.result_text.insert(tk.END, f"Respuesta de {result.src}: {result.summary()}\n")
        else:
            self.result_text.insert(tk.END, "No hay respuesta.\n")

    def network_scan(self):
        self.result_text.insert(tk.END, "Realizando escaneo de red...\n")
        result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2, verbose=0)[0]
        for sent, received in result:
            self.result_text.insert(tk.END, f"{received.psrc} - {received.hwsrc}\n")

    def arp_request(self):
        self.result_text.insert(tk.END, "Realizando solicitud ARP...\n")
        result = sr1(ARP(pdst="192.168.1.1"), timeout=2, verbose=0)
        if result:
            self.result_text.insert(tk.END, f"Respuesta de {result.psrc} - {result.hwsrc}\n")
        else:
            self.result_text.insert(tk.END, "No hay respuesta.\n")
if __name__ == "__main__":
    app = Application()
    app.mainloop()
