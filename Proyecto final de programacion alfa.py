import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog, font
import requests
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import ipaddress
import psutil
from scapy.all import *

def create_database():
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS windows (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        window_name TEXT NOT NULL,
                        content TEXT NOT NULL)''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS api_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        value TEXT NOT NULL)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS subnets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL,
                        subnet_mask TEXT NOT NULL,
                        network_address TEXT NOT NULL,
                        number_of_hosts INTEGER NOT NULL,
                        number_of_subnets INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

def fetch_api_data():
    response = requests.get("https://pokeapi.co/api/v2/pokemon/pikachu")
    return response.json()

def insert_api_data(name, value):
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO api_data (name, value) VALUES (?, ?)", (name, value))
    conn.commit()
    conn.close()

def update_api_data(id, name, value):
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE api_data SET name = ?, value = ? WHERE id = ?", (name, value, id))
    conn.commit()
    conn.close()

def delete_api_data(id):
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM api_data WHERE id = ?", (id,))
    conn.commit()
    conn.close()

def get_all_api_data():
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM api_data")
    rows = cursor.fetchall()
    conn.close()
    return rows

def save_subnet_data(ip, subnet_mask, network_address, number_of_hosts, number_of_subnets):
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO subnets (ip, subnet_mask, network_address, number_of_hosts, number_of_subnets) VALUES (?, ?, ?, ?, ?)",
                   (ip, subnet_mask, network_address, number_of_hosts, number_of_subnets))
    conn.commit()
    conn.close()

def calculate_subnet(ip, subnet_mask):
    try:
        network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
        network_address = str(network.network_address)
        number_of_hosts = network.num_addresses - 2  # Exclude network and broadcast addresses
        number_of_subnets = 2**(32 - network.prefixlen)
        return network_address, number_of_hosts, number_of_subnets
    except ValueError as e:
        messagebox.showerror("Error", f"Invalid IP address or subnet mask: {e}")
        return None, None, None

def leer_log(nombre_archivo):
    try:
        with open(nombre_archivo, 'r') as archivo:
            logs = archivo.readlines()
        return logs
    except FileNotFoundError:
        messagebox.showerror("Error", "El archivo no existe. Asegúrate de que el nombre del archivo sea correcto.")
        return []
    except Exception as e:
        messagebox.showerror("Error", f"Error al leer el archivo: {e}")
        return []

def filtrar_logs(logs, criterio):
    logs_filtrados = [log for log in logs if criterio.lower() in log.lower()]
    return logs_filtrados

def mostrar_logs(logs):
    if logs:
        text_area.delete('1.0', tk.END)
        for log in logs:
            if "CRITICAL" in log:
                guardar_criticos(log)
                text_area.insert(tk.END, log, 'critical')
            elif "WARNING" in log:
                text_area.insert(tk.END, log, 'warning')
            elif "ERROR" in log:
                text_area.insert(tk.END, log, 'error')
            elif "INFO" in log:
                text_area.insert(tk.END, log, 'info')
            else:
                text_area.insert(tk.END, log)
    else:
        messagebox.showinfo("Información", "No se encontraron entradas que coincidan con el criterio.")

def guardar_criticos(log):
    with open('logs_criticos.txt', 'a') as archivo_criticos:
        archivo_criticos.write(log)

def leer_archivo():
    global logs
    nombre_archivo = filedialog.askopenfilename(title="Seleccionar archivo de log", filetypes=[("Archivos de texto", "*.txt")])
    if nombre_archivo:
        logs = leer_log(nombre_archivo)
        if logs:
            messagebox.showinfo("Información", f"Se leyeron {len(logs)} entradas del log.")
        mostrar_logs(logs)

def filtrar_archivo():
    if not logs:
        messagebox.showwarning("Advertencia", "Primero debes leer el archivo de log.")
        return
    criterio = criterio_entry.get()
    if criterio:
        logs_filtrados = filtrar_logs(logs, criterio)
        mostrar_logs(logs_filtrados)
    else:
        messagebox.showwarning("Advertencia", "Debes ingresar un criterio para filtrar.")

def mostrar_estadisticas():
    if not logs:
        messagebox.showwarning("Advertencia", "Primero debes leer el archivo de log.")
        return
    severidad_count = {
        'INFO': 0,
        'WARNING': 0,
        'ERROR': 0,
        'CRITICAL': 0
    }
    origen_count = {}

    for log in logs:
        if "INFO" in log:
            severidad_count['INFO'] += 1
        elif "WARNING" in log:
            severidad_count['WARNING'] += 1
        elif "ERROR" in log:
            severidad_count['ERROR'] += 1
        elif "CRITICAL" in log:
            severidad_count['CRITICAL'] += 1
        if '(' in log and ')' in log:
            inicio_origen = log.index('(') + 1
            fin_origen = log.index(')')
            origen = log[inicio_origen:fin_origen]
            if origen in origen_count:
                origen_count[origen] += 1
            else:
                origen_count[origen] = 1
    stats_message = "Estadísticas del archivo:\n\n"
    stats_message += "Cantidad de logs por nivel de severidad:\n"
    for severidad, count in severidad_count.items():
        stats_message += f"{severidad}: {count}\n"

    stats_message += "\nCantidad de logs por origen:\n"
    for origen, count in origen_count.items():
        stats_message += f"{origen}: {count}\n"

    messagebox.showinfo("Estadísticas", stats_message)

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aplicación con múltiples ventanas")
        self.geometry("300x200")
        
        for i in range(1, 6):
            if i == 1:
                btn = tk.Button(self, text=f"Ventana {i}", command=self.open_subnet_window)
            elif i == 2:
                btn = tk.Button(self, text=f"Ventana {i}", command=self.open_log_window)
            elif i == 3:
                btn = tk.Button(self, text=f"Ventana {i}", command=self.open_api_window)
            elif i == 4:
                btn = tk.Button(self, text=f"Ventana {i}", command=self.open_system_analysis_window)
            elif i == 5:
                btn = tk.Button(self, text=f"Ventana {i}", command=self.open_scapy_window)
            else:
                btn = tk.Button(self, text=f"Ventana {i}", command=lambda i=i: self.open_window(i))
            btn.pack(pady=5)
        
        exit_btn = tk.Button(self, text="Salir", command=self.quit)
        exit_btn.pack(pady=5)
    
    def open_window(self, window_number):
        window = tk.Toplevel(self)
        window.title(f"Ventana {window_number}")
        window.geometry("300x200")
        
        content_label = tk.Label(window, text=f"Contenido de la ventana {window_number}")
        content_label.pack(pady=10)
        
        save_btn = tk.Button(window, text="Guardar contenido", command=lambda: self.save_content(window_number, content_label.cget("text")))
        save_btn.pack(pady=5)

    def open_subnet_window(self):
        window = tk.Toplevel(self)
        window.title("Ventana 1 - Subneteo")
        window.geometry("600x400")

        fuente_titulo = font.Font(family='Times New Roman', size=14, weight='bold')
        fuente_texto = font.Font(family='Times New Roman', size=12)

        frame = tk.Frame(window, bg='#d3e0ea')
        frame.pack(pady=10, padx=10, fill='x')

        ip_label = tk.Label(frame, text="IP:", bg='#d3e0ea', fg='black', font=fuente_titulo)
        ip_label.grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = tk.Entry(frame, font=fuente_texto)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        subnet_mask_label = tk.Label(frame, text="Máscara de Subred:", bg='#d3e0ea', fg='black', font=fuente_titulo)
        subnet_mask_label.grid(row=1, column=0, padx=5, pady=5)
        self.subnet_mask_entry = tk.Entry(frame, font=fuente_texto)
        self.subnet_mask_entry.grid(row=1, column=1, padx=5, pady=5)

        calculate_btn = tk.Button(frame, text="Calcular Subneteo", command=self.calculate_subnet, bg='#274472', fg='white', font=fuente_texto)
        calculate_btn.grid(row=2, columnspan=2, pady=10)

        self.result_label = tk.Label(window, text="", bg='#d3e0ea', fg='black', font=fuente_texto)
        self.result_label.pack(pady=10)

    def open_log_window(self):
        window = tk.Toplevel(self)
        window.title("Ventana 2 - Análisis de Logs")
        window.geometry("800x600")

        fuente_titulo = font.Font(family='Times New Roman', size=14, weight='bold')
        fuente_texto = font.Font(family='Times New Roman', size=12)

        frame = tk.Frame(window, bg='#d3e0ea')
        frame.pack(pady=10, padx=10, fill='x')

        leer_btn = tk.Button(frame, text="Leer Archivo", command=leer_archivo, bg='#274472', fg='white', font=fuente_texto)
        leer_btn.grid(row=0, column=0, padx=5, pady=5)

        criterio_label = tk.Label(frame, text="Criterio de Búsqueda:", bg='#d3e0ea', fg='black', font=fuente_titulo)
        criterio_label.grid(row=0, column=1, padx=5, pady=5)
        global criterio_entry
        criterio_entry = tk.Entry(frame, font=fuente_texto)
        criterio_entry.grid(row=0, column=2, padx=5, pady=5)

        filtrar_btn = tk.Button(frame, text="Filtrar", command=filtrar_archivo, bg='#274472', fg='white', font=fuente_texto)
        filtrar_btn.grid(row=0, column=3, padx=5, pady=5)

        estadisticas_btn = tk.Button(frame, text="Mostrar Estadísticas", command=mostrar_estadisticas, bg='#274472', fg='white', font=fuente_texto)
        estadisticas_btn.grid(row=0, column=4, padx=5, pady=5)

        global text_area
        text_area = tk.Text(window, wrap='word', font=fuente_texto)
        text_area.pack(pady=10, padx=10, fill='both', expand=True)

        text_area.tag_config('critical', background='red', foreground='white')
        text_area.tag_config('warning', background='yellow', foreground='black')
        text_area.tag_config('error', background='orange', foreground='black')
        text_area.tag_config('info', background='lightblue', foreground='black')

    def open_api_window(self):
        window = tk.Toplevel(self)
        window.title("Ventana 3 - API")
        window.geometry("600x400")

        fuente_titulo = font.Font(family='Times New Roman', size=14, weight='bold')
        fuente_texto = font.Font(family='Times New Roman', size=12)

        fetch_btn = tk.Button(window, text="Fetch API Data", command=self.fetch_data, bg='#274472', fg='white', font=fuente_texto)
        fetch_btn.pack(pady=5)

        self.data_listbox = tk.Listbox(window, font=fuente_texto)
        self.data_listbox.pack(pady=10, padx=10, fill='both', expand=True)

        add_btn = tk.Button(window, text="Add Data", command=self.add_data, bg='#274472', fg='white', font=fuente_texto)
        add_btn.pack(pady=5)

        update_btn = tk.Button(window, text="Update Data", command=self.update_data, bg='#274472', fg='white', font=fuente_texto)
        update_btn.pack(pady=5)

        delete_btn = tk.Button(window, text="Delete Data", command=self.delete_data, bg='#274472', fg='white', font=fuente_texto)
        delete_btn.pack(pady=5)

        self.load_data()

    def fetch_data(self):
        data = fetch_api_data()
        name = data['name']
        value = str(data['base_experience'])
        insert_api_data(name, value)
        self.load_data()

    def add_data(self):
        name = simpledialog.askstring("Input", "Enter name:")
        value = simpledialog.askstring("Input", "Enter value:")
        if name and value:
            insert_api_data(name, value)
            self.load_data()

    def update_data(self):
        selected_item = self.data_listbox.curselection()
        if selected_item:
            index = selected_item[0]
            data = self.data_listbox.get(index).split(': ')
            id = int(data[0])
            name = simpledialog.askstring("Input", "Enter new name:", initialvalue=data[1])
            value = simpledialog.askstring("Input", "Enter new value:", initialvalue=data[2])
            if name and value:
                update_api_data(id, name, value)
                self.load_data()

    def delete_data(self):
        selected_item = self.data_listbox.curselection()
        if selected_item:
            index = selected_item[0]
            data = self.data_listbox.get(index).split(': ')
            id = int(data[0])
            delete_api_data(id)
            self.load_data()

    def load_data(self):
        self.data_listbox.delete(0, tk.END)
        rows = get_all_api_data()
        for row in rows:
            self.data_listbox.insert(tk.END, f"{row[0]}: {row[1]}: {row[2]}")

    def open_system_analysis_window(self):
        window = tk.Toplevel(self)
        window.title("Ventana 4 - Análisis del Sistema")
        window.geometry("800x600")

        fuente_titulo = font.Font(family='Times New Roman', size=14, weight='bold')
        fuente_texto = font.Font(family='Times New Roman', size=12)

        frame = tk.Frame(window, bg='#d3e0ea')
        frame.pack(pady=10, padx=10, fill='x')

        cargar_btn = tk.Button(frame, text="Cargar Datos del Sistema", command=self.cargar_datos_sistema, bg='#274472', fg='white', font=fuente_texto)
        cargar_btn.grid(row=0, column=0, padx=5, pady=5)

        guardar_btn = tk.Button(frame, text="Guardar Datos del Sistema", command=self.guardar_datos_sistema, bg='#274472', fg='white', font=fuente_texto)
        guardar_btn.grid(row=0, column=1, padx=5, pady=5)

        graficar_btn = tk.Button(frame, text="Graficar Datos del Sistema", command=self.graficar_datos_sistema, bg='#274472', fg='white', font=fuente_texto)
        graficar_btn.grid(row=0, column=2, padx=5, pady=5)

        self.text_area = tk.Text(window, wrap='word', font=fuente_texto)
        self.text_area.pack(pady=10, padx=10, fill='both', expand=True)

    def cargar_datos_sistema(self):
        data = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'virtual_memory': psutil.virtual_memory()._asdict(),
            'swap_memory': psutil.swap_memory()._asdict(),
            'disk_usage': psutil.disk_usage('/')._asdict(),
            'disk_io_counters': psutil.disk_io_counters()._asdict(),
            'net_io_counters': psutil.net_io_counters()._asdict()
        }
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert(tk.END, f"{data}\n")

    def guardar_datos_sistema(self):
        data = self.text_area.get('1.0', tk.END)
        with open('system_data.txt', 'w') as file:
            file.write(data)
        messagebox.showinfo("Información", "Datos del sistema guardados en system_data.txt")

    def graficar_datos_sistema(self):
        data = eval(self.text_area.get('1.0', tk.END))
        if data:
            df = pd.DataFrame(data)
            df.plot(subplots=True, figsize=(10, 8))
            plt.show()

    def open_scapy_window(self):
        window = tk.Toplevel(self)
        window.title("Ventana 5 - Scapy")
        window.geometry("800x600")

        fuente_titulo = font.Font(family='Times New Roman', size=14, weight='bold')
        fuente_texto = font.Font(family='Times New Roman', size=12)

        tab_control = ttk.Notebook(window)

        # Tab for Packet Capture
        packet_tab = ttk.Frame(tab_control)
        tab_control.add(packet_tab, text='Captura de Paquetes')

        packet_frame = tk.Frame(packet_tab, bg='#d3e0ea')
        packet_frame.pack(pady=10, padx=10, fill='x')

        interface_label = tk.Label(packet_frame, text="Interface:", bg='#d3e0ea', fg='black', font=fuente_titulo)
        interface_label.grid(row=0, column=0, padx=5, pady=5)
        self.interface_entry = tk.Entry(packet_frame, font=fuente_texto)
        self.interface_entry.grid(row=0, column=1, padx=5, pady=5)
        self.interface_entry.insert(0, 'eth0')

        capture_btn = tk.Button(packet_frame, text="Capturar Paquetes", command=self.capture_packets, bg='#274472', fg='white', font=fuente_texto)
        capture_btn.grid(row=0, column=2, padx=5, pady=5)

        self.packet_text_area = tk.Text(packet_tab, wrap='word', font=fuente_texto)
        self.packet_text_area.pack(pady=10, padx=10, fill='both', expand=True)

        # Tab for Packet Analysis
        analysis_tab = ttk.Frame(tab_control)
        tab_control.add(analysis_tab, text='Análisis de Paquetes')

        analysis_frame = tk.Frame(analysis_tab, bg='#d3e0ea')
        analysis_frame.pack(pady=10, padx=10, fill='x')

        filter_label = tk.Label(analysis_frame, text="Filtro:", bg='#d3e0ea', fg='black', font=fuente_titulo)
        filter_label.grid(row=0, column=0, padx=5, pady=5)
        self.packet_filter_entry = tk.Entry(analysis_frame, font=fuente_texto)
        self.packet_filter_entry.grid(row=0, column=1, padx=5, pady=5)
        self.packet_filter_entry.insert(0, 'tcp')

        filter_btn = tk.Button(analysis_frame, text="Filtrar Paquetes", command=self.filter_packets, bg='#274472', fg='white', font=fuente_texto)
        filter_btn.grid(row=0, column=2, padx=5, pady=5)

        self.analysis_text_area = tk.Text(analysis_tab, wrap='word', font=fuente_texto)
        self.analysis_text_area.pack(pady=10, padx=10, fill='both', expand=True)

        # Tab for Packet Statistics
        stats_tab = ttk.Frame(tab_control)
        tab_control.add(stats_tab, text='Estadísticas de Paquetes')

        stats_frame = tk.Frame(stats_tab, bg='#d3e0ea')
        stats_frame.pack(pady=10, padx=10, fill='x')

        stats_btn = tk.Button(stats_frame, text="Mostrar Estadísticas", command=self.show_packet_stats, bg='#274472', fg='white', font=fuente_texto)
        stats_btn.grid(row=0, column=0, padx=5, pady=5)

        self.stats_text_area = tk.Text(stats_tab, wrap='word', font=fuente_texto)
        self.stats_text_area.pack(pady=10, padx=10, fill='both', expand=True)

        tab_control.pack(expand=1, fill='both')

    def capture_packets(self):
        self.packet_text_area.delete('1.0', tk.END)
        interface = self.interface_entry.get()

        def packet_callback(packet):
            self.packet_text_area.insert(tk.END, f"{packet.summary()}\n")

        sniff(iface=interface, prn=packet_callback, timeout=10)

    def filter_packets(self):
        self.analysis_text_area.delete('1.0', tk.END)
        packet_filter = self.packet_filter_entry.get()
        interface = self.interface_entry.get()

        packets = sniff(iface=interface, filter=packet_filter, timeout=10)
        for packet in packets:
            self.analysis_text_area.insert(tk.END, f"{packet.show(dump=True)}\n")

    def show_packet_stats(self):
        self.stats_text_area.delete('1.0', tk.END)
        interface = self.interface_entry.get()
        packet_filter = self.packet_filter_entry.get()

        packets = sniff(iface=interface, filter=packet_filter, timeout=10)
        protocol_counts = {}
        src_counts = {}
        dst_counts = {}

        for packet in packets:
            if packet.haslayer(IP):
                proto = packet[IP].proto
                src = packet[IP].src
                dst = packet[IP].dst

                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
                src_counts[src] = src_counts.get(src, 0) + 1
                dst_counts[dst] = dst_counts.get(dst, 0) + 1

        stats_message = "Estadísticas de Paquetes:\n\n"
        stats_message += "Protocolos:\n"
        for proto, count in protocol_counts.items():
            stats_message += f"{proto}: {count}\n"

        stats_message += "\nDirecciones IP de origen:\n"
        for src, count in src_counts.items():
            stats_message += f"{src}: {count}\n"

        stats_message += "\nDirecciones IP de destino:\n"
        for dst, count in dst_counts.items():
            stats_message += f"{dst}: {count}\n"

        self.stats_text_area.insert(tk.END, stats_message)

    def save_content(self, window_number, content):
        conn = sqlite3.connect('app_database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO windows (window_name, content) VALUES (?, ?)", (f"Ventana {window_number}", content))
        conn.commit()
        conn.close()
        messagebox.showinfo("Información", f"Contenido de la ventana {window_number} guardado en la base de datos.")

    def calculate_subnet(self):
        ip = self.ip_entry.get()
        subnet_mask = self.subnet_mask_entry.get()
        network_address, number_of_hosts, number_of_subnets = calculate_subnet(ip, subnet_mask)
        if network_address:
            result_text = f"Dirección de Red: {network_address}\nNúmero de Hosts: {number_of_hosts}\nNúmero de Subredes: {number_of_subnets}"
            self.result_label.config(text=result_text)
            save_subnet_data(ip, subnet_mask, network_address, number_of_hosts, number_of_subnets)

if __name__ == "__main__":
    create_database()
    app = Application()
    app.mainloop()