import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog, font
import requests
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import ipaddress
import psutil
import platform
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
from netaddr import IPNetwork
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
        number_of_hosts = network.num_addresses - 2  
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

def filtrar_logs(logs, criterio):
    logs_filtrados = [log for log in logs if criterio in log]
    return logs_filtrados

def mostrar_logs(logs):
    text_area.delete('1.0', tk.END)
    for log in logs:
        text_area.insert(tk.END, log)

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
        self.title("Aplicación Multiventana")
        self.geometry("800x600")
        
        fuente_titulo = font.Font(family='Times New Roman', size=14, weight='bold')
        fuente_texto = font.Font(family='Times New Roman', size=12)
        
        main_frame = tk.Frame(self)
        main_frame.pack(pady=20)

        self.create_menu(main_frame, fuente_texto)
        self.create_subnet_calc_button(main_frame, fuente_texto)
        self.create_log_reader_button(main_frame, fuente_texto)
        self.create_api_button(main_frame, fuente_texto)
        self.create_system_analysis_buttons(main_frame, fuente_texto)
        self.create_scapy_button(main_frame, fuente_texto)

    def create_menu(self, frame, font):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Abrir", command=self.open_file)
        file_menu.add_command(label="Guardar", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.quit)

        menu_bar.add_cascade(label="Archivo", menu=file_menu)

    def create_subnet_calc_button(self, frame, font):
        subnet_button = tk.Button(frame, text="Calculadora de Subneteo", command=self.open_subnet_window, font=font)
        subnet_button.pack(pady=5)

    def create_log_reader_button(self, frame, font):
        log_button = tk.Button(frame, text="Lectura de Log", command=self.open_log_window, font=font)
        log_button.pack(pady=5)

    def create_api_button(self, frame, font):
        api_button = tk.Button(frame, text="API", command=self.open_api_window, font=font)
        api_button.pack(pady=5)

    def create_system_analysis_buttons(self, frame, font):
        system_button_frame = tk.Frame(frame)
        system_button_frame.pack(pady=10)

        os_button = tk.Button(system_button_frame, text="Ver Info del SO", command=self.show_os_info, font=font)
        os_button.pack(side=tk.LEFT, padx=5)

        usage_button = tk.Button(system_button_frame, text="Ver Uso del Sistema", command=self.show_system_usage, font=font)
        usage_button.pack(side=tk.LEFT, padx=5)

    def create_scapy_button(self, frame, font):
        scapy_button = tk.Button(frame, text="Funcionalidades de Scapy", command=self.open_scapy_window, font=font)
        scapy_button.pack(pady=5)

    def open_subnet_window(self):
        subnet_window = tk.Toplevel(self)
        subnet_window.title("Calculadora de Subneteo")
        subnet_window.geometry("800x600")
        
        tk.Label(subnet_window, text="IP Address:").pack(pady=5)
        ip_entry = tk.Entry(subnet_window)
        ip_entry.pack(pady=5)
        
        tk.Label(subnet_window, text="Subnet Mask:").pack(pady=5)
        subnet_mask_entry = tk.Entry(subnet_window)
        subnet_mask_entry.pack(pady=5)
        
        def calculate_and_save():
            ip = ip_entry.get()
            subnet_mask = subnet_mask_entry.get()
            network_address, number_of_hosts, number_of_subnets = calculate_subnet(ip, subnet_mask)
            if network_address:
                save_subnet_data(ip, subnet_mask, network_address, number_of_hosts, number_of_subnets)
                messagebox.showinfo("Success", "Subnet data saved successfully!")
        
        calculate_button = tk.Button(subnet_window, text="Calculate and Save", command=calculate_and_save)
        calculate_button.pack(pady=20)
        
    def open_log_window(self):
        log_window = tk.Toplevel(self)
        log_window.title("Lectura de Log")
        log_window.geometry("800x600")
        
        global text_area
        text_area = tk.Text(log_window)
        text_area.pack(expand=True, fill=tk.BOTH)
        
        log_controls_frame = tk.Frame(log_window)
        log_controls_frame.pack(pady=10)
        
        tk.Button(log_controls_frame, text="Leer Archivo", command=leer_archivo).pack(side=tk.LEFT, padx=5)
        tk.Button(log_controls_frame, text="Filtrar", command=filtrar_archivo).pack(side=tk.LEFT, padx=5)
        tk.Button(log_controls_frame, text="Mostrar Estadísticas", command=mostrar_estadisticas).pack(side=tk.LEFT, padx=5)
        
        global criterio_entry
        criterio_entry = tk.Entry(log_controls_frame)
        criterio_entry.pack(side=tk.LEFT, padx=5)
    
    def open_api_window(self):
        api_window = tk.Toplevel(self)
        api_window.title("API")
        api_window.geometry("800x600")
        
        api_controls_frame = tk.Frame(api_window)
        api_controls_frame.pack(pady=10)
        
        tk.Label(api_controls_frame, text="ID:").pack(side=tk.LEFT, padx=5)
        id_entry = tk.Entry(api_controls_frame)
        id_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(api_controls_frame, text="Name:").pack(side=tk.LEFT, padx=5)
        name_entry = tk.Entry(api_controls_frame)
        name_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(api_controls_frame, text="Value:").pack(side=tk.LEFT, padx=5)
        value_entry = tk.Entry(api_controls_frame)
        value_entry.pack(side=tk.LEFT, padx=5)
        
        def insert_data():
            name = name_entry.get()
            value = value_entry.get()
            insert_api_data(name, value)
            messagebox.showinfo("Info", "Data inserted successfully!")
        
        def update_data():
            id_ = id_entry.get()
            name = name_entry.get()
            value = value_entry.get()
            update_api_data(id_, name, value)
            messagebox.showinfo("Info", "Data updated successfully!")
        
        def delete_data():
            id_ = id_entry.get()
            delete_api_data(id_)
            messagebox.showinfo("Info", "Data deleted successfully!")
        
        def fetch_and_show_data():
            data = get_all_api_data()
            text_area_api.delete('1.0', tk.END)
            for row in data:
                text_area_api.insert(tk.END, f"{row}\n")
        
        tk.Button(api_controls_frame, text="Insertar", command=insert_data).pack(side=tk.LEFT, padx=5)
        tk.Button(api_controls_frame, text="Actualizar", command=update_data).pack(side=tk.LEFT, padx=5)
        tk.Button(api_controls_frame, text="Borrar", command=delete_data).pack(side=tk.LEFT, padx=5)
        tk.Button(api_controls_frame, text="Ver Datos", command=fetch_and_show_data).pack(side=tk.LEFT, padx=5)
        
        global text_area_api
        text_area_api = tk.Text(api_window)
        text_area_api.pack(expand=True, fill=tk.BOTH)
    
    def show_os_info(self):
        os_info = platform.system() + " " + platform.release()
        messagebox.showinfo("Información del Sistema Operativo", os_info)
    
    def show_system_usage(self):
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent
        usage_info = f"Uso de CPU: {cpu_usage}%\nUso de Memoria: {memory_usage}%\nUso de Disco: {disk_usage}%"
        messagebox.showinfo("Uso del Sistema", usage_info)
    
    def open_scapy_window(self):
        scapy_window = tk.Toplevel(self)
        scapy_window.title("Funcionalidades de Scapy")
        scapy_window.geometry("800x600")
        ping_button = tk.Button(scapy_window, text="Enviar Ping", command=self.send_ping)
        ping_button.pack(pady=10)

        scan_button = tk.Button(scapy_window, text="Escanear Red", command=self.scan_network)
        scan_button.pack(pady=10)

        capture_button = tk.Button(scapy_window, text="Capturar Paquetes", command=self.capture_packets)
        capture_button.pack(pady=10)
        
        tk.Label(scapy_window, text="IP Address:").pack(pady=5)
        ip_entry = tk.Entry(scapy_window)
        ip_entry.pack(pady=5)
        
        def arp_scan():
            ip = ip_entry.get()
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            devices = []
            for element in answered_list:
                device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                devices.append(device_info)
            text_area_scapy.delete('1.0', tk.END)
            for device in devices:
                text_area_scapy.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")
        
        def icmp_ping():
            ip = ip_entry.get()
            icmp_request = IP(dst=ip)/ICMP()
            response = sr1(icmp_request, timeout=1, verbose=False)
            if response:
                text_area_scapy.insert(tk.END, f"{ip} is reachable\n")
            else:
                text_area_scapy.insert(tk.END, f"{ip} is not reachable\n")
        
        scapy_controls_frame = tk.Frame(scapy_window)
        scapy_controls_frame.pack(pady=10)
        
        tk.Button(scapy_controls_frame, text="ARP Scan", command=arp_scan).pack(side=tk.LEFT, padx=5)
        tk.Button(scapy_controls_frame, text="ICMP Ping", command=icmp_ping).pack(side=tk.LEFT, padx=5)
        
        global text_area_scapy
        text_area_scapy = tk.Text(scapy_window)
        text_area_scapy.pack(expand=True, fill=tk.BOTH)
    def send_ping(self):
        target_ip = simpledialog.askstring("Enviar Ping", "Introduce la dirección IP de destino:")
        if target_ip:
            packet = IP(dst=target_ip)/ICMP()
            response = sr1(packet, timeout=2, verbose=0)
            if response:
                messagebox.showinfo("Ping", f"Respuesta recibida de {target_ip}")
            else:
                messagebox.showinfo("Ping", f"No se recibió respuesta de {target_ip}")

    def scan_network(self):
        network_range = simpledialog.askstring("Escanear Red", "Introduce el rango de red (e.g., 192.168.1.0/24):")
        if network_range:
            network = IPNetwork(network_range)
            live_hosts = []
            for ip in network:
                packet = IP(dst=str(ip))/ICMP()
                response = sr1(packet, timeout=1, verbose=0)
                if response:
                    live_hosts.append(str(ip))
            if live_hosts:
                messagebox.showinfo("Escanear Red", f"Hosts activos:\n{', '.join(live_hosts)}")
            else:
                messagebox.showinfo("Escanear Red", "No se encontraron hosts activos en el rango especificado.")

    def capture_packets(self):
        num_packets = simpledialog.askinteger("Capturar Paquetes", "Introduce el número de paquetes a capturar:")
        if num_packets:
            captured_packets = sniff(count=num_packets)
            packet_summary = "\n".join([pkt.summary() for pkt in captured_packets])
            messagebox.showinfo("Capturar Paquetes", f"Paquetes capturados:\n{packet_summary}")
    def open_file(self):
        filename = filedialog.askopenfilename(title="Seleccionar archivo", filetypes=[("Archivos de texto", "*.txt")])
        if filename:
            with open(filename, 'r') as file:
                content = file.read()
            text_area.delete('1.0', tk.END)
            text_area.insert(tk.END, content)
    
    def save_file(self):
        filename = filedialog.asksaveasfilename(title="Guardar archivo", defaultextension=".txt", filetypes=[("Archivos de texto", "*.txt")])
        if filename:
            content = text_area.get('1.0', tk.END)
            with open(filename, 'w') as file:
                file.write(content)

if __name__ == "__main__":
    create_database()
    app = Application()
    app.mainloop()