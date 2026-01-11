#!/usr/bin/env python3
import sys
import os
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from unittest.mock import MagicMock
from datetime import datetime

# ================= MOCK RPi.GPIO =================
if 'RPi' not in sys.modules:
    mock_gpio = MagicMock()
    mock_gpio.BCM = 'BCM'
    mock_gpio.OUT = 'OUT'
    mock_gpio.LOW = 'LOW'
    mock_gpio.HIGH = 'HIGH'
    sys.modules['RPi'] = MagicMock()
    sys.modules['RPi.GPIO'] = mock_gpio

# Import the existing script logic
try:
    import nwscan
except ImportError as e:
    messagebox.showerror("Import Error", f"Failed to import nwscan module: {e}")
    sys.exit(1)

# ================= GUI APP =================

class NWScanGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("NWSCAN Monitor")
        self.geometry("480x800")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.fonts = {
            'default': ('Helvetica', 12),
            'header': ('Helvetica', 14, 'bold'),
            'status': ('Helvetica', 16, 'bold'),
            'mono': ('Consolas', 10),
            'small': ('Helvetica', 10)
        }
        
        self.style.configure('.', font=self.fonts['default'])
        self.style.configure('TButton', padding=10, font=self.fonts['default'])
        self.style.configure('Header.TLabel', font=self.fonts['header'])
        self.style.configure('Status.TLabel', font=self.fonts['status'])
        
        self.monitor = None
        self.monitor_thread = None
        self.monitoring_active = False
        
        self.create_widgets()
        self.after(500, self.start_monitor)

    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- Header ---
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_indicator = tk.Label(
            header_frame, text="INIT", bg="gray", fg="white", 
            font=self.fonts['status'], width=8
        )
        self.status_indicator.pack(side=tk.LEFT, padx=5)
        
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.ip_label = ttk.Label(info_frame, text="IP: Checking...", style='Header.TLabel')
        self.ip_label.pack(anchor="w")
        
        self.ext_ip_label = ttk.Label(info_frame, text="Ext IP: ...", font=self.fonts['small'], foreground="gray")
        self.ext_ip_label.pack(anchor="w")
        
        # --- Notebook ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.tab_status = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_status, text="  Status  ")
        self.create_status_tab(self.tab_status)
        
        self.tab_neighbors = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_neighbors, text=" Neighbors ")
        self.create_neighbors_tab(self.tab_neighbors)
        
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text=" Settings ")
        self.create_settings_tab(self.tab_settings)
        
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text=" Logs ")
        self.create_logs_tab(self.tab_logs)

        # --- Footer ---
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(5, 0))
        self.last_update_label = ttk.Label(footer_frame, text="Last Update: Never", font=self.fonts['small'])
        self.last_update_label.pack(side=tk.RIGHT)

    def create_status_tab(self, parent):
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)
        
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Internet & Gateway
        self.internet_frame = ttk.LabelFrame(scroll_frame, text="Connectivity")
        self.internet_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.internet_status_label = ttk.Label(self.internet_frame, text="Internet: Unknown")
        self.internet_status_label.pack(anchor="w", padx=5, pady=2)
        
        self.gateway_label = ttk.Label(self.internet_frame, text="Gateway: Unknown")
        self.gateway_label.pack(anchor="w", padx=5, pady=2)
        
        self.downtime_label = ttk.Label(self.internet_frame, text="", foreground="red")
        self.downtime_label.pack(anchor="w", padx=5, pady=2)
        
        # Interfaces
        ttk.Label(scroll_frame, text="Active Interfaces:", style='Header.TLabel').pack(anchor="w", padx=10, pady=(10,0))
        self.interfaces_text = tk.Text(scroll_frame, height=10, width=40, font=self.fonts['mono'], bg="#f0f0f0", relief="flat")
        self.interfaces_text.pack(fill=tk.X, padx=5, pady=5)
        
        # DNS
        ttk.Label(scroll_frame, text="DNS Servers:", style='Header.TLabel').pack(anchor="w", padx=10, pady=(10,0))
        self.dns_text = tk.Text(scroll_frame, height=5, width=40, font=self.fonts['mono'], bg="#f0f0f0", relief="flat")
        self.dns_text.pack(fill=tk.X, padx=5, pady=5)

    def create_neighbors_tab(self, parent):
        self.neighbors_text = scrolledtext.ScrolledText(parent, font=self.fonts['mono'])
        self.neighbors_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_settings_tab(self, parent):
        control_frame = ttk.LabelFrame(parent, text="Service Control")
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.btn_start = ttk.Button(control_frame, text="Start Service", command=self.start_monitor)
        self.btn_start.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=10)
        
        self.btn_stop = ttk.Button(control_frame, text="Stop Service", command=self.stop_monitor)
        self.btn_stop.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=10)
        
        settings_frame = ttk.LabelFrame(parent, text="Configuration")
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.var_lldp = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable LLDP/CDP Discovery", variable=self.var_lldp, command=self.update_settings).pack(anchor="w", padx=10, pady=10)
        
        self.var_telegram = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable Telegram Notifications", variable=self.var_telegram, command=self.update_settings).pack(anchor="w", padx=10, pady=10)
        
        ttk.Separator(settings_frame, orient='horizontal').pack(fill='x', padx=5, pady=10)
        
        self.var_debug = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Enable Debug Logging", variable=self.var_debug, command=self.update_settings).pack(anchor="w", padx=10, pady=10)
        
        self.var_debug_lldp = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Debug LLDP Details", variable=self.var_debug_lldp, command=self.update_settings).pack(anchor="w", padx=20, pady=5)

    def create_logs_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(parent, font=self.fonts['mono'], state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(parent, text="Clear Logs", command=lambda: self.log_text.delete(1.0, tk.END)).pack(fill=tk.X, padx=5, pady=5)
        self.redirect_logging()

    def redirect_logging(self):
        class TextRedirector(object):
            def __init__(self, widget, tag="stdout"):
                self.widget = widget
                self.tag = tag
            def write(self, str):
                try:
                    self.widget.configure(state="normal")
                    self.widget.insert("end", str, (self.tag,))
                    self.widget.see("end")
                    self.widget.configure(state="disabled")
                except: pass
            def flush(self): pass

        sys.stdout = TextRedirector(self.log_text, "stdout")
        sys.stderr = TextRedirector(self.log_text, "stderr")

    def start_monitor(self):
        if self.monitoring_active: return
        try:
            self.monitor = GUINetworkMonitor(self)
            self.monitor.running = True
            self.update_settings()
            self.monitor_thread = threading.Thread(target=self.monitor.monitoring_thread)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.monitoring_active = True
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Service started.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start: {e}")

    def stop_monitor(self):
        if not self.monitoring_active or not self.monitor: return
        self.monitor.running = False
        self.monitoring_active = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status_indicator.config(text="STOPPED", bg="gray")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Service stopping...")

    def update_settings(self):
        if self.monitor:
            self.monitor.lldp_enabled = self.var_lldp.get()
            self.monitor.cdp_enabled = self.var_lldp.get()
            self.monitor.telegram_enabled = self.var_telegram.get()
            self.monitor.debug_enabled = self.var_debug.get()
            self.monitor.debug_lldp = self.var_debug_lldp.get()
            nwscan.DEBUG_ENABLED = self.var_debug.get()
            print("Settings updated.")

    def format_bytes(self, size):
        power = 2**10
        n = 0
        power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
        while size > power:
            size /= power
            n += 1
        return f"{size:.1f} {power_labels.get(n, '')}B"

    def update_gui(self, state):
        # 1. Header
        ip = state.get('ip')
        has_internet = state.get('has_internet')
        ext_ip = state.get('external_ip')
        
        if has_internet:
            self.status_indicator.config(text="ONLINE", bg="#4CAF50")
        elif ip:
            self.status_indicator.config(text="OFFLINE", bg="#FF9800")
        else:
            self.status_indicator.config(text="NO IP", bg="#F44336")
            
        self.ip_label.config(text=f"IP: {ip if ip else 'None'}")
        self.ext_ip_label.config(text=f"Ext IP: {ext_ip if ext_ip else 'N/A'}")
        
        # 2. Status Tab
        self.internet_status_label.config(text=f"Internet: {'Available' if has_internet else 'Unavailable'}")
        
        gateway = state.get('gateway')
        if gateway:
            gw_status = "OK" if gateway.get('available') else "Unreachable"
            self.gateway_label.config(text=f"Gateway: {gateway.get('address')} ({gw_status})")
        else:
            self.gateway_label.config(text="Gateway: None")
            
        # Downtime
        if self.monitor.downtime_start and not has_internet:
            duration = (datetime.now() - self.monitor.downtime_start).total_seconds()
            self.downtime_label.config(text=f"Downtime: {self.monitor.format_duration(duration)}")
        else:
            self.downtime_label.config(text="")
        
        # Interfaces
        self.interfaces_text.config(state="normal")
        self.interfaces_text.delete(1.0, tk.END)
        active_ifaces = state.get('active_interfaces', [])
        if active_ifaces:
            for iface in active_ifaces:
                if isinstance(iface, dict):
                    name = iface.get('name', 'N/A')
                    mac = iface.get('mac', 'N/A')
                    ips = ", ".join([ip.get('ip', '') for ip in iface.get('ip_addresses', [])])
                    rx = self.format_bytes(iface.get('rx_bytes', 0))
                    tx = self.format_bytes(iface.get('tx_bytes', 0))
                    
                    self.interfaces_text.insert(tk.END, f"• {name} ({mac})\n")
                    self.interfaces_text.insert(tk.END, f"  IP: {ips}\n")
                    self.interfaces_text.insert(tk.END, f"  Traffic: ↓{rx} / ↑{tx}\n\n")
        else:
            self.interfaces_text.insert(tk.END, "No active interfaces")
        self.interfaces_text.config(state="disabled")
        
        # DNS
        self.dns_text.config(state="normal")
        self.dns_text.delete(1.0, tk.END)
        dns_status = state.get('dns_status', [])
        if dns_status:
            for dns in dns_status:
                 if isinstance(dns, dict):
                     server = dns.get('server')
                     working = dns.get('working')
                     resp_time = dns.get('response_time')
                     status_txt = "OK" if working else "FAIL"
                     time_txt = f" ({resp_time*1000:.0f}ms)" if resp_time else ""
                     self.dns_text.insert(tk.END, f"• {server}: {status_txt}{time_txt}\n")
        else:
            self.dns_text.insert(tk.END, "No DNS servers found")
        self.dns_text.config(state="disabled")
        
        # 3. Neighbors
        self.neighbors_text.config(state="normal")
        self.neighbors_text.delete(1.0, tk.END)
        neighbors = state.get('neighbors', [])
        
        if neighbors:
            for n in neighbors:
                self.neighbors_text.insert(tk.END, f"INTERFACE: {n.get('interface', 'Unknown')}\n", 'bold')
                
                chassis = n.get('chassis_name') or n.get('chassis_id') or 'Unknown'
                self.neighbors_text.insert(tk.END, f"Device: {chassis}\n")
                
                if n.get('management_ip'):
                    self.neighbors_text.insert(tk.END, f"Mgmt IP: {n.get('management_ip')}\n")
                
                if n.get('port_id'):
                    self.neighbors_text.insert(tk.END, f"Port: {n.get('port_id')}\n")
                    
                if n.get('system_description'):
                    desc = n.get('system_description', '')
                    self.neighbors_text.insert(tk.END, f"Desc: {desc}\n")
                
                if n.get('capabilities'):
                    caps = ", ".join(n.get('capabilities', []))
                    self.neighbors_text.insert(tk.END, f"Caps: {caps}\n")
                    
                self.neighbors_text.insert(tk.END, "-"*40 + "\n\n")
        else:
            self.neighbors_text.insert(tk.END, "\nNo neighbors detected.\n")
            
        self.neighbors_text.config(state="disabled")
        
        # 4. Footer
        self.last_update_label.config(text=f"Last Update: {state.get('timestamp')}")

class GUINetworkMonitor(nwscan.NetworkMonitor):
    def __init__(self, gui_app):
        super().__init__()
        self.gui_app = gui_app
        
    def display_network_info(self, state):
        self.gui_app.after(0, self.gui_app.update_gui, state)
        self.last_display_state = state.copy()
        if self.telegram_enabled and self.telegram_initialized:
            try:
                self.send_telegram_notification(state)
            except Exception as e:
                print(f"Telegram error: {e}")

if __name__ == "__main__":
    app = NWScanGUI()
    app.mainloop()
