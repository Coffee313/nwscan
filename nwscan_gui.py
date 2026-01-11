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
try:
    import RPi.GPIO
    print("RPi.GPIO detected. Using real hardware.")
except (ImportError, RuntimeError):
    print("RPi.GPIO not found. Using mock.")
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
        self.geometry("800x480")
        
        # Force fullscreen with a slight delay to ensure window manager catches it
        self.after(100, lambda: self.attributes('-fullscreen', True))
        self.bind("<Escape>", lambda event: self.attributes("-fullscreen", False))
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.fonts = {
            'default': ('Helvetica', 12),
            'header': ('Helvetica', 14, 'bold'),
            'status': ('Helvetica', 16, 'bold'),
            'mono': ('Consolas', 10),
            'small': ('Helvetica', 10),
            'bold': ('Helvetica', 12, 'bold')
        }
        
        self.style.configure('.', font=self.fonts['default'])
        self.style.configure('TButton', padding=10, font=self.fonts['default'])
        self.style.configure('Header.TLabel', font=self.fonts['header'])
        self.style.configure('Status.TLabel', font=self.fonts['status'])
        self.style.configure('Bold.TLabel', font=self.fonts['bold'])
        
        self.monitor = None
        self.monitor_thread = None
        self.monitoring_active = False
        
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.after(500, self.start_monitor)

    def on_closing(self):
        if self.monitor:
            try:
                self.monitor.cleanup()
            except:
                pass
        self.destroy()
        sys.exit(0)

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

        # Exit Button
        btn_exit = ttk.Button(header_frame, text="X", width=3, command=self.on_closing)
        btn_exit.pack(side=tk.RIGHT, padx=5)
        
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
        # Create scrolling area
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.status_scroll_frame = ttk.Frame(canvas)
        
        self.status_scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.status_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 1. System Status
        self.system_frame = ttk.LabelFrame(self.status_scroll_frame, text="System Status")
        self.system_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        
        self.internet_status_label = ttk.Label(self.system_frame, text="Internet: Unknown")
        self.internet_status_label.pack(anchor="w", padx=5, pady=2)
        
        self.downtime_label = ttk.Label(self.system_frame, text="", foreground="red")
        self.downtime_label.pack(anchor="w", padx=5, pady=2)

        # 2. Gateway
        self.gateway_frame = ttk.LabelFrame(self.status_scroll_frame, text="Gateway")
        self.gateway_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        
        self.gateway_info_label = ttk.Label(self.gateway_frame, text="Checking...")
        self.gateway_info_label.pack(anchor="w", padx=5, pady=5)

        # 3. DNS Servers
        self.dns_frame = ttk.LabelFrame(self.status_scroll_frame, text="DNS Servers")
        self.dns_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        
        self.dns_container = ttk.Frame(self.dns_frame)
        self.dns_container.pack(fill=tk.X, padx=5, pady=5)

        # 4. Interfaces (Dynamic)
        self.interfaces_container = ttk.Frame(self.status_scroll_frame)
        self.interfaces_container.pack(fill=tk.X, padx=5, pady=5)

    def create_neighbors_tab(self, parent):
        # Create scrolling area
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.neighbors_scroll_frame = ttk.Frame(canvas)
        
        self.neighbors_scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.neighbors_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

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
        try:
            self.monitor.cleanup()
        except Exception as e:
            print(f"Error stopping monitor: {e}")
            
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

    def clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

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
        
        # 2. Status Tab - System & Gateway
        self.internet_status_label.config(text=f"Internet: {'Available' if has_internet else 'Unavailable'}")
        
        if self.monitor.downtime_start and not has_internet:
            duration = (datetime.now() - self.monitor.downtime_start).total_seconds()
            self.downtime_label.config(text=f"Downtime: {self.monitor.format_duration(duration)}")
        else:
            self.downtime_label.config(text="")

        gateway = state.get('gateway')
        if gateway:
            gw_status = "OK" if gateway.get('available') else "Unreachable"
            self.gateway_info_label.config(text=f"Address: {gateway.get('address')}\nInterface: {gateway.get('interface')}\nStatus: {gw_status}")
        else:
            self.gateway_info_label.config(text="Gateway: None")

        # 3. Status Tab - DNS
        self.clear_frame(self.dns_container)
        dns_status = state.get('dns_status', [])
        if dns_status:
            for dns in dns_status:
                if isinstance(dns, dict):
                    server = dns.get('server')
                    working = dns.get('working')
                    resp_time = dns.get('response_time')
                    
                    frame = ttk.Frame(self.dns_container)
                    frame.pack(fill=tk.X, pady=2)
                    
                    status_lbl = tk.Label(frame, text="✓" if working else "✗", fg="green" if working else "red", font=self.fonts['bold'])
                    status_lbl.pack(side=tk.LEFT)
                    
                    time_txt = f"({resp_time*1000:.0f}ms)" if resp_time else ""
                    ttk.Label(frame, text=f"{server} {time_txt}").pack(side=tk.LEFT, padx=5)
        else:
            ttk.Label(self.dns_container, text="No DNS servers configured").pack(anchor="w")

        # 4. Status Tab - Interfaces
        self.clear_frame(self.interfaces_container)
        active_ifaces = state.get('active_interfaces', [])
        
        if active_ifaces:
            ttk.Label(self.interfaces_container, text="Active Interfaces", style='Header.TLabel').pack(anchor="w", pady=(10,5))
            
            for iface in active_ifaces:
                if isinstance(iface, dict):
                    frame = ttk.LabelFrame(self.interfaces_container, text=f"{iface.get('name', 'N/A')} ({iface.get('mac', 'N/A')})")
                    frame.pack(fill=tk.X, pady=5)
                    
                    # IP details
                    for ip_info in iface.get('ip_addresses', []):
                        ip_frame = ttk.Frame(frame)
                        ip_frame.pack(fill=tk.X, padx=5, pady=2)
                        
                        ttk.Label(ip_frame, text=f"IP: {ip_info.get('cidr')}", style='Bold.TLabel').pack(anchor="w")
                        ttk.Label(ip_frame, text=f"Mask: {ip_info.get('mask')}").pack(anchor="w")
                        ttk.Label(ip_frame, text=f"Network: {ip_info.get('network')} | Bcast: {ip_info.get('broadcast')}").pack(anchor="w")
                        
                        if ip_info.get('prefix', 0) >= 24:
                            range_txt = f"Range: {ip_info.get('first_usable')} - {ip_info.get('last_usable')}"
                            hosts_txt = f"Hosts: {ip_info.get('usable_hosts')}"
                            ttk.Label(ip_frame, text=f"{range_txt} | {hosts_txt}").pack(anchor="w")
                    
                    # Traffic
                    rx = self.format_bytes(iface.get('rx_bytes', 0))
                    tx = self.format_bytes(iface.get('tx_bytes', 0))
                    ttk.Label(frame, text=f"Traffic: ↓ {rx} | ↑ {tx}", font=self.fonts['small']).pack(anchor="w", padx=5, pady=2)
        else:
            ttk.Label(self.interfaces_container, text="No active interfaces").pack(anchor="w")

        # 5. Neighbors Tab
        self.clear_frame(self.neighbors_scroll_frame)
        neighbors = state.get('neighbors', [])
        
        if neighbors:
            for n in neighbors:
                frame = ttk.LabelFrame(self.neighbors_scroll_frame, text=f"Neighbor on {n.get('interface', 'Unknown')}")
                frame.pack(fill=tk.X, padx=5, pady=5)
                
                # Basic info
                grid_frame = ttk.Frame(frame)
                grid_frame.pack(fill=tk.X, padx=5, pady=5)
                
                row = 0
                def add_row(label, value):
                    nonlocal row
                    if value:
                        ttk.Label(grid_frame, text=label + ":", font=self.fonts['bold']).grid(row=row, column=0, sticky="w", padx=2)
                        ttk.Label(grid_frame, text=str(value), wraplength=350).grid(row=row, column=1, sticky="w", padx=2)
                        row += 1
                
                add_row("Device", n.get('chassis_name') or n.get('chassis_id'))
                add_row("Port", n.get('port_id'))
                add_row("Desc", n.get('port_description'))
                add_row("Mgmt IP", n.get('management_ip'))
                add_row("System", n.get('system_description'))
                add_row("Platform", n.get('platform'))
                add_row("Caps", ", ".join(n.get('capabilities', [])) if isinstance(n.get('capabilities'), list) else n.get('capabilities'))
                add_row("Protocol", n.get('protocol'))
                
        else:
            ttk.Label(self.neighbors_scroll_frame, text="No neighbors detected").pack(padx=10, pady=10)
        
        # 6. Footer Update
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
