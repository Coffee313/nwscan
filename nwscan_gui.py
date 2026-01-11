import sys
import os
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from unittest.mock import MagicMock
from datetime import datetime

# ================= MOCK RPi.GPIO =================
# We mock this before importing nwscan to allow running on non-Pi devices (like Windows)
# or just to handle the dependency if the hardware isn't present.
mock_gpio = MagicMock()
mock_gpio.BCM = 'BCM'
mock_gpio.OUT = 'OUT'
mock_gpio.LOW = 'LOW'
mock_gpio.HIGH = 'HIGH'
sys.modules['RPi'] = MagicMock()
sys.modules['RPi.GPIO'] = mock_gpio

# Now we can safely import nwscan
try:
    import nwscan
except ImportError as e:
    messagebox.showerror("Import Error", f"Failed to import nwscan module: {e}")
    sys.exit(1)

# ================= GUI APP =================

class NWScanGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("NWSCAN GUI")
        self.geometry("480x800")  # Smartphone-like resolution
        
        # Configure styles for touch
        self.style = ttk.Style()
        self.style.theme_use('clam')  # 'clam' usually looks better on Linux/Pi than default
        
        # Increase font sizes for touch
        default_font = ('Helvetica', 12)
        header_font = ('Helvetica', 14, 'bold')
        status_font = ('Helvetica', 16, 'bold')
        
        self.style.configure('.', font=default_font)
        self.style.configure('TButton', padding=10, font=default_font)
        self.style.configure('Header.TLabel', font=header_font)
        self.style.configure('Status.TLabel', font=status_font)
        
        # Initialize Monitor
        self.monitor = None
        self.monitor_thread = None
        self.monitoring_active = False
        
        self.create_widgets()
        
        # Start the monitor
        self.start_monitor()

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- Header Section ---
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_indicator = tk.Label(header_frame, text="INIT", bg="gray", fg="white", font=('Helvetica', 16, 'bold'), width=10)
        self.status_indicator.pack(side=tk.LEFT, padx=5)
        
        self.ip_label = ttk.Label(header_frame, text="IP: Checking...", style='Header.TLabel')
        self.ip_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # --- Notebook (Tabs) ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Dashboard / Status
        self.tab_status = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_status, text="Status")
        self.create_status_tab(self.tab_status)
        
        # Tab 2: Neighbors (LLDP/CDP)
        self.tab_neighbors = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_neighbors, text="Neighbors")
        self.create_neighbors_tab(self.tab_neighbors)
        
        # Tab 3: Settings & Controls
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text="Settings")
        self.create_settings_tab(self.tab_settings)
        
        # Tab 4: Logs
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text="Logs")
        self.create_logs_tab(self.tab_logs)

        # --- Footer ---
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(5, 0))
        self.last_update_label = ttk.Label(footer_frame, text="Last Update: Never", font=('Helvetica', 10))
        self.last_update_label.pack(side=tk.RIGHT)

    def create_status_tab(self, parent):
        # Scrollable area
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.status_scroll_frame = ttk.Frame(canvas)
        
        self.status_scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.status_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Content
        self.internet_status_label = ttk.Label(self.status_scroll_frame, text="Internet: Unknown")
        self.internet_status_label.pack(anchor="w", padx=10, pady=5)
        
        ttk.Separator(self.status_scroll_frame, orient='horizontal').pack(fill='x', padx=5, pady=5)
        
        ttk.Label(self.status_scroll_frame, text="Active Interfaces:", style='Header.TLabel').pack(anchor="w", padx=10)
        self.interfaces_text = tk.Text(self.status_scroll_frame, height=10, width=40, font=('Consolas', 10))
        self.interfaces_text.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Separator(self.status_scroll_frame, orient='horizontal').pack(fill='x', padx=5, pady=5)
        
        ttk.Label(self.status_scroll_frame, text="DNS Servers:", style='Header.TLabel').pack(anchor="w", padx=10)
        self.dns_text = tk.Text(self.status_scroll_frame, height=4, width=40, font=('Consolas', 10))
        self.dns_text.pack(fill=tk.X, padx=10, pady=5)

    def create_neighbors_tab(self, parent):
        self.neighbors_text = scrolledtext.ScrolledText(parent, font=('Consolas', 10))
        self.neighbors_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_settings_tab(self, parent):
        # Control Buttons
        control_frame = ttk.LabelFrame(parent, text="Service Control")
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.btn_start = ttk.Button(control_frame, text="Start Service", command=self.start_monitor)
        self.btn_start.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        self.btn_stop = ttk.Button(control_frame, text="Stop Service", command=self.stop_monitor)
        self.btn_stop.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        # Toggles
        settings_frame = ttk.LabelFrame(parent, text="Configuration")
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.var_lldp = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable LLDP/CDP Discovery", variable=self.var_lldp, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        self.var_telegram = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable Telegram Notifications", variable=self.var_telegram, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        self.var_debug = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Enable Debug Logging", variable=self.var_debug, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        self.var_debug_lldp = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Debug LLDP", variable=self.var_debug_lldp, command=self.update_settings).pack(anchor="w", padx=20, pady=5)

    def create_logs_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(parent, font=('Consolas', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Redirect stdout/stderr to this widget
        self.redirect_logging()

    def redirect_logging(self):
        class TextRedirector(object):
            def __init__(self, widget, tag="stdout"):
                self.widget = widget
                self.tag = tag

            def write(self, str):
                self.widget.configure(state="normal")
                self.widget.insert("end", str, (self.tag,))
                self.widget.see("end")
                self.widget.configure(state="disabled")
            
            def flush(self):
                pass

        sys.stdout = TextRedirector(self.log_text, "stdout")
        sys.stderr = TextRedirector(self.log_text, "stderr")

    def start_monitor(self):
        if self.monitoring_active:
            return
            
        try:
            self.monitor = GUINetworkMonitor(self)
            self.monitor.running = True
            
            # Apply initial settings
            self.update_settings()
            
            self.monitor_thread = threading.Thread(target=self.monitor.monitoring_thread)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            self.monitoring_active = True
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            print("Service started.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitor: {e}")

    def stop_monitor(self):
        if not self.monitoring_active or not self.monitor:
            return
            
        self.monitor.running = False
        self.monitoring_active = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        print("Service stopping...")

    def update_settings(self):
        if self.monitor:
            self.monitor.lldp_enabled = self.var_lldp.get()
            self.monitor.cdp_enabled = self.var_lldp.get() # Link CDP to LLDP toggle for simplicity
            self.monitor.telegram_enabled = self.var_telegram.get()
            self.monitor.debug_enabled = self.var_debug.get()
            self.monitor.debug_lldp = self.var_debug_lldp.get()
            
            # Force global debug variable update in nwscan module if needed
            nwscan.DEBUG_ENABLED = self.var_debug.get()

    def update_gui(self, state):
        # Update Status Header
        ip = state.get('ip')
        has_internet = state.get('has_internet')
        
        if has_internet:
            self.status_indicator.config(text="ONLINE", bg="green")
        elif ip:
            self.status_indicator.config(text="OFFLINE", bg="orange")
        else:
            self.status_indicator.config(text="NO IP", bg="red")
            
        self.ip_label.config(text=f"IP: {ip if ip else 'None'}")
        
        # Update Status Tab
        self.internet_status_label.config(text=f"Internet: {'Available' if has_internet else 'Unavailable'}")
        
        # Interfaces
        self.interfaces_text.config(state="normal")
        self.interfaces_text.delete(1.0, tk.END)
        for iface in state.get('active_interfaces', []):
            if isinstance(iface, dict):
                name = iface.get('name', 'N/A')
                mac = iface.get('mac', 'N/A')
                ips = ", ".join([ip.get('ip', '') for ip in iface.get('ip_addresses', [])])
                self.interfaces_text.insert(tk.END, f"{name}: {ips}\nMAC: {mac}\n\n")
        self.interfaces_text.config(state="disabled")
        
        # DNS
        self.dns_text.config(state="normal")
        self.dns_text.delete(1.0, tk.END)
        for dns in state.get('dns_status', []):
             if isinstance(dns, dict):
                 server = dns.get('server')
                 working = dns.get('working')
                 status = "OK" if working else "FAIL"
                 self.dns_text.insert(tk.END, f"{server}: {status}\n")
        self.dns_text.config(state="disabled")
        
        # Neighbors
        self.neighbors_text.config(state="normal")
        self.neighbors_text.delete(1.0, tk.END)
        neighbors = state.get('neighbors', [])
        if neighbors:
            for n in neighbors:
                self.neighbors_text.insert(tk.END, f"Interface: {n.get('interface')}\n")
                self.neighbors_text.insert(tk.END, f"Name: {n.get('chassis_name')}\n")
                self.neighbors_text.insert(tk.END, f"IP: {n.get('management_ip')}\n")
                self.neighbors_text.insert(tk.END, f"Port: {n.get('port_id')}\n")
                self.neighbors_text.insert(tk.END, f"Desc: {n.get('system_description')}\n")
                self.neighbors_text.insert(tk.END, "-"*30 + "\n")
        else:
            self.neighbors_text.insert(tk.END, "No neighbors found.")
        self.neighbors_text.config(state="disabled")
        
        # Footer
        self.last_update_label.config(text=f"Last Update: {state.get('timestamp')}")

class GUINetworkMonitor(nwscan.NetworkMonitor):
    def __init__(self, gui_app):
        super().__init__()
        self.gui_app = gui_app
        
    def display_network_info(self, state):
        # Override to update GUI instead of printing
        # Use after() to schedule update on main thread
        self.gui_app.after(0, self.gui_app.update_gui, state)
        
        # Still log to console (which is redirected to log tab)
        print(f"[{state.get('timestamp')}] Network state updated")

if __name__ == "__main__":
    app = NWScanGUI()
    app.mainloop()