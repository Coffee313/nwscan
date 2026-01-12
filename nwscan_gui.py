#!/usr/bin/env python3
import sys
import os
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from unittest.mock import MagicMock
from datetime import datetime
import json
import pathlib
from queue import Queue
import ipaddress
import shutil
import socket
import subprocess

# ================= MOCK RPi.GPIO =================
try:
    import RPi.GPIO
except (ImportError, RuntimeError):
    sys.modules['RPi'] = MagicMock()
    sys.modules['RPi.GPIO'] = MagicMock()

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
        
        self.after(1000, lambda: self.attributes('-fullscreen', True))
        self.bind("<Escape>", lambda event: self.attributes("-fullscreen", False))
        
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
        
        self.config_file = pathlib.Path(__file__).parent / 'nwscan_config.json'
        self.log_queue = Queue()
        self.nmap_stop_event = threading.Event()
        self.nmap_thread = None
        
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.load_settings()
        self.process_log_queue()
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
        # Top menu removed; Nmap available as a tab
        
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
        
        self.tab_nmap = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_nmap, text=" Nmap ")
        self.create_nmap_tab(self.tab_nmap)
        
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
    def create_nmap_tab(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(frame, text="Interface").pack(anchor="w")
        self.nmap_iface_var = tk.StringVar()
        self.nmap_iface_combo = ttk.Combobox(frame, textvariable=self.nmap_iface_var, state="readonly")
        self.nmap_iface_combo.pack(fill=tk.X, padx=0, pady=5)
        ttk.Button(frame, text="Refresh Interfaces", command=self._nmap_refresh_interfaces).pack(anchor="w", pady=2)
        ttk.Label(frame, text="Target (IP/CIDR/Range)").pack(anchor="w")
        self.nmap_target_var = tk.StringVar()
        target_entry = ttk.Entry(frame, textvariable=self.nmap_target_var)
        target_entry.pack(fill=tk.X, padx=0, pady=5)
        ttk.Label(frame, text="Custom Ports (comma-separated)").pack(anchor="w")
        self.nmap_ports_var = tk.StringVar()
        ports_entry = ttk.Entry(frame, textvariable=self.nmap_ports_var)
        ports_entry.pack(fill=tk.X, padx=0, pady=5)
        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, pady=10)
        ttk.Button(btns, text="Discover Hosts", command=lambda: self._nmap_start_task(self._nmap_discover_hosts)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Quick Scan", command=lambda: self._nmap_start_task(self._nmap_quick_scan)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Custom Scan", command=lambda: self._nmap_start_task(self._nmap_custom_scan)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Stop scanning", command=self._nmap_stop_scanning).pack(side=tk.LEFT, padx=5)
        self.nmap_log = scrolledtext.ScrolledText(frame, font=self.fonts['mono'])
        self.nmap_log.pack(fill=tk.BOTH, expand=True, pady=10)
        self.after(1000, self._nmap_refresh_interfaces)
        common = [21,22,23,25,53,80,110,139,143,443,445,587,993,995,3306,5432,8080,8443]
        self.nmap_ports_var.set(",".join(str(p) for p in common))
    def open_nmap_scanner(self):
        win = tk.Toplevel(self)
        win.title("Nmap Scanner")
        win.geometry("800x480")
        frame = ttk.Frame(win)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(frame, text="Target (IP/CIDR/Range)").pack(anchor="w")
        self.nmap_target_var = tk.StringVar()
        target_entry = ttk.Entry(frame, textvariable=self.nmap_target_var)
        target_entry.pack(fill=tk.X, padx=0, pady=5)
        ttk.Label(frame, text="Custom Ports (comma-separated)").pack(anchor="w")
        self.nmap_ports_var = tk.StringVar()
        ports_entry = ttk.Entry(frame, textvariable=self.nmap_ports_var)
        ports_entry.pack(fill=tk.X, padx=0, pady=5)
        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, pady=10)
        ttk.Button(btns, text="Discover Hosts", command=lambda: threading.Thread(target=self._nmap_discover_hosts, daemon=True).start()).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Quick Scan", command=lambda: threading.Thread(target=self._nmap_quick_scan, daemon=True).start()).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Custom Scan", command=lambda: threading.Thread(target=self._nmap_custom_scan, daemon=True).start()).pack(side=tk.LEFT, padx=5)
        self.nmap_log = scrolledtext.ScrolledText(frame, font=self.fonts['mono'])
        self.nmap_log.pack(fill=tk.BOTH, expand=True, pady=10)
    def _append_nmap_log(self, text):
        self.nmap_log.insert("end", text + "\n")
        self.nmap_log.see("end")
    def _parse_targets(self):
        val = self.nmap_target_var.get().strip()
        ips = []
        try:
            if "-" in val and "/" not in val:
                try:
                    start_str, end_str = val.split("-", 1)
                    start_ip = ipaddress.ip_address(start_str.strip())
                    end_ip = ipaddress.ip_address(end_str.strip())
                    if int(end_ip) < int(start_ip):
                        start_ip, end_ip = end_ip, start_ip
                    cur = int(start_ip)
                    end = int(end_ip)
                    while cur <= end and len(ips) < 4096:
                        ips.append(str(ipaddress.ip_address(cur)))
                        cur += 1
                except:
                    pass
            elif "/" in val:
                net = ipaddress.ip_network(val, strict=False)
                for ip in net.hosts():
                    ips.append(str(ip))
            else:
                ipaddress.ip_address(val)
                ips.append(val)
        except:
            pass
        if len(ips) == 0:
            # Default to selected interface subnet
            subnet = self._nmap_get_selected_subnet()
            if subnet:
                for ip in subnet.hosts():
                    ips.append(str(ip))
            else:
                self.after(0, self._append_nmap_log, "Invalid target and no interface subnet available")
        if len(ips) > 512:
            ips = ips[:512]
            self.after(0, self._append_nmap_log, "Target range truncated to 512 hosts")
        return ips
    def _nmap_get_selected_subnet(self):
        iface_name = self.nmap_iface_var.get().strip()
        try:
            if self.monitor and self.monitor.current_state:
                for iface in self.monitor.current_state.get('interfaces', []):
                    if isinstance(iface, dict) and iface.get('name') == iface_name:
                        # Prefer first IPv4 CIDR
                        for ip_info in iface.get('ip_addresses', []):
                            cidr = ip_info.get('cidr')
                            if cidr and ':' not in cidr:
                                try:
                                    return ipaddress.ip_network(cidr, strict=False)
                                except:
                                    continue
        except:
            pass
        return None
    def _nmap_autofill_fields(self):
        subnet = self._nmap_get_selected_subnet()
        if subnet and subnet.version == 4:
            try:
                first = ipaddress.IPv4Address(int(subnet.network_address) + 1)
                last = ipaddress.IPv4Address(int(subnet.broadcast_address) - 1)
                if int(last) >= int(first):
                    self.nmap_target_var.set(f"{first}-{last}")
                else:
                    self.nmap_target_var.set(str(subnet))
            except:
                self.nmap_target_var.set(str(subnet))
    def _nmap_start_task(self, target_fn):
        try:
            self.nmap_stop_event.clear()
            t = threading.Thread(target=target_fn, daemon=True)
            t.start()
            self.nmap_thread = t
        except:
            pass
    def _nmap_stop_scanning(self):
        try:
            self.nmap_stop_event.set()
            self.after(0, self._append_nmap_log, "Scanning stopped")
        except:
            pass
    def _send_scan_summary_to_telegram(self, message):
        try:
            if self.monitor and self.monitor.telegram_enabled and self.monitor.telegram_initialized:
                self.monitor.send_telegram_message_simple(message)
        except:
            pass
    def _nmap_refresh_interfaces(self):
        names = []
        try:
            if self.monitor and self.monitor.current_state:
                for iface in self.monitor.current_state.get('interfaces', []):
                    if isinstance(iface, dict):
                        names.append(iface.get('name'))
        except:
            pass
        if not names:
            names = ['eth0', 'wlan0']
        self.nmap_iface_combo['values'] = names
        if not self.nmap_iface_var.get():
            self.nmap_iface_var.set(names[0])
        self.nmap_iface_combo.bind("<<ComboboxSelected>>", lambda e: self._nmap_autofill_fields())
        self._nmap_autofill_fields()
    def _ping_host(self, ip):
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return r.returncode == 0
        except:
            return False
    def _scan_ports(self, ip, ports):
        open_ports = []
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                res = s.connect_ex((ip, p))
                s.close()
                if res == 0:
                    open_ports.append(p)
            except:
                pass
        return open_ports
    def _nmap_discover_hosts(self):
        ips = self._parse_targets()
        if not ips:
            return
        self.after(0, self._append_nmap_log, f"Discovering hosts in {len(ips)} targets...")
        live = []
        for ip in ips:
            if self.nmap_stop_event.is_set():
                break
            if self._ping_host(ip):
                live.append(ip)
                self.after(0, self._append_nmap_log, f"{ip} is up")
        if not live:
            self.after(0, self._append_nmap_log, "No hosts reachable")
        else:
            self.after(0, self._append_nmap_log, f"Total up hosts: {len(live)}")
        summary = []
        summary.append(f"<b>NMAP DISCOVERY</b>")
        summary.append(f"Targets: {len(ips)}")
        summary.append(f"Up hosts: {len(live)}")
        if live:
            summary.append("Hosts:")
            for h in live[:50]:
                summary.append(f" • {h}")
        self._send_scan_summary_to_telegram("\n".join(summary))
    def _nmap_quick_scan(self):
        ips = self._parse_targets()
        if not ips:
            return
        common = [21,22,23,25,53,80,110,139,143,443,445,587,993,995,3306,5432,8080,8443]
        use_cli = shutil.which("nmap") is not None
        if use_cli and len(ips) == 1:
            ip = ips[0]
            ports_str = ",".join(str(p) for p in common)
            try:
                r = subprocess.run(["nmap", "-Pn", "-T4", "-p", ports_str, ip], capture_output=True, text=True, timeout=20)
                self.after(0, self._append_nmap_log, r.stdout.strip() or "nmap produced no output")
                msg = []
                msg.append(f"<b>NMAP QUICK SCAN</b>")
                msg.append(f"Target: {ip}")
                msg.append(f"Ports: {ports_str}")
                self._send_scan_summary_to_telegram("\n".join(msg))
                return
            except:
                pass
        results = []
        for ip in ips:
            if self.nmap_stop_event.is_set():
                break
            open_ports = self._scan_ports(ip, common)
            if open_ports:
                self.after(0, self._append_nmap_log, f"{ip} open: {', '.join(str(p) for p in open_ports)}")
                results.append((ip, open_ports))
            else:
                self.after(0, self._append_nmap_log, f"{ip} no common ports open")
        msg = []
        msg.append(f"<b>NMAP QUICK SCAN</b>")
        msg.append(f"Targets: {len(ips)}")
        if results:
            msg.append("Open ports:")
            for ip, ports in results[:50]:
                msg.append(f" • {ip}: {', '.join(str(p) for p in ports)}")
        else:
            msg.append("No open common ports found")
        self._send_scan_summary_to_telegram("\n".join(msg))
    def _nmap_custom_scan(self):
        ips = self._parse_targets()
        if not ips:
            return
        raw = self.nmap_ports_var.get().strip()
        try:
            ports = [int(x) for x in raw.split(",") if x.strip().isdigit()]
        except:
            ports = []
        if not ports:
            self.after(0, self._append_nmap_log, "No valid ports specified")
            return
        use_cli = shutil.which("nmap") is not None
        if use_cli and len(ips) == 1:
            ip = ips[0]
            ports_str = ",".join(str(p) for p in ports)
            try:
                r = subprocess.run(["nmap", "-Pn", "-T4", "-p", ports_str, ip], capture_output=True, text=True, timeout=20)
                self.after(0, self._append_nmap_log, r.stdout.strip() or "nmap produced no output")
                msg = []
                msg.append(f"<b>NMAP CUSTOM SCAN</b>")
                msg.append(f"Target: {ip}")
                msg.append(f"Ports: {ports_str}")
                self._send_scan_summary_to_telegram("\n".join(msg))
                return
            except:
                pass
        results = []
        for ip in ips:
            if self.nmap_stop_event.is_set():
                break
            open_ports = self._scan_ports(ip, ports)
            if open_ports:
                self.after(0, self._append_nmap_log, f"{ip} open: {', '.join(str(p) for p in open_ports)}")
                results.append((ip, open_ports))
            else:
                self.after(0, self._append_nmap_log, f"{ip} no specified ports open")
        msg = []
        msg.append(f"<b>NMAP CUSTOM SCAN</b>")
        msg.append(f"Targets: {len(ips)}")
        msg.append(f"Ports: {', '.join(str(p) for p in ports)}")
        if results:
            msg.append("Open ports:")
            for ip, ports in results[:50]:
                msg.append(f" • {ip}: {', '.join(str(p) for p in ports)}")
        else:
            msg.append("No open specified ports found")
        self._send_scan_summary_to_telegram("\n".join(msg))

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

        # 1. Interfaces (Dynamic)
        self.interfaces_container = ttk.Frame(self.status_scroll_frame)
        self.interfaces_container.pack(fill=tk.X, padx=5, pady=5)

        # 2. Gateway
        self.gateway_frame = ttk.LabelFrame(self.status_scroll_frame, text="Gateway")
        self.gateway_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        
        self.gateway_info_label = ttk.Label(self.gateway_frame, text="Checking...")
        self.gateway_info_label.pack(anchor="w", padx=5, pady=5)

        # 3. System Status
        self.system_frame = ttk.LabelFrame(self.status_scroll_frame, text="System Status")
        self.system_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        
        self.internet_status_label = ttk.Label(self.system_frame, text="Internet: Unknown")
        self.internet_status_label.pack(anchor="w", padx=5, pady=2)
        
        self.downtime_label = ttk.Label(self.system_frame, text="", foreground="red")
        self.downtime_label.pack(anchor="w", padx=5, pady=2)

        # 4. DNS Servers
        self.dns_frame = ttk.LabelFrame(self.status_scroll_frame, text="DNS Servers")
        self.dns_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        
        self.dns_container = ttk.Frame(self.dns_frame)
        self.dns_container.pack(fill=tk.X, padx=5, pady=5)



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
        telegram_frame = ttk.LabelFrame(settings_frame, text="Telegram Chats")
        telegram_frame.pack(fill=tk.X, padx=10, pady=5)
        self.telegram_ids_list = tk.Listbox(telegram_frame, height=4)
        self.telegram_ids_list.pack(fill=tk.X, padx=5, pady=5)
        add_row = ttk.Frame(telegram_frame)
        add_row.pack(fill=tk.X, padx=5, pady=5)
        self.telegram_id_entry = ttk.Entry(add_row)
        self.telegram_id_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(add_row, text="Add", command=self.add_telegram_id).pack(side=tk.LEFT, padx=5)
        ttk.Button(add_row, text="Remove", command=self.remove_selected_telegram_ids).pack(side=tk.LEFT, padx=5)
        
        self.var_downtime_notify = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable Downtime Notifications", variable=self.var_downtime_notify, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        ttk.Separator(settings_frame, orient='horizontal').pack(fill='x', padx=5, pady=10)
        perf_frame = ttk.LabelFrame(settings_frame, text="Performance")
        perf_frame.pack(fill=tk.X, padx=10, pady=10)
        row = 0
        ttk.Label(perf_frame, text="Check Interval (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_check_interval = tk.IntVar(value=1)
        ttk.Spinbox(perf_frame, from_=1, to=10, textvariable=self.var_check_interval, command=self.update_settings, width=6).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        ttk.Label(perf_frame, text="LLDP Recheck (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_lldp_interval = tk.IntVar(value=5)
        ttk.Spinbox(perf_frame, from_=1, to=60, textvariable=self.var_lldp_interval, command=self.update_settings, width=6).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        ttk.Label(perf_frame, text="Interfaces TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_interfaces = tk.IntVar(value=2)
        ttk.Spinbox(perf_frame, from_=1, to=30, textvariable=self.var_ttl_interfaces, command=self.update_settings, width=6).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        ttk.Label(perf_frame, text="DNS Servers TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_dns_servers = tk.IntVar(value=15)
        ttk.Spinbox(perf_frame, from_=5, to=120, textvariable=self.var_ttl_dns_servers, command=self.update_settings, width=6).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        ttk.Label(perf_frame, text="DNS Status TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_dns_status = tk.IntVar(value=8)
        ttk.Spinbox(perf_frame, from_=2, to=60, textvariable=self.var_ttl_dns_status, command=self.update_settings, width=6).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        ttk.Label(perf_frame, text="Gateway TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_gateway = tk.IntVar(value=5)
        ttk.Spinbox(perf_frame, from_=2, to=60, textvariable=self.var_ttl_gateway, command=self.update_settings, width=6).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        ttk.Label(perf_frame, text="External IP TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_external_ip = tk.IntVar(value=120)
        ttk.Spinbox(perf_frame, from_=30, to=600, textvariable=self.var_ttl_external_ip, command=self.update_settings, width=8).grid(row=row, column=1, sticky="w", padx=5)
        
        self.var_debug = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Enable Debug Logging", variable=self.var_debug, command=self.update_settings).pack(anchor="w", padx=10, pady=10)
        
        self.var_debug_lldp = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Debug LLDP Details", variable=self.var_debug_lldp, command=self.update_settings).pack(anchor="w", padx=20, pady=5)
        
        ttk.Separator(settings_frame, orient='horizontal').pack(fill='x', padx=5, pady=10)
        
        # Interface monitoring controls
        interface_frame = ttk.LabelFrame(settings_frame, text="Interface Monitoring")
        interface_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.var_monitor_eth0 = tk.BooleanVar(value=True)
        ttk.Checkbutton(interface_frame, text="Monitor eth0 (Ethernet)", variable=self.var_monitor_eth0, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        self.var_monitor_wlan0 = tk.BooleanVar(value=True)
        ttk.Checkbutton(interface_frame, text="Monitor wlan0 (WiFi)", variable=self.var_monitor_wlan0, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        # MAC address changing section
        mac_frame = ttk.LabelFrame(settings_frame, text="MAC Address Control")
        mac_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # eth0 MAC controls
        eth0_frame = ttk.Frame(mac_frame)
        eth0_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(eth0_frame, text="eth0:").pack(side=tk.LEFT, padx=(0,10))
        self.eth0_mac_var = tk.StringVar()
        self.eth0_mac_entry = ttk.Entry(eth0_frame, width=20, textvariable=self.eth0_mac_var)
        self.eth0_mac_entry.pack(side=tk.LEFT, padx=(0,10))
        self.eth0_mac_var.trace_add('write', lambda *args: self._format_mac_var(self.eth0_mac_var, self.eth0_mac_entry))
        ttk.Button(eth0_frame, text="Change eth0 MAC", command=self.change_eth0_mac).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(eth0_frame, text="Restore", command=self.restore_eth0_mac).pack(side=tk.LEFT)
        
        # wlan0 MAC controls
        wlan0_frame = ttk.Frame(mac_frame)
        wlan0_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(wlan0_frame, text="wlan0:").pack(side=tk.LEFT, padx=(0,10))
        self.wlan0_mac_var = tk.StringVar()
        self.wlan0_mac_entry = ttk.Entry(wlan0_frame, width=20, textvariable=self.wlan0_mac_var)
        self.wlan0_mac_entry.pack(side=tk.LEFT, padx=(0,10))
        self.wlan0_mac_var.trace_add('write', lambda *args: self._format_mac_var(self.wlan0_mac_var, self.wlan0_mac_entry))
        ttk.Button(wlan0_frame, text="Change wlan0 MAC", command=self.change_wlan0_mac).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(wlan0_frame, text="Restore", command=self.restore_wlan0_mac).pack(side=tk.LEFT)

    def create_logs_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(parent, font=self.fonts['mono'], state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(parent, text="Clear Logs", command=lambda: self.log_text.delete(1.0, tk.END)).pack(fill=tk.X, padx=5, pady=5)
        self.redirect_logging()

    def redirect_logging(self):
        class QueueLogger:
            def __init__(self, queue):
                self.queue = queue
            def write(self, text):
                self.queue.put(text)
            def flush(self):
                pass

        sys.stdout = QueueLogger(self.log_queue)
        sys.stderr = QueueLogger(self.log_queue)

    def process_log_queue(self):
        try:
            while not self.log_queue.empty():
                message = self.log_queue.get_nowait()
                if message:
                    self.log_text.configure(state="normal")
                    self.log_text.insert("end", message)
                    self.log_text.see("end")
                    self.log_text.configure(state="disabled")
        except Exception as e:
            # This might happen if the queue is empty after the check
            pass
        finally:
            self.after(100, self.process_log_queue)

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
            self.monitor.downtime_report_on_recovery = self.var_downtime_notify.get()
            self.monitor.debug_enabled = self.var_debug.get()
            self.monitor.debug_lldp = self.var_debug_lldp.get()
            self.monitor.monitor_eth0 = self.var_monitor_eth0.get()
            self.monitor.monitor_wlan0 = self.var_monitor_wlan0.get()
            self.monitor.check_interval = max(1, int(self.var_check_interval.get()))
            self.monitor.lldp_recheck_interval = max(1, int(self.var_lldp_interval.get()))
            self.monitor.ttl_interfaces = max(1, int(self.var_ttl_interfaces.get()))
            self.monitor.ttl_dns_servers = max(1, int(self.var_ttl_dns_servers.get()))
            self.monitor.ttl_dns_status = max(1, int(self.var_ttl_dns_status.get()))
            self.monitor.ttl_gateway = max(1, int(self.var_ttl_gateway.get()))
            self.monitor.ttl_external_ip = max(10, int(self.var_ttl_external_ip.get()))
            nwscan.DEBUG_ENABLED = self.var_debug.get()
            try:
                ids = list(self.telegram_ids_list.get(0, tk.END))
                self.monitor.telegram_chat_ids = ids
            except:
                pass
            print("Settings updated.")
        self.save_settings()
    def add_telegram_id(self):
        val = self.telegram_id_entry.get().strip()
        if not val:
            return
        existing = set(self.telegram_ids_list.get(0, tk.END))
        if val not in existing:
            self.telegram_ids_list.insert(tk.END, val)
            self.telegram_id_entry.delete(0, tk.END)
            self.update_settings()
    def remove_selected_telegram_ids(self):
        sel = list(self.telegram_ids_list.curselection())
        sel.reverse()
        for i in sel:
            self.telegram_ids_list.delete(i)
        self.update_settings()

    def change_eth0_mac(self):
        new_mac = self.eth0_mac_entry.get().strip()
        if not new_mac:
            messagebox.showwarning("Warning", "Please enter a MAC address for eth0")
            return
        if not self.is_valid_mac(new_mac):
            messagebox.showerror("Error", "Invalid MAC address format. Use XX:XX:XX:XX:XX:XX")
            return
        try:
            if self.monitor:
                self.monitor.change_interface_mac("eth0", new_mac)
                messagebox.showinfo("Success", f"eth0 MAC address changed to {new_mac}")
            else:
                messagebox.showwarning("Warning", "Service must be running to change MAC address")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change eth0 MAC: {str(e)}")

    def change_wlan0_mac(self):
        new_mac = self.wlan0_mac_entry.get().strip()
        if not new_mac:
            messagebox.showwarning("Warning", "Please enter a MAC address for wlan0")
            return
        if not self.is_valid_mac(new_mac):
            messagebox.showerror("Error", "Invalid MAC address format. Use XX:XX:XX:XX:XX:XX")
            return
        try:
            if self.monitor:
                self.monitor.change_interface_mac("wlan0", new_mac)
                messagebox.showinfo("Success", f"wlan0 MAC address changed to {new_mac}")
            else:
                messagebox.showwarning("Warning", "Service must be running to change MAC address")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change wlan0 MAC: {str(e)}")

    def is_valid_mac(self, mac):
        import re
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(pattern, mac))

    def _format_mac_entry(self, entry):
        value = entry.get()
        hex_only = ''.join(ch for ch in value if ch.lower() in '0123456789abcdef')
        hex_only = hex_only[:12]
        parts = [hex_only[i:i+2] for i in range(0, len(hex_only), 2)]
        formatted = ':'.join(parts)
        if formatted != value:
            entry.delete(0, tk.END)
            entry.insert(0, formatted)
        entry.icursor(len(formatted))

    def _format_mac_var(self, var, entry):
        if getattr(self, "_mac_formatting", False):
            return
        self._mac_formatting = True
        value = var.get()
        hex_only = ''.join(ch for ch in value if ch.lower() in '0123456789abcdef')
        hex_only = hex_only[:12]
        parts = [hex_only[i:i+2] for i in range(0, len(hex_only), 2)]
        formatted = ':'.join(parts)
        if formatted != value:
            var.set(formatted)
        self.after_idle(lambda e=entry: e.icursor(len(e.get())))
        self._mac_formatting = False

    def restore_eth0_mac(self):
        try:
            if self.monitor:
                self.monitor.restore_interface_mac("eth0")
                messagebox.showinfo("Success", "eth0 MAC restored to factory")
            else:
                messagebox.showwarning("Warning", "Service must be running to restore MAC")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore eth0 MAC: {str(e)}")

    def restore_wlan0_mac(self):
        try:
            if self.monitor:
                self.monitor.restore_interface_mac("wlan0")
                messagebox.showinfo("Success", "wlan0 MAC restored to factory")
            else:
                messagebox.showwarning("Warning", "Service must be running to restore MAC")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore wlan0 MAC: {str(e)}")
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
        
        if self.monitor and self.monitor.downtime_start and not has_internet:
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

    def load_settings(self):
        """Load settings from configuration file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    settings = json.load(f)
                
                # Apply loaded settings to GUI variables
                self.var_lldp.set(settings.get('lldp_enabled', True))
                self.var_telegram.set(settings.get('telegram_enabled', True))
                self.var_downtime_notify.set(settings.get('downtime_notifications', True))
                self.var_debug.set(settings.get('debug_enabled', False))
                self.var_debug_lldp.set(settings.get('debug_lldp', False))
                self.var_monitor_eth0.set(settings.get('monitor_eth0', True))
                self.var_monitor_wlan0.set(settings.get('monitor_wlan0', True))
                self.var_check_interval.set(settings.get('check_interval', 1))
                self.var_lldp_interval.set(settings.get('lldp_recheck_interval', 5))
                self.var_ttl_interfaces.set(settings.get('ttl_interfaces', 2))
                self.var_ttl_dns_servers.set(settings.get('ttl_dns_servers', 15))
                self.var_ttl_dns_status.set(settings.get('ttl_dns_status', 8))
                self.var_ttl_gateway.set(settings.get('ttl_gateway', 5))
                self.var_ttl_external_ip.set(settings.get('ttl_external_ip', 120))
                ids = settings.get('telegram_chat_ids', [])
                try:
                    self.telegram_ids_list.delete(0, tk.END)
                    for cid in ids:
                        self.telegram_ids_list.insert(tk.END, str(cid))
                except:
                    pass
                print(f"Settings loaded from {self.config_file}")
            else:
                print("No existing config file found, using defaults")
                self.save_settings()  # Create initial config file
                
        except Exception as e:
            print(f"Error loading settings: {e}")
            # Use defaults if loading fails
            self.save_settings()

    def save_settings(self):
        """Save settings to configuration file"""
        settings = {
            'lldp_enabled': self.var_lldp.get(),
            'telegram_enabled': self.var_telegram.get(),
            'downtime_notifications': self.var_downtime_notify.get(),
            'debug_enabled': self.var_debug.get(),
            'debug_lldp': self.var_debug_lldp.get(),
            'monitor_eth0': self.var_monitor_eth0.get(),
            'monitor_wlan0': self.var_monitor_wlan0.get(),
            'check_interval': int(self.var_check_interval.get()),
            'lldp_recheck_interval': int(self.var_lldp_interval.get()),
            'ttl_interfaces': int(self.var_ttl_interfaces.get()),
            'ttl_dns_servers': int(self.var_ttl_dns_servers.get()),
            'ttl_dns_status': int(self.var_ttl_dns_status.get()),
            'ttl_gateway': int(self.var_ttl_gateway.get()),
            'ttl_external_ip': int(self.var_ttl_external_ip.get()),
            'telegram_chat_ids': list(self.telegram_ids_list.get(0, tk.END))
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(settings, f, indent=4)
            print(f"Settings saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving settings: {e}")

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

    def save_settings(self):
        """Save current settings to configuration file"""
        try:
            settings = {
                'lldp_enabled': self.var_lldp.get(),
                'telegram_enabled': self.var_telegram.get(),
                'downtime_notifications': self.var_downtime_notify.get(),
                'debug_enabled': self.var_debug.get(),
                'debug_lldp': self.var_debug_lldp.get(),
                'monitor_eth0': self.var_monitor_eth0.get(),
                'monitor_wlan0': self.var_monitor_wlan0.get(),
                'last_saved': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(settings, f, indent=2)
            
            print(f"Settings saved to {self.config_file}")
            
        except Exception as e:
            print(f"Error saving settings: {e}")

    # No GUI handlers here; NWScanGUI owns UI callbacks

if __name__ == "__main__":
    app = NWScanGUI()
    app.mainloop()
