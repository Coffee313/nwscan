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
import concurrent.futures
import signal
import tempfile
try:
    import fcntl
except ImportError:
    fcntl = None

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
    def __init__(self, is_root=True):
        print("[*] NWScanGUI: Starting __init__...")
        super().__init__()
        self.is_root = is_root
        self.title("NWSCAN")
        
        # Detect screen size and orientation
        self.update_idletasks()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        
        print(f"[*] Screen resolution: {screen_width}x{screen_height}")
        
        # Orientation check
        self.is_portrait = screen_height > screen_width
        if self.is_portrait:
            print("[*] Portrait mode detected (rotated screen).")
        
        if screen_width <= 480 or screen_height <= 480:
            print(f"[*] Small screen detected. Optimizing layout...")
            self.is_small_screen = True
            # For small screens, force geometry and enable fullscreen
            self.geometry(f"{screen_width}x{screen_height}+0+0")
            self.attributes('-fullscreen', True)
        else:
            self.is_small_screen = False
            self.geometry("800x480")
            
        self.bind("<Escape>", lambda event: self.attributes("-fullscreen", False))
        self.bind("<F11>", lambda event: self.attributes("-fullscreen", not self.attributes("-fullscreen")))
        
        try:
            self.style = ttk.Style()
            self.style.theme_use('clam')
            self.style.configure('Green.Horizontal.TProgressbar', background='#2ecc71', troughcolor='#e8f6f3')
            print("[+] Style initialized.")
        except Exception as e:
            print(f"[!] Style initialization error: {e}")
        
        # Optimize fonts for small screens/portrait
        base_size = 9
        if self.is_small_screen:
            if screen_width < 350 or screen_height < 350:
                base_size = 8
        else:
            base_size = 12
            
        self.fonts = {
            'default': ('Helvetica', base_size),
            'header': ('Helvetica', base_size + 1, 'bold'),
            'status': ('Helvetica', base_size + 2, 'bold'),
            'mono': ('Consolas', base_size - 1),
            'small': ('Helvetica', base_size - 2),
            'bold': ('Helvetica', base_size, 'bold')
        }
        
        try:
            self.style.configure('.', font=self.fonts['default'])
            self.style.configure('TButton', padding=2, font=self.fonts['default'])
            self.style.configure('Header.TLabel', font=self.fonts['header'])
            self.style.configure('Status.TLabel', font=self.fonts['status'])
            self.style.configure('Bold.TLabel', font=self.fonts['bold'])
            self.style.configure('TNotebook.Tab', padding=[5, 2], font=self.fonts['small'])
            print("[+] Fonts and styles configured.")
        except Exception as e:
            print(f"[!] Font/Style configuration error: {e}")
        
        self.monitor = None
        self.monitor_thread = None
        self.monitoring_active = False
        self.settings_loaded_from_file = False
        
        # Absolute path for config file
        self.base_dir = pathlib.Path(__file__).parent.resolve()
        self.config_file = self.base_dir / 'nwscan_config.json'
        self.log_queue = Queue()
        self.nmap_stop_event = threading.Event()
        self.nmap_thread = None
        self._nmap_procs = set()
        self._nmap_procs_lock = threading.Lock()
        self._last_nmap_subnet = None
        
        # SFTP Settings
        self.var_sftp_enabled = tk.BooleanVar(value=True)
        self.var_sftp_user = tk.StringVar(value="admin")
        self.var_sftp_password = tk.StringVar(value="password")
        self.var_sftp_port = tk.IntVar(value=2222)
        
        try:
            self.create_widgets()
            print("[+] Widgets created successfully.")
        except Exception as e:
            print(f"[!] CRITICAL error in create_widgets: {e}")
            import traceback
            traceback.print_exc()
            
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        try:
            self.load_settings()
            print("[+] Settings loaded.")
        except Exception as e:
            print(f"[!] Error in load_settings: {e}")
            
        self.process_log_queue()
        
        # Force window to top and visible
        self.after(100, self._force_visible)
        self.after(500, self.start_monitor)
        print("[*] NWScanGUI: __init__ finished.")

    def _safe_fullscreen(self):
        try:
            self.attributes('-fullscreen', True)
        except:
            pass

    def _force_visible(self):
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
            self.attributes("-topmost", True)
            self.after(1000, lambda: self.attributes("-topmost", False))
            print("[+] GUI window visibility forced.")
        except:
            pass

    def on_closing(self):
        if self.monitor:
            try:
                # Пытаемся сохранить настройки перед закрытием с алертом в случае ошибки
                self.save_settings(show_error_popup=True)
                self.monitor.cleanup()
            except:
                pass
        self.destroy()
        sys.exit(0)

    def create_widgets(self):
        print("[*] Starting create_widgets...")
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # --- Header ---
        print("[*] Creating Header...")
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # In portrait mode, we might want a more compact header
        if self.is_portrait:
            # Vertical-ish header for 320px width
            top_row = ttk.Frame(header_frame)
            top_row.pack(fill=tk.X)
            
            self.status_indicator = tk.Label(
                top_row, text="INIT", bg="gray", fg="white", 
                font=self.fonts['bold'], width=6
            )
            self.status_indicator.pack(side=tk.LEFT, padx=2)
            
            btn_exit = ttk.Button(top_row, text="X", width=2, command=self.on_closing)
            btn_exit.pack(side=tk.RIGHT, padx=2)
            
            info_row = ttk.Frame(header_frame)
            info_row.pack(fill=tk.X, pady=2)
            
            self.ip_label = ttk.Label(info_row, text="IP: ...", font=self.fonts['bold'])
            self.ip_label.pack(side=tk.LEFT, padx=5)
            
            self.ext_ip_label = ttk.Label(info_row, text="Ext: ...", font=self.fonts['small'], foreground="gray")
            self.ext_ip_label.pack(side=tk.RIGHT, padx=5)
        else:
            # Original landscape header
            self.status_indicator = tk.Label(
                header_frame, text="INIT", bg="gray", fg="white", 
                font=self.fonts['status'], width=8
            )
            self.status_indicator.pack(side=tk.LEFT, padx=5)

            btn_exit = ttk.Button(header_frame, text="X", width=3, command=self.on_closing)
            btn_exit.pack(side=tk.RIGHT, padx=5)
            
            info_frame = ttk.Frame(header_frame)
            info_frame.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
            
            self.ip_label = ttk.Label(info_frame, text="IP: Checking...", style='Header.TLabel')
            self.ip_label.pack(anchor="w")
            
            self.ext_ip_label = ttk.Label(info_frame, text="Ext IP: ...", font=self.fonts['small'], foreground="gray")
            self.ext_ip_label.pack(anchor="w")
        
        # --- Notebook ---
        print("[*] Creating Notebook...")
        # Reduce tab padding for small screens
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Shorter tab names for portrait
        t_status = "Status" if not self.is_portrait else "Stat"
        t_nmap = "Nmap" if not self.is_portrait else "Scan"
        t_neighbors = "Neighbors" if not self.is_portrait else "Nb"
        t_sftp = "SFTP" if not self.is_portrait else "SFTP"
        t_settings = "Settings" if not self.is_portrait else "Set"
        t_logs = "Logs" if not self.is_portrait else "Log"

        print(f"[*] Creating {t_status} tab...")
        self.tab_status = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_status, text=f" {t_status} ")
        self.create_status_tab(self.tab_status)
        
        print(f"[*] Creating {t_nmap} tab...")
        self.tab_nmap = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_nmap, text=f" {t_nmap} ")
        self.create_nmap_tab(self.tab_nmap)
        
        print(f"[*] Creating {t_neighbors} tab...")
        self.tab_neighbors = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_neighbors, text=f" {t_neighbors} ")
        self.create_neighbors_tab(self.tab_neighbors)
        
        print(f"[*] Creating {t_sftp} tab...")
        self.tab_sftp = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sftp, text=f" {t_sftp} ")
        self.create_sftp_tab(self.tab_sftp)
        
        print(f"[*] Creating {t_settings} tab...")
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text=f" {t_settings} ")
        self.create_settings_tab(self.tab_settings)
        
        print(f"[*] Creating {t_logs} tab...")
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text=f" {t_logs} ")
        self.create_logs_tab(self.tab_logs)

        # --- Footer ---
        if not self.is_portrait:
            print("[*] Creating Footer...")
            footer_frame = ttk.Frame(main_frame)
            footer_frame.pack(fill=tk.X, pady=(5, 0))
            
            self.save_status_label = ttk.Label(footer_frame, text="", font=self.fonts['small'])
            self.save_status_label.pack(side=tk.LEFT)
            
            self.last_update_label = ttk.Label(footer_frame, text="Last Update: Never", font=self.fonts['small'])
            self.last_update_label.pack(side=tk.RIGHT)
        else:
            # Very minimal footer for portrait - labels exist but are not packed
            self.save_status_label = ttk.Label(main_frame, text="")
            self.last_update_label = ttk.Label(main_frame, text="")
            
        print("[*] create_widgets finished.")
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
        ttk.Label(frame, text="Protocol").pack(anchor="w")
        self.nmap_proto_var = tk.StringVar(value="TCP")
        self.nmap_proto_combo = ttk.Combobox(frame, textvariable=self.nmap_proto_var, state="readonly", values=["TCP","UDP","Both"])
        self.nmap_proto_combo.pack(fill=tk.X, padx=0, pady=5)
        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, pady=5)
        
        if self.is_portrait:
            # 2x2 grid for buttons in portrait mode
            ttk.Button(btns, text="Discover", command=lambda: self._nmap_start_task(self._nmap_discover_hosts)).grid(row=0, column=0, sticky="ew", padx=2, pady=2)
            ttk.Button(btns, text="Quick", command=lambda: self._nmap_start_task(self._nmap_quick_scan)).grid(row=0, column=1, sticky="ew", padx=2, pady=2)
            ttk.Button(btns, text="Custom", command=lambda: self._nmap_start_task(self._nmap_custom_scan)).grid(row=1, column=0, sticky="ew", padx=2, pady=2)
            ttk.Button(btns, text="Stop", command=self._nmap_stop_scanning).grid(row=1, column=1, sticky="ew", padx=2, pady=2)
            btns.columnconfigure(0, weight=1)
            btns.columnconfigure(1, weight=1)
        else:
            ttk.Button(btns, text="Discover Hosts", command=lambda: self._nmap_start_task(self._nmap_discover_hosts)).pack(side=tk.LEFT, padx=5)
            ttk.Button(btns, text="Quick Scan", command=lambda: self._nmap_start_task(self._nmap_quick_scan)).pack(side=tk.LEFT, padx=5)
            ttk.Button(btns, text="Custom Scan", command=lambda: self._nmap_start_task(self._nmap_custom_scan)).pack(side=tk.LEFT, padx=5)
            ttk.Button(btns, text="Stop scanning", command=self._nmap_stop_scanning).pack(side=tk.LEFT, padx=5)
        self.nmap_progress = ttk.Progressbar(frame, orient="horizontal", mode="determinate", style='Green.Horizontal.TProgressbar')
        self.nmap_progress.pack(fill=tk.X, padx=0, pady=5)
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
    def _register_nmap_proc(self, proc):
        try:
            with self._nmap_procs_lock:
                self._nmap_procs.add(proc)
        except:
            pass
    def _unregister_nmap_proc(self, proc):
        try:
            with self._nmap_procs_lock:
                self._nmap_procs.discard(proc)
        except:
            pass
    def _kill_nmap_procs(self):
        procs = []
        try:
            with self._nmap_procs_lock:
                procs = list(self._nmap_procs)
        except:
            procs = []
        for p in procs:
            try:
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGTERM)
                    except:
                        try:
                            p.terminate()
                        except:
                            pass
                try:
                    p.wait(timeout=1)
                except:
                    try:
                        if p.poll() is None:
                            try:
                                os.killpg(p.pid, signal.SIGKILL)
                            except:
                                try:
                                    p.kill()
                                except:
                                    pass
                    except:
                        pass
            except:
                pass
            finally:
                self._unregister_nmap_proc(p)
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
        if len(ips) > 2048:
            ips = ips[:2048]
            self.after(0, self._append_nmap_log, "Target range truncated to 2048 hosts")
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
                val = ""
                if int(last) >= int(first):
                    val = f"{first}-{last}"
                else:
                    val = str(subnet)
                self.nmap_target_var.set(val)
                self._last_nmap_subnet = val
            except:
                self.nmap_target_var.set(str(subnet))
                self._last_nmap_subnet = str(subnet)
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
            self._kill_nmap_procs()
            self.after(0, self._append_nmap_log, "Scanning stopped")
            self.after(0, self._nmap_progress_reset)
            try:
                if self.nmap_thread:
                    self.nmap_thread.join(timeout=1)
            except:
                pass
        except:
            pass
    def _nmap_auto_sequence(self):
        try:
            self._nmap_discover_hosts()
            if not self.nmap_stop_event.is_set():
                self._nmap_quick_scan()
        except:
            pass
    def _send_scan_summary_to_telegram(self, message):
        try:
            if self.monitor and self.monitor.telegram_enabled and self.monitor.telegram_initialized:
                self.monitor.send_telegram_message_simple(message)
        except:
            pass
    def _parse_nmap_ports(self, text):
        tcp = []
        udp = []
        try:
            import re
            for line in text.splitlines():
                if 'open' in line and '/tcp' in line:
                    m = re.search(r'(\d+)/tcp\s+open', line)
                    if m:
                        try:
                            tcp.append(int(m.group(1)))
                        except:
                            pass
                if 'open' in line and '/udp' in line:
                    m = re.search(r'(\d+)/udp\s+open', line)
                    if m:
                        try:
                            udp.append(int(m.group(1)))
                        except:
                            pass
        except:
            pass
        return tcp, udp
    def _nmap_run_cli_batch(self, ips, ports, proto):
        results = []
        ports_str = ",".join(str(p) for p in ports)
        def worker(ip):
            if self.nmap_stop_event.is_set():
                return None
            args = ["nmap", "-Pn", "-T4", "-p", ports_str]
            if proto == "UDP":
                args += ["-sU"]
            elif proto == "BOTH":
                args += ["-sU", "-sT"]
            args.append(ip)
            out = ""
            proc = None
            try:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                self._register_nmap_proc(proc)
                while True:
                    if self.nmap_stop_event.is_set():
                        raise RuntimeError("stop")
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
                try:
                    o, e = proc.communicate(timeout=0.1)
                except:
                    o, e = "", ""
                out = (o or "").strip()
                self.after(0, self._append_nmap_log, out if out else f"{ip}: no output")
                t_ports, u_ports = self._parse_nmap_ports(out)
                return (ip, t_ports, u_ports)
            except RuntimeError:
                try:
                    if proc and proc.poll() is None:
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except:
                            try:
                                proc.terminate()
                            except:
                                pass
                except:
                    pass
                return (ip, [], [])
            except:
                return (ip, [], [])
            finally:
                if proc:
                    self._unregister_nmap_proc(proc)
        self.after(0, lambda: self._nmap_progress_init(len(ips)))
        workers = self._get_nmap_workers()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = []
            for ip in ips:
                if self.nmap_stop_event.is_set():
                    break
                futs.append(ex.submit(worker, ip))
            for f in concurrent.futures.as_completed(futs):
                try:
                    res = f.result()
                    if res:
                        results.append(res)
                        self.after(0, self._nmap_progress_tick)
                except:
                    pass
        self.after(0, self._nmap_progress_done)
        return results
    def _nmap_run_python_batch(self, ips, ports, proto):
        results = []
        workers = self._get_nmap_workers()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = []
            for ip in ips:
                if self.nmap_stop_event.is_set():
                    break
                futs.append(ex.submit(self._nmap_python_worker, ip, ports, proto))
            for f in concurrent.futures.as_completed(futs):
                try:
                    res = f.result()
                    if res:
                        results.append(res)
                        self.after(0, self._nmap_progress_tick)
                except:
                    pass
        return results
    def _nmap_python_worker(self, ip, ports, proto):
        if self.nmap_stop_event.is_set():
            return None
        t_ports = []
        u_ports = []
        try:
            if proto in ("TCP","BOTH"):
                t_ports = self._scan_ports(ip, ports)
                if t_ports:
                    self.after(0, self._append_nmap_log, f"{ip} TCP open: {', '.join(str(p) for p in t_ports)}")
                else:
                    self.after(0, self._append_nmap_log, f"{ip} TCP no ports open")
            if proto in ("UDP","BOTH"):
                u_ports = self._scan_udp_ports(ip, ports)
                if u_ports:
                    self.after(0, self._append_nmap_log, f"{ip} UDP open-like: {', '.join(str(p) for p in u_ports)}")
                else:
                    self.after(0, self._append_nmap_log, f"{ip} UDP no ports detected")
        except:
            pass
        return (ip, t_ports, u_ports)
    def _nmap_refresh_interfaces(self):
        names = []
        try:
            if self.monitor and self.monitor.current_state:
                for iface in self.monitor.current_state.get('interfaces', []):
                    if isinstance(iface, dict):
                        name = iface.get('name')
                        if name and not name.startswith('docker'):
                            names.append(name)
        except:
            pass
        if not names:
            names = ['eth0', 'wlan0']
        
        # Сохраняем текущий выбор, чтобы не сбрасывать его при обновлении
        current_selection = self.nmap_iface_var.get()
        self.nmap_iface_combo['values'] = names
        
        if not current_selection or current_selection not in names:
            if names:
                self.nmap_iface_var.set(names[0])
                self._nmap_autofill_fields()
        elif not self.nmap_target_var.get().strip():
            # Если интерфейс выбран, но поле target пустое - заполняем
            self._nmap_autofill_fields()
        else:
            # Check if subnet changed (e.g. via Telegram command)
            subnet = self._nmap_get_selected_subnet()
            if subnet and subnet.version == 4:
                try:
                    first = ipaddress.IPv4Address(int(subnet.network_address) + 1)
                    last = ipaddress.IPv4Address(int(subnet.broadcast_address) - 1)
                    val = ""
                    if int(last) >= int(first):
                        val = f"{first}-{last}"
                    else:
                        val = str(subnet)
                    
                    if val != getattr(self, '_last_nmap_subnet', None):
                        curr = self.nmap_target_var.get().strip()
                        # Update only if current value matches previous auto-fill (user hasn't customized it)
                        if not curr or curr == getattr(self, '_last_nmap_subnet', ""):
                            self.nmap_target_var.set(val)
                        self._last_nmap_subnet = val
                except:
                    pass
        
        self.nmap_iface_combo.bind("<<ComboboxSelected>>", lambda e: self._nmap_autofill_fields())

    def _ping_host(self, ip):
        try:
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
    def _scan_udp_ports(self, ip, ports):
        open_like = []
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.3)
                try:
                    s.sendto(b'\x00', (ip, p))
                    s.recvfrom(1024)
                    open_like.append(p)
                except socket.timeout:
                    pass
                except Exception:
                    pass
                finally:
                    s.close()
            except:
                pass
        return open_like
    def _nmap_discover_hosts(self):
        ips = self._parse_targets()
        if not ips:
            return
        self.after(0, self._append_nmap_log, f"Discovering hosts in {len(ips)} targets...")
        self.after(0, lambda: self._nmap_progress_init(len(ips)))
        live = []
        try:
            workers = self._get_nmap_workers()
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                future_to_ip = {}
                for ip in ips:
                    if self.nmap_stop_event.is_set():
                        break
                    future_to_ip[ex.submit(self._ping_host, ip)] = ip
                for fut in concurrent.futures.as_completed(future_to_ip):
                    if self.nmap_stop_event.is_set():
                        break
                    ip = future_to_ip.get(fut)
                    try:
                        up = fut.result()
                        if up:
                            live.append(ip)
                            self.after(0, self._append_nmap_log, f"{ip} is up")
                    except:
                        pass
                    finally:
                        self.after(0, self._nmap_progress_tick)
        except:
            pass
        if not live:
            self.after(0, self._append_nmap_log, "No hosts reachable")
        else:
            self.after(0, self._append_nmap_log, f"Total up hosts: {len(live)}")
        self.after(0, self._nmap_progress_done)
        summary = []
        summary.append(f"<b>NMAP DISCOVERY</b>")
        summary.append(f"Targets: {len(ips)}")
        summary.append(f"Up hosts: {len(live)}")
        if live:
            summary.append("Hosts:")
            try:
                live.sort(key=lambda x: ipaddress.ip_address(x))
            except:
                live.sort()
            for h in live[:50]:
                summary.append(f" • {h}")
        self._send_scan_summary_to_telegram("\n".join(summary))
    def _nmap_quick_scan(self):
        ips = self._parse_targets()
        if not ips:
            return
        common = [21,22,23,25,53,80,110,139,143,443,445,587,993,995,3306,5432,8080,8443]
        proto = (self.nmap_proto_var.get() or "TCP").upper()
        use_cli = shutil.which("nmap") is not None
        if use_cli and len(ips) == 1:
            ip = ips[0]
            ports_str = ",".join(str(p) for p in common)
            try:
                args = ["nmap", "-Pn", "-T4", "-p", ports_str]
                if proto == "UDP":
                    args += ["-sU"]
                elif proto == "BOTH":
                    args += ["-sU", "-sT"]
                args.append(ip)
                out = ""
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                self._register_nmap_proc(proc)
                while True:
                    if self.nmap_stop_event.is_set():
                        raise RuntimeError("stop")
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
                try:
                    o, e = proc.communicate(timeout=0.1)
                except:
                    o, e = "", ""
                out = (o or "").strip()
                self.after(0, self._append_nmap_log, out if out else "nmap produced no output")
                msg = []
                msg.append(f"<b>NMAP QUICK SCAN</b>")
                msg.append(f"Target: {ip}")
                msg.append(f"Protocol: {proto}")
                msg.append(f"Ports: {ports_str}")
                self._send_scan_summary_to_telegram("\n".join(msg))
                self.after(0, lambda: (self._nmap_progress_init(1), self._nmap_progress_done()))
                return
            except RuntimeError:
                try:
                    if proc and proc.poll() is None:
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except:
                            try:
                                proc.terminate()
                            except:
                                pass
                except:
                    pass
            except:
                pass
        if use_cli and len(ips) > 1:
            self.after(0, lambda: self._nmap_progress_init(len(ips)))
            batch = self._nmap_run_cli_batch(ips, common, proto)
            msg = []
            msg.append(f"<b>NMAP QUICK SCAN</b>")
            msg.append(f"Targets: {len(ips)}")
            msg.append(f"Protocol: {proto}")
            if batch:
                try:
                    batch.sort(key=lambda x: ipaddress.ip_address(x[0]))
                except:
                    batch.sort()
                if proto in ("TCP","BOTH"):
                    tcp_lines = [f" • {ip}: {', '.join(str(p) for p in t)}" for ip, t, u in batch if t]
                    msg.append("Open TCP:" if tcp_lines else "No open common TCP ports")
                    msg.extend(tcp_lines[:50])
                if proto in ("UDP","BOTH"):
                    udp_lines = [f" • {ip}: {', '.join(str(p) for p in u)}" for ip, t, u in batch if u]
                    msg.append("Open-like UDP:" if udp_lines else "No UDP ports detected")
                    msg.extend(udp_lines[:50])
            else:
                msg.append("No results")
            self._send_scan_summary_to_telegram("\n".join(msg))
            self.after(0, self._nmap_progress_done)
            return
        if len(ips) > 1:
            self.after(0, lambda: self._nmap_progress_init(len(ips)))
            batch = self._nmap_run_python_batch(ips, common, proto)
            msg = []
            msg.append(f"<b>NMAP QUICK SCAN</b>")
            msg.append(f"Targets: {len(ips)}")
            msg.append(f"Protocol: {proto}")
            if batch:
                try:
                    batch.sort(key=lambda x: ipaddress.ip_address(x[0]))
                except:
                    batch.sort()
                if proto in ("TCP","BOTH"):
                    tcp_lines = [f" • {ip}: {', '.join(str(p) for p in t)}" for ip, t, u in batch if t]
                    msg.append("Open TCP:" if tcp_lines else "No open common TCP ports")
                    msg.extend(tcp_lines[:50])
                if proto in ("UDP","BOTH"):
                    udp_lines = [f" • {ip}: {', '.join(str(p) for p in u)}" for ip, t, u in batch if u]
                    msg.append("Open-like UDP:" if udp_lines else "No UDP ports detected")
                    msg.extend(udp_lines[:50])
            else:
                msg.append("No results")
            self._send_scan_summary_to_telegram("\n".join(msg))
            self.after(0, self._nmap_progress_done)
            return
        results_tcp = []
        results_udp = []
        self._nmap_progress_init(len(ips))
        for ip in ips:
            if self.nmap_stop_event.is_set():
                break
            if proto in ("TCP","BOTH"):
                open_tcp = self._scan_ports(ip, common)
                if open_tcp:
                    self.after(0, self._append_nmap_log, f"{ip} TCP open: {', '.join(str(p) for p in open_tcp)}")
                    results_tcp.append((ip, open_tcp))
                else:
                    self.after(0, self._append_nmap_log, f"{ip} TCP no common ports open")
            if proto in ("UDP","BOTH"):
                open_udp = self._scan_udp_ports(ip, common)
                if open_udp:
                    self.after(0, self._append_nmap_log, f"{ip} UDP open-like: {', '.join(str(p) for p in open_udp)}")
                    results_udp.append((ip, open_udp))
                else:
                    self.after(0, self._append_nmap_log, f"{ip} UDP no common ports detected")
            self._nmap_progress_tick()
        msg = []
        msg.append(f"<b>NMAP QUICK SCAN</b>")
        msg.append(f"Targets: {len(ips)}")
        msg.append(f"Protocol: {proto}")
        if proto in ("TCP","BOTH"):
            if results_tcp:
                try:
                    results_tcp.sort(key=lambda x: ipaddress.ip_address(x[0]))
                except:
                    results_tcp.sort()
                msg.append("Open TCP:")
                for ip, ports in results_tcp[:50]:
                    msg.append(f" • {ip}: {', '.join(str(p) for p in ports)}")
            else:
                msg.append("No open common TCP ports")
        if proto in ("UDP","BOTH"):
            if results_udp:
                try:
                    results_udp.sort(key=lambda x: ipaddress.ip_address(x[0]))
                except:
                    results_udp.sort()
                msg.append("Open-like UDP:")
                for ip, ports in results_udp[:50]:
                    msg.append(f" • {ip}: {', '.join(str(p) for p in ports)}")
            else:
                msg.append("No UDP ports detected")
        self._send_scan_summary_to_telegram("\n".join(msg))
        self._nmap_progress_done()
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
                proto = (self.nmap_proto_var.get() or "TCP").upper()
                args = ["nmap", "-Pn", "-T4", "-p", ports_str]
                if proto == "UDP":
                    args += ["-sU"]
                elif proto == "BOTH":
                    args += ["-sU", "-sT"]
                args.append(ip)
                out = ""
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                self._register_nmap_proc(proc)
                while True:
                    if self.nmap_stop_event.is_set():
                        raise RuntimeError("stop")
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
                try:
                    o, e = proc.communicate(timeout=0.1)
                except:
                    o, e = "", ""
                out = (o or "").strip()
                self.after(0, self._append_nmap_log, out if out else "nmap produced no output")
                msg = []
                msg.append(f"<b>NMAP CUSTOM SCAN</b>")
                msg.append(f"Target: {ip}")
                msg.append(f"Protocol: {proto}")
                msg.append(f"Ports: {ports_str}")
                self._send_scan_summary_to_telegram("\n".join(msg))
                self.after(0, lambda: (self._nmap_progress_init(1), self._nmap_progress_done()))
                return
            except RuntimeError:
                try:
                    if proc and proc.poll() is None:
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except:
                            try:
                                proc.terminate()
                            except:
                                pass
                except:
                    pass
            except:
                pass
        proto = (self.nmap_proto_var.get() or "TCP").upper()
        if use_cli and len(ips) > 1:
            self.after(0, lambda: self._nmap_progress_init(len(ips)))
            batch = self._nmap_run_cli_batch(ips, ports, proto)
            msg = []
            msg.append(f"<b>NMAP CUSTOM SCAN</b>")
            msg.append(f"Targets: {len(ips)}")
            msg.append(f"Protocol: {proto}")
            msg.append(f"Ports: {', '.join(str(p) for p in ports)}")
            if batch:
                try:
                    batch.sort(key=lambda x: ipaddress.ip_address(x[0]))
                except:
                    batch.sort()
                if proto in ("TCP","BOTH"):
                    tcp_lines = [f" • {ip}: {', '.join(str(p) for p in t)}" for ip, t, u in batch if t]
                    msg.append("Open TCP:" if tcp_lines else "No TCP ports open")
                    msg.extend(tcp_lines[:50])
                if proto in ("UDP","BOTH"):
                    udp_lines = [f" • {ip}: {', '.join(str(p) for p in u)}" for ip, t, u in batch if u]
                    msg.append("Open-like UDP:" if udp_lines else "No UDP ports detected")
                    msg.extend(udp_lines[:50])
            else:
                msg.append("No results")
            self._send_scan_summary_to_telegram("\n".join(msg))
            self.after(0, self._nmap_progress_done)
            return
        if len(ips) > 1:
            self.after(0, lambda: self._nmap_progress_init(len(ips)))
            batch = self._nmap_run_python_batch(ips, ports, proto)
            msg = []
            msg.append(f"<b>NMAP CUSTOM SCAN</b>")
            msg.append(f"Targets: {len(ips)}")
            msg.append(f"Protocol: {proto}")
            msg.append(f"Ports: {', '.join(str(p) for p in ports)}")
            if batch:
                try:
                    batch.sort(key=lambda x: ipaddress.ip_address(x[0]))
                except:
                    batch.sort()
                if proto in ("TCP","BOTH"):
                    tcp_lines = [f" • {ip}: {', '.join(str(p) for p in t)}" for ip, t, u in batch if t]
                    msg.append("Open TCP:" if tcp_lines else "No TCP ports open")
                    msg.extend(tcp_lines[:50])
                if proto in ("UDP","BOTH"):
                    udp_lines = [f" • {ip}: {', '.join(str(p) for p in u)}" for ip, t, u in batch if u]
                    msg.append("Open-like UDP:" if udp_lines else "No UDP ports detected")
                    msg.extend(udp_lines[:50])
            else:
                msg.append("No results")
            self._send_scan_summary_to_telegram("\n".join(msg))
            self.after(0, self._nmap_progress_done)
            return
        results_tcp = []
        results_udp = []
        self._nmap_progress_init(len(ips))
        for ip in ips:
            if self.nmap_stop_event.is_set():
                break
            if proto in ("TCP","BOTH"):
                open_tcp = self._scan_ports(ip, ports)
                if open_tcp:
                    self.after(0, self._append_nmap_log, f"{ip} TCP open: {', '.join(str(p) for p in open_tcp)}")
                    results_tcp.append((ip, open_tcp))
                else:
                    self.after(0, self._append_nmap_log, f"{ip} TCP no specified ports open")
            if proto in ("UDP","BOTH"):
                open_udp = self._scan_udp_ports(ip, ports)
                if open_udp:
                    self.after(0, self._append_nmap_log, f"{ip} UDP open-like: {', '.join(str(p) for p in open_udp)}")
                    results_udp.append((ip, open_udp))
                else:
                    self.after(0, self._append_nmap_log, f"{ip} UDP no specified ports detected")
            self._nmap_progress_tick()
        msg = []
        msg.append(f"<b>NMAP CUSTOM SCAN</b>")
        msg.append(f"Targets: {len(ips)}")
        msg.append(f"Protocol: {proto}")
        msg.append(f"Ports: {', '.join(str(p) for p in ports)}")
        if proto in ("TCP","BOTH"):
            if results_tcp:
                msg.append("Open TCP:")
                for ip, tports in results_tcp[:50]:
                    msg.append(f" • {ip}: {', '.join(str(p) for p in tports)}")
            else:
                msg.append("No TCP ports open")
        if proto in ("UDP","BOTH"):
            if results_udp:
                msg.append("Open-like UDP:")
                for ip, uports in results_udp[:50]:
                    msg.append(f" • {ip}: {', '.join(str(p) for p in uports)}")
            else:
                msg.append("No UDP ports detected")
        self._send_scan_summary_to_telegram("\n".join(msg))
        self._nmap_progress_done()
    def _get_nmap_workers(self):
        try:
            return max(1, min(64, int(self.var_nmap_workers.get())))
        except:
            try:
                return max(1, min(64, int(getattr(self, 'nmap_max_workers', 5))))
            except:
                return 5
    def _nmap_progress_init(self, total):
        try:
            total = max(1, int(total))
            self.nmap_progress['maximum'] = total
            self.nmap_progress['value'] = 0
        except:
            pass
    def _nmap_progress_tick(self):
        try:
            v = float(self.nmap_progress['value'])
            m = float(self.nmap_progress['maximum'])
            self.nmap_progress['value'] = min(m, v + 1)
        except:
            pass
    def _nmap_progress_done(self):
        try:
            self.nmap_progress['value'] = self.nmap_progress['maximum']
        except:
            pass
    def _nmap_progress_reset(self):
        try:
            self.nmap_progress['maximum'] = 100
            self.nmap_progress['value'] = 0
        except:
            pass

    def create_status_tab(self, parent):
        # Create scrolling area
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.status_scroll_frame = ttk.Frame(canvas)
        
        self.status_scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.status_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Touch scrolling support
        self._setup_touch_scrolling(canvas)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 1. Interfaces (Top Priority)
        self.interfaces_container = ttk.Frame(self.status_scroll_frame)
        self.interfaces_container.pack(fill=tk.X, padx=10, pady=5)

        # 2. Internet Status
        internet_frame = ttk.LabelFrame(self.status_scroll_frame, text="Internet & System")
        internet_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.internet_status_label = ttk.Label(internet_frame, text="Internet: Checking...", font=self.fonts['bold'])
        self.internet_status_label.pack(anchor="w", padx=10, pady=2)
        
        self.downtime_label = ttk.Label(internet_frame, text="", foreground="red")
        self.downtime_label.pack(anchor="w", padx=10, pady=2)

        # 3. Gateway Info
        gateway_frame = ttk.LabelFrame(self.status_scroll_frame, text="Default Gateway")
        gateway_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.gateway_info_label = ttk.Label(gateway_frame, text="Gateway: Checking...")
        self.gateway_info_label.pack(anchor="w", padx=10, pady=5)

        # 4. DNS Status
        dns_header_frame = ttk.Frame(self.status_scroll_frame)
        dns_header_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        ttk.Label(dns_header_frame, text="DNS Servers", style='Header.TLabel').pack(side=tk.LEFT)
        
        self.dns_container = ttk.Frame(self.status_scroll_frame)
        self.dns_container.pack(fill=tk.X, padx=10, pady=5)

    def _setup_touch_scrolling(self, canvas):
        """Setup mouse/touch drag scrolling for a canvas"""
        self._last_y = 0
        
        def on_press(event):
            self._last_y = event.y
            canvas.scan_mark(event.x, event.y)
            
        def on_drag(event):
            # Calculate delta and scroll
            # canvas.scan_dragto is standard but we want a natural feel
            canvas.scan_dragto(event.x, event.y, gain=1)
            
        canvas.bind("<Button-1>", on_press)
        canvas.bind("<B1-Motion>", on_drag)
        # Mouse wheel support as well
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))

    def create_neighbors_tab(self, parent):
        # Create scrolling area
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.neighbors_scroll_frame = ttk.Frame(canvas)
        
        self.neighbors_scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.neighbors_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Touch scrolling support
        self._setup_touch_scrolling(canvas)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_sftp_tab(self, parent):
        # Create scrolling area
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.sftp_scroll_frame = ttk.Frame(canvas)
        
        self.sftp_scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.sftp_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Touch scrolling support
        self._setup_touch_scrolling(canvas)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 1. SFTP Status & Control
        status_frame = ttk.LabelFrame(self.sftp_scroll_frame, text="SFTP Server Status")
        status_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.sftp_status_label = ttk.Label(status_frame, text="Status: Unknown", font=self.fonts['bold'])
        self.sftp_status_label.pack(side=tk.TOP if self.is_portrait else tk.LEFT, padx=10, pady=5)
        
        self.btn_sftp_toggle = ttk.Button(status_frame, text="Toggle SFTP", command=self.toggle_sftp)
        self.btn_sftp_toggle.pack(side=tk.TOP if self.is_portrait else tk.RIGHT, padx=10, pady=5)
        
        # 2. Configuration
        config_frame = ttk.LabelFrame(self.sftp_scroll_frame, text="Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        row = 0
        ttk.Label(config_frame, text="Port:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.var_sftp_port, width=10).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        
        ttk.Label(config_frame, text="Username:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.var_sftp_user).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        
        ttk.Label(config_frame, text="Password:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.var_sftp_password).grid(row=row, column=1, sticky="w", padx=5)
        row += 1
        
        ttk.Button(config_frame, text="Apply Settings", command=self.update_settings).grid(row=row, column=0, columnspan=2, pady=10)
        
        # 3. Files
        files_frame = ttk.LabelFrame(self.sftp_scroll_frame, text="Files")
        files_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.sftp_files_text = scrolledtext.ScrolledText(files_frame, height=10, font=self.fonts['mono'])
        self.sftp_files_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(files_frame, text="Refresh Files", command=self.refresh_sftp_files).pack(fill=tk.X, padx=5, pady=5)
        
    def toggle_sftp(self):
        if self.monitor:
            new_state = not self.monitor.sftp_enabled
            self.var_sftp_enabled.set(new_state)
            self.update_settings()
            self.after(1000, self.refresh_sftp_status)
            
    def refresh_sftp_status(self):
        if self.monitor:
            status = "Running" if self.monitor.sftp_enabled else "Stopped"
            color = "green" if self.monitor.sftp_enabled else "red"
            self.sftp_status_label.config(text=f"Status: {status}", foreground=color)
            self.btn_sftp_toggle.config(text="Stop SFTP" if self.monitor.sftp_enabled else "Start SFTP")
            
    def refresh_sftp_files(self):
        self.sftp_files_text.delete(1.0, tk.END)
        if self.monitor and os.path.exists(self.monitor.sftp_root):
            try:
                files = os.listdir(self.monitor.sftp_root)
                if not files:
                    self.sftp_files_text.insert(tk.END, "No files found.")
                else:
                    for f in files:
                        fpath = os.path.join(self.monitor.sftp_root, f)
                        size = os.path.getsize(fpath)
                        size_str = self.monitor.format_size(size)
                        self.sftp_files_text.insert(tk.END, f"{f:<30} {size_str}\n")
            except Exception as e:
                self.sftp_files_text.insert(tk.END, f"Error listing files: {e}")
        else:
             self.sftp_files_text.insert(tk.END, "SFTP root directory not found or monitor not started.")

    def create_settings_tab(self, parent):
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.settings_scroll_frame = ttk.Frame(canvas)
        self.settings_scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.settings_scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Touch scrolling support
        self._setup_touch_scrolling(canvas)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        control_frame = ttk.LabelFrame(self.settings_scroll_frame, text="Service Control")
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.btn_start = ttk.Button(control_frame, text="Start Service", command=self.start_monitor)
        self.btn_start.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=10)
        
        self.btn_stop = ttk.Button(control_frame, text="Stop Service", command=self.stop_monitor)
        self.btn_stop.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=10)
        
        settings_frame = ttk.LabelFrame(self.settings_scroll_frame, text="Configuration")
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.var_auto_scan = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Auto NMAP scan on network up", variable=self.var_auto_scan, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        self.var_lldp = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable LLDP/CDP Discovery", variable=self.var_lldp, command=self.update_settings).pack(anchor="w", padx=10, pady=10)
        
        # LLDP Interfaces
        lldp_frame = ttk.Frame(settings_frame)
        lldp_frame.pack(fill=tk.X, padx=30, pady=0)
        self.var_lldp_eth0 = tk.BooleanVar(value=True)
        ttk.Checkbutton(lldp_frame, text="Scan eth0", variable=self.var_lldp_eth0, command=self.update_settings).pack(anchor="w")
        self.var_lldp_wlan0 = tk.BooleanVar(value=True)
        ttk.Checkbutton(lldp_frame, text="Scan wlan0", variable=self.var_lldp_wlan0, command=self.update_settings).pack(anchor="w")
        
        self.var_telegram = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable Telegram Notifications", variable=self.var_telegram, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
        
        self.var_telegram_on_change = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Notify only on network changes", variable=self.var_telegram_on_change, command=self.update_settings).pack(anchor="w", padx=30, pady=2)
        
        self.var_downtime_notify = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Enable Downtime Notifications", variable=self.var_downtime_notify, command=self.update_settings).pack(anchor="w", padx=10, pady=5)
                
        telegram_frame = ttk.LabelFrame(settings_frame, text="Telegram Settings")
        telegram_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(telegram_frame, text="Bot Token:").pack(anchor="w", padx=5, pady=2)
        self.telegram_token_var = tk.StringVar()
        self.telegram_token_entry = ttk.Entry(telegram_frame, textvariable=self.telegram_token_var, show="*")
        self.telegram_token_entry.pack(fill=tk.X, padx=5, pady=2)
        self.telegram_token_entry.bind("<FocusOut>", lambda e: self.update_settings())
        self.telegram_token_entry.bind("<Return>", lambda e: self.update_settings())
        ttk.Separator(telegram_frame, orient='horizontal').pack(fill='x', padx=5, pady=6)
        ttk.Label(telegram_frame, text="Chat IDs:").pack(anchor="w", padx=5, pady=2)
        self.telegram_ids_list = tk.Listbox(telegram_frame, height=4)
        self.telegram_ids_list.pack(fill=tk.X, padx=5, pady=5)
        add_row = ttk.Frame(telegram_frame)
        add_row.pack(fill=tk.X, padx=5, pady=5)
        self.telegram_id_entry = ttk.Entry(add_row)
        self.telegram_id_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(add_row, text="Add", command=self.add_telegram_id).pack(side=tk.LEFT, padx=5)
        ttk.Button(add_row, text="Remove", command=self.remove_selected_telegram_ids).pack(side=tk.LEFT, padx=5)

        
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
        ttk.Separator(settings_frame, orient='horizontal').pack(fill='x', padx=5, pady=10)
        perf_frame = ttk.LabelFrame(settings_frame, text="Performance")
        perf_frame.pack(fill=tk.X, padx=10, pady=10)
        row = 0
        ttk.Label(perf_frame, text="Check Interval (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_check_interval = tk.IntVar(value=2)
        sb1 = ttk.Spinbox(perf_frame, from_=1, to=10, textvariable=self.var_check_interval, command=self.update_settings, width=6)
        sb1.grid(row=row, column=1, sticky="w", padx=5)
        sb1.bind("<FocusOut>", lambda e: self.update_settings())
        sb1.bind("<Return>", lambda e: self.update_settings())
        row += 1
        ttk.Label(perf_frame, text="LLDP Recheck (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_lldp_interval = tk.IntVar(value=10)
        sb2 = ttk.Spinbox(perf_frame, from_=1, to=60, textvariable=self.var_lldp_interval, command=self.update_settings, width=6)
        sb2.grid(row=row, column=1, sticky="w", padx=5)
        sb2.bind("<FocusOut>", lambda e: self.update_settings())
        sb2.bind("<Return>", lambda e: self.update_settings())
        row += 1
        ttk.Label(perf_frame, text="Interfaces TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_interfaces = tk.IntVar(value=5)
        sb3 = ttk.Spinbox(perf_frame, from_=1, to=30, textvariable=self.var_ttl_interfaces, command=self.update_settings, width=6)
        sb3.grid(row=row, column=1, sticky="w", padx=5)
        sb3.bind("<FocusOut>", lambda e: self.update_settings())
        sb3.bind("<Return>", lambda e: self.update_settings())
        row += 1
        ttk.Label(perf_frame, text="DNS Servers TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_dns_servers = tk.IntVar(value=30)
        sb4 = ttk.Spinbox(perf_frame, from_=5, to=120, textvariable=self.var_ttl_dns_servers, command=self.update_settings, width=6)
        sb4.grid(row=row, column=1, sticky="w", padx=5)
        sb4.bind("<FocusOut>", lambda e: self.update_settings())
        sb4.bind("<Return>", lambda e: self.update_settings())
        row += 1
        ttk.Label(perf_frame, text="DNS Status TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_dns_status = tk.IntVar(value=15)
        sb5 = ttk.Spinbox(perf_frame, from_=2, to=60, textvariable=self.var_ttl_dns_status, command=self.update_settings, width=6)
        sb5.grid(row=row, column=1, sticky="w", padx=5)
        sb5.bind("<FocusOut>", lambda e: self.update_settings())
        sb5.bind("<Return>", lambda e: self.update_settings())
        row += 1
        ttk.Label(perf_frame, text="Gateway TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_gateway = tk.IntVar(value=10)
        sb6 = ttk.Spinbox(perf_frame, from_=2, to=60, textvariable=self.var_ttl_gateway, command=self.update_settings, width=6)
        sb6.grid(row=row, column=1, sticky="w", padx=5)
        sb6.bind("<FocusOut>", lambda e: self.update_settings())
        sb6.bind("<Return>", lambda e: self.update_settings())
        row += 1
        ttk.Label(perf_frame, text="External IP TTL (s)").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_ttl_external_ip = tk.IntVar(value=300)
        sb7 = ttk.Spinbox(perf_frame, from_=30, to=600, textvariable=self.var_ttl_external_ip, command=self.update_settings, width=8)
        sb7.grid(row=row, column=1, sticky="w", padx=5)
        sb7.bind("<FocusOut>", lambda e: self.update_settings())
        sb7.bind("<Return>", lambda e: self.update_settings())
        row += 1
        ttk.Label(perf_frame, text="Nmap Parallel Hosts").grid(row=row, column=0, sticky="w", padx=5, pady=2)
        self.var_nmap_workers = tk.IntVar(value=2)
        sb8 = ttk.Spinbox(perf_frame, from_=1, to=64, textvariable=self.var_nmap_workers, command=self.update_settings, width=6)
        sb8.grid(row=row, column=1, sticky="w", padx=5)
        sb8.bind("<FocusOut>", lambda e: self.update_settings())
        sb8.bind("<Return>", lambda e: self.update_settings())

    def create_logs_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(parent, font=self.fonts['mono'], state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(parent, text="Clear Logs", command=lambda: self.log_text.delete(1.0, tk.END)).pack(fill=tk.X, padx=5, pady=5)
        self.redirect_logging()

    def redirect_logging(self):
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
        class QueueLogger:
            def __init__(self, queue, original):
                self.queue = queue
                self.original = original
            def write(self, text):
                if text:
                    self.queue.put(text)
                if self.original:
                    try:
                        self.original.write(text)
                    except:
                        pass
            def flush(self):
                if self.original:
                    try:
                        self.original.flush()
                    except:
                        pass

        sys.stdout = QueueLogger(self.log_queue, self.original_stdout)
        sys.stderr = QueueLogger(self.log_queue, self.original_stderr)

    def process_log_queue(self):
        try:
            while not self.log_queue.empty():
                message = self.log_queue.get_nowait()
                if message:
                    self.log_text.configure(state="normal")
                    self.log_text.insert("end", message)
                    self.log_text.see("end")
                    self.log_text.configure(state="disabled")
                    
            # Auto-truncate logs if too long (keep last ~1000 lines approx)
            if int(self.log_text.index('end-1c').split('.')[0]) > 5000:
                 self.log_text.configure(state='normal')
                 self.log_text.delete('1.0', '1000.0')
                 self.log_text.configure(state='disabled')
        except Exception as e:
            # This might happen if the queue is empty after the check
            pass
        finally:
            self.after(100, self.process_log_queue)

    def start_monitor(self):
        if self.monitoring_active: return
        try:
            if not self.monitor:
                try:
                    self.monitor = GUINetworkMonitor(self)
                except RuntimeError as e:
                    if "Another instance" in str(e):
                        msg = "Error: Another instance of NWSCAN is already running (likely the background service).\n\nPlease stop it first:\nsudo systemctl stop nwscan"
                        print(f"\n[!] {msg}")
                        messagebox.showerror("Conflict", msg)
                        self.on_closing()
                        return
                    raise
            self.monitor.config_callback = self.sync_settings_from_dict
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
            print(f"[!] Failed to start monitor: {e}")
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
        """Sync GUI variables to monitor instance and save"""
        if self.monitor:
            # We call save_settings which now performs the sync internally
            # to ensure monitor state matches GUI state before saving.
            self.save_settings(show_error_popup=False)
            
            print("Settings updated and save triggered.")
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
            
        # Build monitored IP info
        monitored_ips = []
        try:
            # Check eth0
            try:
                if bool(self.var_monitor_eth0.get()):
                    eth0_found = False
                    # Look for eth0 in interfaces list
                    for iface in state.get('interfaces', []):
                        if iface.get('name') == 'eth0':
                            eth0_found = True
                            ips = iface.get('ip_addresses', [])
                            if ips:
                                # Show first IP
                                ip_str = ips[0].get('cidr', 'Unknown')
                                monitored_ips.append(f"eth0: {ip_str}")
                            else:
                                monitored_ips.append("eth0: No IP")
                            break
                    if not eth0_found:
                        monitored_ips.append("eth0: Down")
            except Exception as e: 
                print(f"Error checking eth0: {e}")

            # Check wlan0
            try:
                if bool(self.var_monitor_wlan0.get()):
                    wlan0_found = False
                    for iface in state.get('interfaces', []):
                        if iface.get('name') == 'wlan0':
                            wlan0_found = True
                            ips = iface.get('ip_addresses', [])
                            if ips:
                                ip_str = ips[0].get('cidr', 'Unknown')
                                monitored_ips.append(f"wlan0: {ip_str}")
                            else:
                                monitored_ips.append("wlan0: No IP")
                            break
                    if not wlan0_found:
                        monitored_ips.append("wlan0: Down")
            except Exception as e:
                print(f"Error checking wlan0: {e}")
            
        except Exception as e:
            print(f"Error building IP list: {e}")
        
        # Join list or show placeholder if nothing monitored
        ip_display = " | ".join(monitored_ips) if monitored_ips else "No Monitored Interfaces"
        self.ip_label.config(text=f"{ip_display}")
        self.ext_ip_label.config(text=f"Ext IP: {ext_ip if ext_ip else 'N/A'}")
        
        # 2. Status Tab - Internet Status
        self.internet_status_label.config(text=f"Internet: {'Available' if has_internet else 'Unavailable'}")
        
        if self.monitor and self.monitor.downtime_start and not has_internet:
            duration = (datetime.now() - self.monitor.downtime_start).total_seconds()
            self.downtime_label.config(text=f"Downtime: {self.monitor.format_duration(duration)}")
        else:
            self.downtime_label.config(text="")

        # 3. Status Tab - Interfaces (Moved to top of tab)
        self.clear_frame(self.interfaces_container)
        active_ifaces = state.get('active_interfaces', [])
        
        if active_ifaces:
            ttk.Label(self.interfaces_container, text="Active Interfaces", style='Header.TLabel').pack(anchor="w", pady=(10,5))
            
            for iface in active_ifaces:
                if isinstance(iface, dict):
                    if iface.get('name', '').startswith('docker'):
                        continue
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

        # 4. Status Tab - Gateway
        gateway = state.get('gateway')
        if gateway:
            gw_status = "OK" if gateway.get('available') else "Unreachable"
            self.gateway_info_label.config(text=f"Address: {gateway.get('address')}\nInterface: {gateway.get('interface')}\nStatus: {gw_status}")
        else:
            self.gateway_info_label.config(text="Gateway: None")

        # 5. Status Tab - DNS
        self.clear_frame(self.dns_container)
        dns_status = state.get('dns_status', [])
        if dns_status:
            # Group by interface
            dns_by_iface = {}
            for dns in dns_status:
                if isinstance(dns, dict):
                    iface = dns.get('interface', 'Unknown')
                    if iface not in dns_by_iface:
                        dns_by_iface[iface] = []
                    dns_by_iface[iface].append(dns)
            
            # Display grouped results
            for iface_name, dns_list in dns_by_iface.items():
                iface_frame = ttk.LabelFrame(self.dns_container, text=f"Interface: {iface_name}")
                iface_frame.pack(fill=tk.X, pady=5, padx=2)
                
                for dns in dns_list:
                    server = dns.get('server')
                    working = dns.get('working')
                    resp_time = dns.get('response_time')
                    
                    frame = ttk.Frame(iface_frame)
                    frame.pack(fill=tk.X, pady=2, padx=5)
                    
                    status_lbl = tk.Label(frame, text="✓" if working else "✗", fg="green" if working else "red", font=self.fonts['bold'])
                    status_lbl.pack(side=tk.LEFT)
                    
                    time_txt = f"({resp_time*1000:.0f}ms)" if resp_time else ""
                    ttk.Label(frame, text=f"{server} {time_txt}").pack(side=tk.LEFT, padx=5)
        else:
            ttk.Label(self.dns_container, text="No DNS servers configured").pack(anchor="w")

        # 6. Neighbors Tab
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
        
        # 7. SFTP Status Update
        self.refresh_sftp_status()
        if self.notebook.tab(self.notebook.select(), "text").strip() == "SFTP":
            self.refresh_sftp_files()
        
        # Автоматическое обновление списка интерфейсов для Nmap
        self._nmap_refresh_interfaces()

    def load_settings(self):
        """Load settings from configuration file using monitor's logic"""
        try:
            # First ensure monitor is initialized to use its path logic
            if not self.monitor:
                self.monitor = GUINetworkMonitor(self)
                
            cfg_path = self.monitor.get_config_path()
            if os.path.exists(cfg_path):
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                self.sync_settings_from_dict(settings)
                self.settings_loaded_from_file = True
                print(f"Settings loaded from {cfg_path}")
            else:
                print(f"No existing config file found at {cfg_path}, using defaults")
                # If file doesn't exist, we treat it as "loaded" defaults so we can save them on exit
                self.settings_loaded_from_file = True
        except Exception as e:
            print(f"Error loading settings: {e}")

    def sync_settings_from_dict(self, settings):
        """Update GUI variables from a settings dictionary (thread-safe)"""
        def _update():
            try:
                # Use lldp_enabled as primary for the combined GUI checkbox
                if 'lldp_enabled' in settings: 
                    self.var_lldp.set(settings['lldp_enabled'])
                elif 'cdp_enabled' in settings:
                    self.var_lldp.set(settings['cdp_enabled'])
                
                if 'lldp_eth0' in settings: self.var_lldp_eth0.set(settings['lldp_eth0'])
                if 'lldp_wlan0' in settings: self.var_lldp_wlan0.set(settings['lldp_wlan0'])
                    
                if 'telegram_enabled' in settings: self.var_telegram.set(settings['telegram_enabled'])
                if 'telegram_notify_on_change' in settings: self.var_telegram_on_change.set(settings['telegram_notify_on_change'])
                if 'downtime_notifications' in settings: self.var_downtime_notify.set(settings['downtime_notifications'])
                if 'monitor_eth0' in settings: self.var_monitor_eth0.set(settings['monitor_eth0'])
                if 'monitor_wlan0' in settings: self.var_monitor_wlan0.set(settings['monitor_wlan0'])
                if 'check_interval' in settings: self.var_check_interval.set(settings['check_interval'])
                if 'lldp_recheck_interval' in settings: self.var_lldp_interval.set(settings['lldp_recheck_interval'])
                if 'ttl_interfaces' in settings: self.var_ttl_interfaces.set(settings['ttl_interfaces'])
                if 'ttl_dns_servers' in settings: self.var_ttl_dns_servers.set(settings['ttl_dns_servers'])
                if 'ttl_dns_status' in settings: self.var_ttl_dns_status.set(settings['ttl_dns_status'])
                if 'ttl_gateway' in settings: self.var_ttl_gateway.set(settings['ttl_gateway'])
                if 'ttl_external_ip' in settings: self.var_ttl_external_ip.set(settings['ttl_external_ip'])
                if 'nmap_max_workers' in settings: self.var_nmap_workers.set(settings['nmap_max_workers'])
                if 'auto_scan_on_network_up' in settings: self.var_auto_scan.set(settings['auto_scan_on_network_up'])
                if 'telegram_token' in settings: self.telegram_token_var.set(settings['telegram_token'])
                
                # SFTP settings sync
                if 'sftp_enabled' in settings: self.var_sftp_enabled.set(settings['sftp_enabled'])
                if 'sftp_user' in settings: self.var_sftp_user.set(settings['sftp_user'])
                if 'sftp_password' in settings: self.var_sftp_password.set(settings['sftp_password'])
                if 'sftp_port' in settings: self.var_sftp_port.set(settings['sftp_port'])
                
                if 'telegram_chat_ids' in settings:
                    self.telegram_ids_list.delete(0, tk.END)
                    for cid in settings['telegram_chat_ids']:
                        self.telegram_ids_list.insert(tk.END, str(cid))
            except Exception as e:
                print(f"Error syncing GUI: {e}")
        
        self.after(0, _update)

    def save_settings(self, show_error_popup=False):
        """Save current settings to configuration file using unified monitor logic"""
        if not self.monitor:
            return False
            
        if not getattr(self, 'settings_loaded_from_file', False):
            print("[!] Skipping save_settings: Settings were not successfully loaded (preventing default overwrite)")
            return False
            
        try:
            # First sync any remaining GUI state to monitor (mostly for 'on_closing' case)
            # But we do it carefully to avoid overwriting newer values if possible.
            # For now, a full sync is safest before a final save.
            lldp_val = bool(self.var_lldp.get())
            self.monitor.lldp_enabled = lldp_val
            self.monitor.cdp_enabled = lldp_val # Sync CDP with LLDP checkbox
            self.monitor.lldp_eth0 = bool(self.var_lldp_eth0.get())
            self.monitor.lldp_wlan0 = bool(self.var_lldp_wlan0.get())
            self.monitor.telegram_enabled = bool(self.var_telegram.get())
            self.monitor.telegram_notify_on_change = bool(self.var_telegram_on_change.get())
            self.monitor.downtime_report_on_recovery = bool(self.var_downtime_notify.get())
            self.monitor.monitor_eth0 = bool(self.var_monitor_eth0.get())
            self.monitor.monitor_wlan0 = bool(self.var_monitor_wlan0.get())
            self.monitor.check_interval = int(self.var_check_interval.get() or 30)
            self.monitor.lldp_recheck_interval = int(self.var_lldp_interval.get() or 30)
            self.monitor.ttl_interfaces = int(self.var_ttl_interfaces.get() or 10)
            self.monitor.ttl_dns_servers = int(self.var_ttl_dns_servers.get() or 60)
            self.monitor.ttl_dns_status = int(self.var_ttl_dns_status.get() or 30)
            self.monitor.ttl_gateway = int(self.var_ttl_gateway.get() or 30)
            self.monitor.ttl_external_ip = int(self.var_ttl_external_ip.get() or 300)
            self.monitor.telegram_bot_token = self.telegram_token_var.get().strip()
            self.monitor.telegram_chat_ids = set(str(cid) for cid in self.telegram_ids_list.get(0, tk.END))
            self.monitor.nmap_workers = int(self.var_nmap_workers.get() or 8)
            self.monitor.auto_scan_on_network_up = bool(self.var_auto_scan.get())
            
            # Sync SFTP settings to monitor
            self.monitor.sftp_enabled = bool(self.var_sftp_enabled.get())
            self.monitor.sftp_user = self.var_sftp_user.get().strip()
            self.monitor.sftp_password = self.var_sftp_password.get().strip()
            self.monitor.sftp_port = int(self.var_sftp_port.get() or 2222)

            # Use unified save logic from nwscan.py
            if self.monitor.save_config():
                self.save_status_label.config(text="✅ Settings saved", foreground="green")
                # Hide status after 3 seconds
                self.after(3000, lambda: self.save_status_label.config(text=""))
                return True
            else:
                err = getattr(self.monitor, 'last_save_error', 'File access denied or locked')
                self.save_status_label.config(text="❌ Save failed", foreground="red")
                if show_error_popup:
                    messagebox.showerror("Save Error", f"Failed to save configuration!\n\nDetails: {err}\n\nCheck file permissions and try again.")
                return False
        except Exception as e:
            self.save_status_label.config(text="❌ Sync error", foreground="red")
            if show_error_popup:
                messagebox.showerror("Error", f"Error during settings sync: {e}")
            return False

class GUINetworkMonitor(nwscan.NetworkMonitor):
    def __init__(self, gui_app):
        super().__init__(is_root=gui_app.is_root, exit_on_lock_fail=False)
        self.gui_app = gui_app
        
    def display_network_info(self, state):
        # Update GUI only
        self.gui_app.after(0, self.gui_app.update_gui, state)
        self.last_display_state = state.copy()
        
    def trigger_auto_scan(self, state):
        """Override to use GUI-specific scan kickoff"""
        if not getattr(self, 'auto_scan_on_network_up', True):
            return
            
        gw = state.get('gateway')
        active = state.get('active_interfaces', [])
        has_ips = False
        for iface in active:
            if isinstance(iface, dict) and iface.get('ip_addresses'):
                if len(iface.get('ip_addresses')) > 0:
                    has_ips = True
                    break
        
        if gw and gw.get('available') and has_ips:
            prev = self.last_telegram_state
            prev_gw = prev.get('gateway') if isinstance(prev, dict) else None
            prev_avail = prev_gw.get('available') if isinstance(prev_gw, dict) else False
            prev_addr = prev_gw.get('address') if isinstance(prev_gw, dict) else None
            
            if (not prev_avail) or (prev_addr != gw.get('address')):
                def kickoff():
                    try:
                        gw_iface = state.get('gateway', {}).get('interface')
                        if gw_iface:
                            self.gui_app.nmap_iface_var.set(gw_iface)
                            self.gui_app._nmap_autofill_fields()
                    except:
                        pass
                    self.gui_app._nmap_start_task(self.gui_app._nmap_auto_sequence)
                self.gui_app.after(0, kickoff)
                # Also send to Telegram via base class logic (will happen in monitoring_thread)

    def save_settings(self):
        """Save current settings to configuration file (delegates to gui_app)"""
        try:
            self.gui_app.save_settings()
        except Exception as e:
            print(f"Error saving settings from monitor: {e}")

    # No GUI handlers here; NWScanGUI owns UI callbacks

if __name__ == "__main__":
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Launching NWSCAN GUI...")
    
    # SINGLETON CHECK: Ensure only one instance runs
    pid_file = os.path.join(tempfile.gettempdir(), "nwscan_gui.pid")
    lock_file = None
    
    if os.name == 'posix':
        try:
            import fcntl
            lock_file = open(pid_file, 'w')
            fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock_file.write(str(os.getpid()))
            lock_file.flush()
        except (IOError, OSError, ImportError):
            print("\n[!] CRITICAL: Another instance of NWScan GUI is already running.")
            sys.exit(1)
    else:
        # Simple check for Windows (not as robust as fcntl but better than nothing)
        # On Windows, we'll just check if the file exists and is not empty, 
        # but better yet, we can try to delete it.
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
        except (IOError, OSError):
            print("\n[!] CRITICAL: Another instance of NWScan GUI is likely running (PID file locked).")
            sys.exit(1)

    # Check if running as root on Linux
    if os.name == 'posix' and os.geteuid() != 0:
        print("[*] Detected non-root user. Elevating to root via sudo...")
        try:
            # Preserve environment for GUI (DISPLAY, XAUTHORITY)
            os.execvp('sudo', ['sudo', '-E', sys.executable] + sys.argv)
        except Exception as e:
            print(f"[!] Elevation failed: {e}")
            sys.exit(1)
            
    # Fix for running as root on Linux with X11
    if os.name == 'posix' and os.geteuid() == 0:
        print("[*] Running as root. Configuring X11 environment...")
        
        # Force DISPLAY if missing
        if 'DISPLAY' not in os.environ:
            print("[!] DISPLAY environment variable missing. Setting to :0")
            os.environ['DISPLAY'] = ':0'
        
        # MHS 3.5 LCD usually works on :0, but sometimes on :0.0
        # If the user is in a terminal, we might need to export it.
        
        # 2. XAUTHORITY fix
        if 'XAUTHORITY' not in os.environ:
            try:
                # Get current desktop user
                user = subprocess.check_output("logname", shell=True).decode().strip()
                if not user:
                    user = os.environ.get('SUDO_USER', 'pi')
                
                auth_path = f"/home/{user}/.Xauthority"
                if os.path.exists(auth_path):
                    print(f"[*] Found XAUTHORITY at: {auth_path}")
                    os.environ['XAUTHORITY'] = auth_path
                else:
                    print(f"[!] XAUTHORITY file not found at {auth_path}")
            except Exception as e:
                print(f"[!] Error detecting XAUTHORITY: {e}")

    # --- ADDED: Ensure X11 is ready ---
    if os.name == 'posix':
        try:
            subprocess.run(['xset', 'q'], check=False, capture_output=True)
            # xhost might be needed to allow root to connect to the X server
            user = os.environ.get('SUDO_USER', 'pi')
            subprocess.run(['xhost', f'+si:localuser:root'], check=False, capture_output=True)
        except:
            pass

    print("[*] Initializing Tkinter...")
    is_root = True
    try:
        print("[*] Creating NWScanGUI instance...")
        app = NWScanGUI(is_root=is_root)
        
        print("[*] Entering mainloop...")
        app.mainloop()
    except Exception as e:
        print(f"\nCRITICAL ERROR: Failed to start GUI.")
        print(f"Reason: {e}")
        import traceback
        traceback.print_exc()
        
        if "no display name" in str(e).lower() or "couldn't connect to display" in str(e).lower():
            print("\nSUGGESTION: This is a DISPLAY error.")
            print("1. If you are on the local Desktop, run: xhost +local:root")
            print("2. Try: export DISPLAY=:0.0")
            print("3. Check if X is running: pgrep Xorg")
        sys.exit(1)
