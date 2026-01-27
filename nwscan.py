#!/usr/bin/env python3
"""
NWSCAN - Network Status Monitor
Background checks, display only on changes, stable LED blinking
With full IP mask display, Telegram notifications, and LLDP/CDP support
"""


import time
import socket
import traceback
import subprocess
import os
import sys
import re
import signal
import json
import requests
import urllib3
import struct
from datetime import datetime, timedelta
from threading import Thread, Lock, Event
import ipaddress
import concurrent.futures
import shutil
import paramiko

try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    from unittest.mock import MagicMock
    GPIO = MagicMock()

# ================= CONFIGURATION =================
LED_GREEN_PIN = 16         # GPIO port (physical pin 36) - Green component
LED_RED_PIN = 20           # GPIO port (physical pin 38) - Red component
LED_BLUE_PIN = 12          # GPIO port (physical pin 32) - Blue component
LED_PIN = LED_GREEN_PIN    # Backward compatibility
BUZZER_PIN = 21            # GPIO port (physical pin 40)
RESET_BUTTON_PIN = 26      # GPIO port (physical pin 37) - Button to reset to DHCP
CHECK_HOST = "8.8.8.8"    # Server to check
CHECK_PORT = 53           # DNS port
CHECK_INTERVAL = 2        # Check interval in seconds (Increased for Pi)
BLINK_INTERVAL = 0.15     # Stable blink interval
DNS_TEST_HOSTNAME = "google.com"  # Hostname for DNS resolution test

# Internet downtime logging
DOWNTIME_LOG_FILE = "/var/log/nwscan_downtime.log"  # File to log internet downtimes
DOWNTIME_REPORT_ON_RECOVERY = True  # Send report when internet is restored

# LLDP/CDP settings
LLDP_ENABLED = True        # Enable LLDP neighbor discovery
CDP_ENABLED = True         # Enable CDP neighbor discovery (Cisco)
LLDP_TIMEOUT = 2          # Timeout for LLDP/CDP commands in seconds
LLDP_RECHECK_INTERVAL = 10   # How often to recheck LLDP/CDP (seconds) (Increased for Pi)

# Caching/TTL to reduce subprocess load on low-power devices
INTERFACES_TTL = 5         # (Increased for Pi)
DNS_SERVERS_TTL = 30       # (Increased for Pi)
DNS_STATUS_TTL = 15        # (Increased for Pi)
GATEWAY_TTL = 10           # (Increased for Pi)
EXTERNAL_IP_TTL = 300      # (Increased for Pi)
AUTO_INSTALL_LLDP = True   # Automatically install LLDP tools if missing
FILTER_DUPLICATE_NEIGHBORS = True  # Filter duplicate neighbors

# Telegram configuration
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
TELEGRAM_API_BASE_URL = os.environ.get("TELEGRAM_API_BASE_URL", "https://api.telegram.org")
TELEGRAM_ENABLED = True                         # Включить/выключить Telegram уведомления
TELEGRAM_NOTIFY_ON_CHANGE = True                # Отправлять уведомления только при изменениях
TELEGRAM_TIMEOUT = 10                          # Таймаут для Telegram запросов (секунды)
TELEGRAM_CHAT_IDS = []                         # Список ID чатов; может быть пустым при старте

# Debug settings
DEBUG_ENABLED = False                           # Включить подробное логирование (internal use only)
DEBUG_TELEGRAM = False                          # Включить отладку Telegram (internal use only)
DEBUG_LLDP = False                              # Включить отладку LLDP/CDP (internal use only)
# =================================================

# Отключаем предупреждения о SSL для упрощения
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'  # No Color

def colored(text, color):
    return color + text + NC

def debug_print(message, category="INFO"):
    """Вывод информации. Важные события (INFO, SUCCESS, WARNING, ERROR, DOWNTIME) выводятся всегда."""
    
    # Categories that should ALWAYS be printed regardless of debug mode
    ALWAYS_PRINT = ["INFO", "SUCCESS", "WARNING", "ERROR", "DOWNTIME"]
    
    should_print = False
    
    if category in ALWAYS_PRINT:
        should_print = True
    elif DEBUG_ENABLED:
        should_print = True
    elif category == "LLDP" and DEBUG_LLDP:
        should_print = True
    elif category == "TELEGRAM" and DEBUG_TELEGRAM:
        should_print = True
        
    if should_print:
        # colors = {
        #     "INFO": CYAN,
        #     "TELEGRAM": PURPLE,
        #     "ERROR": RED,
        #     "SUCCESS": GREEN,
        #     "WARNING": YELLOW,
        #     "DOWNTIME": YELLOW,
        #     "LLDP": BLUE
        # }
        
        # color = colors.get(category, CYAN)
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Print without colors to keep GUI logs clean
        print(f"[{timestamp}] [{category}] {message}")

def cidr_to_mask(prefix):
    """Convert CIDR prefix to subnet mask"""
    masks = {
        32: "255.255.255.255", 31: "255.255.255.254", 30: "255.255.255.252",
        29: "255.255.255.248", 28: "255.255.255.240", 27: "255.255.255.224",
        26: "255.255.255.192", 25: "255.255.255.128", 24: "255.255.255.0",
        23: "255.255.254.0",   22: "255.255.252.0",   21: "255.255.248.0",
        20: "255.255.240.0",   19: "255.255.224.0",   18: "255.255.192.0",
        17: "255.255.128.0",   16: "255.255.0.0",     15: "255.254.0.0",
        14: "255.252.0.0",     13: "255.248.0.0",     12: "255.240.0.0",
        11: "255.224.0.0",     10: "255.192.0.0",     9: "255.128.0.0",
        8: "255.0.0.0",        7: "254.0.0.0",        6: "252.0.0.0",
        5: "248.0.0.0",        4: "240.0.0.0",        3: "224.0.0.0",
        2: "192.0.0.0",        1: "128.0.0.0",        0: "0.0.0.0"
    }
    return masks.get(prefix, f"/{prefix}")

def calculate_network_info(ip_cidr):
    """Calculate full network information from CIDR notation"""
    try:
        ip_str, prefix_str = ip_cidr.split('/')
        prefix = int(prefix_str)
        
        # Convert IP to integer
        ip_parts = list(map(int, ip_str.split('.')))
        ip_num = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        
        # Calculate network mask
        mask_num = (0xffffffff << (32 - prefix)) & 0xffffffff
        
        # Network address
        network_num = ip_num & mask_num
        
        # Broadcast address
        broadcast_num = network_num | (~mask_num & 0xffffffff)
        
        # Convert back to IP format
        def num_to_ip(num):
            return "{}.{}.{}.{}".format(
                (num >> 24) & 0xff,
                (num >> 16) & 0xff,
                (num >> 8) & 0xff,
                num & 0xff
            )
        
        # First and last usable IPs
        first_usable = network_num + 1 if prefix < 31 else network_num
        last_usable = broadcast_num - 1 if prefix < 31 else broadcast_num
        
        # Total hosts
        total_hosts = 2 ** (32 - prefix)
        usable_hosts = max(0, total_hosts - 2) if prefix < 31 else total_hosts
        
        return {
            'ip': ip_str,
            'prefix': prefix,
            'mask': cidr_to_mask(prefix),
            'mask_decimal': mask_num,
            'network': num_to_ip(network_num),
            'broadcast': num_to_ip(broadcast_num),
            'first_usable': num_to_ip(first_usable),
            'last_usable': num_to_ip(last_usable),
            'total_hosts': total_hosts,
            'usable_hosts': usable_hosts,
            'cidr': ip_cidr
        }
    except Exception as e:
        debug_print(f"Error calculating network info for {ip_cidr}: {e}", "ERROR")
        return None

# ================= SFTP SERVER IMPLEMENTATION =================
class SimpleSFTPServerInterface(paramiko.SFTPServerInterface):
    def __init__(self, server, root_dir):
        self.root_dir = os.path.abspath(root_dir)
        debug_print(f"SFTP: Interface initialized for root: {self.root_dir}", "INFO")
        super().__init__(server)

    def _realpath(self, path):
        # Prevent path traversal
        path = path.replace('\\', '/')
        if path.startswith('/'):
            path = path[1:]
        normalized = os.path.normpath(os.path.join(self.root_dir, path))
        if not normalized.startswith(self.root_dir):
            debug_print(f"SFTP: Path traversal attempt: {path}", "WARNING")
            return self.root_dir
        return normalized

    def canonicalize(self, path):
        debug_print(f"SFTP: Canonicalize path: {path}", "DEBUG")
        if path == '.' or path == '':
            return '/'
        return os.path.normpath('/' + path.lstrip('/'))

    def list_dir(self, path):
        realpath = self._realpath(path)
        debug_print(f"SFTP: List dir: {path} -> {realpath}", "INFO")
        try:
            out = []
            for fname in os.listdir(realpath):
                fpath = os.path.join(realpath, fname)
                st = os.stat(fpath)
                attr = paramiko.SFTPAttributes.from_stat(st)
                attr.filename = fname
                out.append(attr)
            return out
        except OSError as e:
            debug_print(f"SFTP: List dir error: {e}", "ERROR")
            return paramiko.SFT_ERRNO_NO_SUCH_FILE

    def stat(self, path):
        realpath = self._realpath(path)
        debug_print(f"SFTP: Stat path: {path} -> {realpath}", "DEBUG")
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(realpath))
        except OSError as e:
            return paramiko.SFT_ERRNO_NO_SUCH_FILE

    def lstat(self, path):
        realpath = self._realpath(path)
        debug_print(f"SFTP: Lstat path: {path} -> {realpath}", "DEBUG")
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(realpath))
        except OSError as e:
            return paramiko.SFT_ERRNO_NO_SUCH_FILE

    def open(self, path, flags, attr):
        realpath = self._realpath(path)
        debug_print(f"SFTP: Open file: {path} (flags={flags})", "INFO")
        try:
            # Determine mode for opening
            if flags & os.O_WRONLY:
                if flags & os.O_APPEND:
                    mode = 'ab'
                else:
                    mode = 'wb'
            elif flags & os.O_RDWR:
                if flags & os.O_APPEND:
                    mode = 'a+b'
                else:
                    mode = 'r+b'
            else:
                mode = 'rb'

            if flags & os.O_CREAT:
                # Use os.open for more control with flags
                fd = os.open(realpath, flags, attr.st_mode if attr and attr.st_mode else 0o644)
                f = os.fdopen(fd, mode)
            else:
                f = open(realpath, mode)
            
            # Simple handle
            class FakeHandle(paramiko.SFTPHandle):
                def __init__(self, file_obj, flags, path):
                    super().__init__(flags)
                    self.file = file_obj
                    self.path = path
                def close(self):
                    debug_print(f"SFTP: Closing handle for {self.path}", "DEBUG")
                    super().close()
                    self.file.close()
                def read(self, offset, length):
                    try:
                        self.file.seek(offset)
                        return self.file.read(length)
                    except EOFError:
                        return b''
                def write(self, offset, data):
                    try:
                        self.file.seek(offset)
                        self.file.write(data)
                        return len(data)
                    except Exception as e:
                        debug_print(f"SFTP: Write error: {e}", "ERROR")
                        return paramiko.SFT_ERRNO_PERMISSION_DENIED
                def stat(self):
                    try:
                        return paramiko.SFTPAttributes.from_stat(os.fstat(self.file.fileno()))
                    except Exception:
                        return paramiko.SFT_ERRNO_PERMISSION_DENIED
            
            return FakeHandle(f, flags, path)
        except OSError as e:
            debug_print(f"SFTP: Open error: {e}", "ERROR")
            if e.errno == 2:
                return paramiko.SFT_ERRNO_NO_SUCH_FILE
            return paramiko.SFT_ERRNO_PERMISSION_DENIED

    def readlink(self, path):
        try:
            return os.readlink(self._realpath(path))
        except OSError:
            return paramiko.SFT_ERRNO_NO_SUCH_FILE

    def symlink(self, target, path):
        try:
            os.symlink(target, self._realpath(path))
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFT_ERRNO_PERMISSION_DENIED

    def remove(self, path):
        try:
            os.remove(self._realpath(path))
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFT_ERRNO_PERMISSION_DENIED

    def rename(self, oldpath, newpath):
        try:
            os.rename(self._realpath(oldpath), self._realpath(newpath))
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFT_ERRNO_PERMISSION_DENIED

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._realpath(path))
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFT_ERRNO_PERMISSION_DENIED

    def rmdir(self, path):
        try:
            os.rmdir(self._realpath(path))
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFT_ERRNO_PERMISSION_DENIED

class SimpleSSHServer(paramiko.ServerInterface):
    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.event = Event()

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        debug_print(f"SFTP: Auth attempt for user '{username}'", "INFO")
        if username == self.user and password == self.password:
            debug_print(f"SFTP: Auth SUCCESS for user '{username}'", "SUCCESS")
            return paramiko.AUTH_SUCCESSFUL
        debug_print(f"SFTP: Auth FAILED for user '{username}'", "WARNING")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        debug_print(f"SFTP: Channel request: {kind} (id={chanid})", "INFO")
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_interactive(self, username, submethods):
        return paramiko.AUTH_FAILED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        debug_print("SFTP: Shell request (denied)", "WARNING")
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        debug_print("SFTP: PTY request (denied)", "WARNING")
        return False

    def check_channel_subsystem_request(self, channel, name):
        debug_print(f"SFTP: Subsystem request: {name}", "INFO")
        if name == 'sftp':
            self.event.set()
            return True
        return False

# =============================================================

class NetworkMonitor:
    def __init__(self, is_root=True, exit_on_lock_fail=True):
        self.is_root = is_root
        # Prevent multiple instances
        self.lock_file = "/tmp/nwscan.lock" if os.name == 'posix' else None
        self.lock_fd = None
        if self.lock_file:
            try:
                self.lock_fd = os.open(self.lock_file, os.O_CREAT | os.O_WRONLY)
                import fcntl
                try:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (IOError, OSError):
                    print("Error: Another instance of NWSCAN is already running.")
                    if exit_on_lock_fail:
                        sys.exit(1)
                    else:
                        raise RuntimeError("Another instance is running")
            except Exception as e:
                if "Another instance" in str(e):
                    raise
                debug_print(f"Lock file warning: {e}", "WARNING")

        self.config_callback = None
        self.restart_pending = False
        self.lock = Lock()
        self.current_state = {
            'ip': None,
            'has_internet': False,
            'interfaces': [],
            'active_interfaces': [],
            'gateway': None,
            'dns': [],
            'dns_status': [],
            'external_ip': None,
            'neighbors': []  # LLDP/CDP neighbors
        }
        self.last_display_state = None
        self.last_telegram_state = None
        self.running = True
        self.led_state = "OFF"
        self.stop_led_thread = False
        self.led_thread = None
        self.telegram_initialized = False
        self.telegram_errors = 0
        self.max_telegram_errors = 3
        
        # Internet downtime tracking
        self.downtime_start = None  # Когда начался даунтайм
        self.internet_was_up = True  # Предыдущее состояние интернета
        self.downtime_log_file = DOWNTIME_LOG_FILE
        self.downtime_report_on_recovery = DOWNTIME_REPORT_ON_RECOVERY
        
        # LLDP/CDP tracking
        self.lldp_enabled = LLDP_ENABLED
        self.cdp_enabled = CDP_ENABLED
        self.lldp_eth0 = True
        self.lldp_wlan0 = True
        self.lldp_timeout = LLDP_TIMEOUT
        self.lldp_recheck_interval = LLDP_RECHECK_INTERVAL
        self.auto_install_lldp = AUTO_INSTALL_LLDP
        self.filter_duplicates = FILTER_DUPLICATE_NEIGHBORS
        self.last_lldp_check = 0
        self.lldp_neighbors = {}
        self.lldp_service_checked = False
        self.lldp_service_running = False
        
        # Dump control
        self.dump_stop_event = Event()
        self.dump_process = None
        
        self.telegram_enabled = TELEGRAM_ENABLED
        self.telegram_bot_token = TELEGRAM_BOT_TOKEN
        self.telegram_api_base_url = TELEGRAM_API_BASE_URL
        self.telegram_chat_ids = set(TELEGRAM_CHAT_IDS)
        self.telegram_notify_on_change = TELEGRAM_NOTIFY_ON_CHANGE
        self.telegram_timeout = TELEGRAM_TIMEOUT
        self.debug_enabled = DEBUG_ENABLED
        self.debug_lldp = globals().get('DEBUG_LLDP', False)
        self.debug_telegram = DEBUG_TELEGRAM
        self.monitor_eth0 = True
        self.monitor_wlan0 = True
        self.check_interval = CHECK_INTERVAL
        self.ttl_interfaces = INTERFACES_TTL
        self.ttl_dns_servers = DNS_SERVERS_TTL
        self.ttl_dns_status = DNS_STATUS_TTL
        self.ttl_gateway = GATEWAY_TTL
        self.ttl_external_ip = EXTERNAL_IP_TTL
        self.telegram_last_init_attempt = 0
        self.telegram_reinit_interval = 30
        self.telegram_update_offset = None
        self.telegram_cmd_thread = None
        self._nmap_procs = set()
        self._nmap_procs_lock = Lock()
        self.nmap_stop_event = Event()
        self.nmap_thread = None
        self.nmap_workers = 2
        self.auto_scan_on_network_up = False
        self.restart_pending = False
        self.config_callback = None
        self.last_save_error = None
        self.startup_message_sent = False
        
        # SFTP settings
        self.sftp_enabled = True
        self.sftp_user = "admin"
        self.sftp_password = "password"
        self.sftp_port = 2222
        self.sftp_server_instance = None
        self.sftp_thread = None
        self.sftp_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sftp_files")
        self.waiting_for_sftp_upload = {} # chat_id -> bool
        self.known_sftp_files = set()
        self.last_sftp_scan = 0
        
        # Ensure SFTP root exists
        if not os.path.exists(self.sftp_root):
            try:
                os.makedirs(self.sftp_root)
            except:
                pass
        
        # Initial scan of SFTP files
        try:
            if os.path.exists(self.sftp_root):
                self.known_sftp_files = set(os.listdir(self.sftp_root))
        except:
            self.known_sftp_files = set()

        # Загружаем конфигурацию
        try:
            self.load_config()
        except Exception as e:
            debug_print(f"Error applying config: {e}", "ERROR")
        self._cache = {
            'interfaces': {'ts': 0, 'value': ([], [])},
            'dns_servers': {'ts': 0, 'value': []},
            'dns_status': {'ts': 0, 'value': []},
            'gateway': {'ts': 0, 'value': None},
            'external_ip': {'ts': 0, 'value': None},
        }
        
        # GPIO setup
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(LED_GREEN_PIN, GPIO.OUT)
        GPIO.setup(LED_RED_PIN, GPIO.OUT)
        GPIO.output(LED_GREEN_PIN, GPIO.LOW)
        GPIO.output(LED_RED_PIN, GPIO.LOW)
        
        GPIO.setup(LED_BLUE_PIN, GPIO.OUT)
        GPIO.output(LED_BLUE_PIN, GPIO.LOW)
            
        GPIO.setup(BUZZER_PIN, GPIO.OUT)
        GPIO.output(BUZZER_PIN, GPIO.LOW)
        
        self.scanning_in_progress = False
        self.dump_in_progress = False
        
            # Reset Button Setup
        try:
            GPIO.setup(RESET_BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
            # Try to remove existing event detect if any (helps with "Failed to add edge detection")
            try:
                GPIO.remove_event_detect(RESET_BUTTON_PIN)
            except:
                pass
            GPIO.add_event_detect(RESET_BUTTON_PIN, GPIO.FALLING, callback=self._reset_button_callback, bouncetime=500)
            debug_print(f"Reset button active on GPIO {RESET_BUTTON_PIN}", "INFO")
        except Exception as e:
            debug_print(f"Event detection failed for GPIO {RESET_BUTTON_PIN}: {e}. Switching to polling mode.", "WARNING")
            # Fallback to polling
            Thread(target=self._button_polling_loop, daemon=True).start()
        
        # Beep on startup
        self.beep_startup()
        
        # Initial network state check
        try:
            self.update_network_state()
        except:
            pass

        # Initialize Telegram
        self.init_telegram()
        self.start_telegram_command_loop()
        
        # Start LED control thread
        self.start_led_thread()
        
        # Initialize downtime log file
        self.init_downtime_log()
        
        # Check and install LLDP tools if needed
        self.check_and_install_lldp_tools()
        
        # Start LLDP service if needed
        self.start_lldp_service()
    
    def _button_polling_loop(self):
        """Fallback polling loop for reset button"""
        debug_print("Starting button polling loop", "INFO")
        last_state = GPIO.HIGH
        while self.running:
            try:
                current_state = GPIO.input(RESET_BUTTON_PIN)
                # Check for falling edge (HIGH -> LOW)
                if last_state == GPIO.HIGH and current_state == GPIO.LOW:
                    self._reset_button_callback(RESET_BUTTON_PIN)
                    # Simple debounce
                    time.sleep(1.0)
                last_state = current_state
                time.sleep(0.1)
            except Exception as e:
                debug_print(f"Error in button polling: {e}", "ERROR")
                time.sleep(1)

    def _reset_button_callback(self, channel):
        """Handle reset button press: set eth0 and wlan0 to DHCP"""
        debug_print(f"Reset button pressed on channel {channel}. Resetting network to DHCP...", "WARNING")
        
        # Beep to acknowledge press
        self.beep(0.1)
        
        try:
            # Set eth0 to DHCP
            self.set_interface_ip('eth0', method='dhcp')
            debug_print("eth0 set to DHCP", "SUCCESS")
            
            # Set wlan0 to DHCP
            self.set_interface_ip('wlan0', method='dhcp')
            debug_print("wlan0 set to DHCP", "SUCCESS")
            
            # Long beep on success
            self.beep(0.5)
            
            # Force update
            self.update_network_state()
            
        except Exception as e:
            debug_print(f"Error during button reset: {e}", "ERROR")
            # Error beep (3 short beeps)
            for _ in range(3):
                self.beep(0.1)
                time.sleep(0.2)

    def start_telegram_command_loop(self):
        try:
            if not self.telegram_enabled:
                return
            if self.telegram_cmd_thread and self.telegram_cmd_thread.is_alive():
                return
            t = Thread(target=self.telegram_command_loop, daemon=True)
            self.telegram_cmd_thread = t
            t.start()
        except Exception as e:
            debug_print(f"Error starting telegram loop: {e}", "ERROR")
    
    def telegram_command_loop(self):
        # Первичная инициализация offset, чтобы пропустить старые сообщения из очереди
        if self.telegram_update_offset is None:
            try:
                url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/getUpdates"
                # Запрашиваем только последнее сообщение, чтобы получить актуальный offset
                r = requests.get(url, params={'offset': -1, 'limit': 1, 'timeout': 0}, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    results = data.get('result', [])
                    if results:
                        self.telegram_update_offset = results[0]['update_id'] + 1
                        debug_print(f"Telegram offset initialized: {self.telegram_update_offset} (skipping old messages)", "INFO")
            except Exception as e:
                debug_print(f"Error during telegram offset initialization: {e}", "WARNING")

        while self.running:
            try:
                if not self.telegram_enabled or not self.telegram_initialized:
                    time.sleep(2)
                    continue
                url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/getUpdates"
                params = {}
                if self.telegram_update_offset is not None:
                    params['offset'] = self.telegram_update_offset
                params['timeout'] = 20
                r = requests.get(url, params=params, timeout=max(20, self.telegram_timeout + 10), verify=False)
                if r.status_code != 200:
                    time.sleep(1)
                    continue
                data = r.json()
                updates = data.get('result', [])
                for upd in updates:
                    try:
                        uid = upd.get('update_id')
                        if uid is not None:
                            self.telegram_update_offset = uid + 1
                        msg = upd.get('message') or upd.get('edited_message')
                        if not msg:
                            continue
                        chat = msg.get('chat', {})
                        chat_id = str(chat.get('id'))
                        text = msg.get('text') or ""
                        
                        # Handle SFTP uploads (files)
                        if any(k in msg for k in ('document', 'video', 'audio', 'photo')):
                            if self.handle_telegram_file(chat_id, msg):
                                # If handled as a file, we can optionally continue or skip command processing
                                pass
                        
                        if not text:
                            continue
                        # Allow /start and 
                        #  regardless of chat authorization
                        cmd_prefix = (text.strip().split()[0] if text.strip().split() else "").lower()
                        cmd_base = cmd_prefix.split('@', 1)[0]
                        
                        is_authorized = chat_id in self.telegram_chat_ids
                        is_auth_cmd = cmd_base in ("/start", "/help")
                        
                        if not is_authorized and not is_auth_cmd:
                            if not self.telegram_chat_ids:
                                # Special case: first user ever
                                if cmd_base == "/start":
                                    pass # will be handled in handle_telegram_command
                                else:
                                    debug_print(f"Ignoring command {cmd_base} from unauthorized user {chat_id} (no users in set)", "WARNING")
                                    self.send_telegram_message_to(chat_id, "Для начала отправьте /start")
                                    continue
                            else:
                                # Not authorized and not /start or /help
                                debug_print(f"Ignoring command {cmd_base} from unauthorized user {chat_id}", "WARNING")
                                continue
                        
                        self.handle_telegram_command(chat_id, text.strip())
                        if self.restart_pending:
                            break
                    except:
                        pass
                
                if self.restart_pending:
                    # Подтверждаем получение всех сообщений перед перезапуском
                    if self.telegram_update_offset is not None:
                        try:
                            requests.get(url, params={'offset': self.telegram_update_offset, 'timeout': 0}, verify=False)
                        except:
                            pass
                    
                    debug_print("Restarting service by command...", "INFO")
                    try:
                        self.cleanup()
                    except:
                        pass
                    
                    # On Windows, os.execv can leave the old process alive if called from a thread.
                    # We use subprocess.Popen + os._exit for a cleaner restart on all platforms.
                    try:
                        # If we have a GUI app, we should ideally close it properly
                        if hasattr(self, 'gui_app') and self.gui_app:
                            try:
                                # We can't easily call self.gui_app.on_closing() from here because it's a different thread
                                # and might involve GUI calls. But cleanup() was already called.
                                pass
                            except:
                                pass
                        
                        subprocess.Popen([sys.executable] + sys.argv)
                        os._exit(0) # Use os._exit to kill the process immediately from the thread
                    except Exception as e:
                        debug_print(f"Failed to restart via Popen: {e}", "ERROR")
                        os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception as e:
                debug_print(f"Error in telegram loop: {e}", "ERROR")
                time.sleep(1)
    
    def send_telegram_message_to(self, chat_id, message):
        try:
            if not self.telegram_enabled or not self.telegram_initialized:
                return False
            url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/sendMessage"
            params = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }
            r = requests.post(url, data=params, timeout=self.telegram_timeout, verify=False)
            if r.status_code != 200:
                debug_print(f"Telegram send error ({r.status_code}): {r.text}", "ERROR")
            return r.status_code == 200
        except Exception as e:
            debug_print(f"Telegram send exception: {e}", "ERROR")
            return False
    
    def handle_telegram_command(self, chat_id, text):
        debug_print(f"Received Telegram command from {chat_id}: {text}", "INFO")
        try:
            parts = text.split()
            cmd = parts[0].split('@', 1)[0].lower() if parts else ""
            if cmd in ("/start", "start"):
                if chat_id not in self.telegram_chat_ids:
                    self.telegram_chat_ids.add(chat_id)
                    self.save_config()
                    self.send_telegram_message_to(chat_id, "Чат авторизован. Используйте /help для списка команд.")
                else:
                    self.send_telegram_message_to(chat_id, "Вы уже авторизованы.")
                return
            if cmd in ("/help", "help"):
                self.cmd_help(chat_id)
                return
            if cmd in ("/status", "status"):
                self.cmd_status(chat_id)
                return
            if cmd in ("/refresh", "refresh"):
                self.cmd_status(chat_id)
                return
            if cmd in ("/settings", "settings", "/get_settings", "get_settings"):
                self.cmd_settings(chat_id)
                return
            if cmd in ("/restart", "restart"):
                self.cmd_restart(chat_id)
                return
            if cmd in ("/reboot_os", "reboot_os"):
                self.cmd_reboot_os(chat_id)
                return
            if cmd in ("/shutdown_os", "shutdown_os"):
                self.cmd_shutdown_os(chat_id)
                return
            if cmd in ("/nslookup", "nslookup") and len(parts) >= 2:
                self.cmd_nslookup(chat_id, parts[1])
                return
            if cmd in ("/set", "set") and len(parts) >= 2:
                key = parts[1]
                val = " ".join(parts[2:]) if len(parts) > 2 else ""
                self.cmd_set(chat_id, key, val)
                return
            if cmd in ("/chat_add", "chat_add") and len(parts) >= 2:
                cid = str(parts[1])
                if cid not in self.telegram_chat_ids:
                    self.telegram_chat_ids.add(cid)
                    self.save_config()
                self.send_telegram_message_to(chat_id, f"Чат {cid} добавлен")
                return
            if cmd in ("/chat_remove", "chat_remove") and len(parts) >= 2:
                cid = str(parts[1])
                if cid in self.telegram_chat_ids:
                    self.telegram_chat_ids.discard(cid)
                    self.save_config()
                    self.send_telegram_message_to(chat_id, f"Чат {cid} удален")
                else:
                    self.send_telegram_message_to(chat_id, "Чат не найден в списке")
                return
            if cmd in ("/scan_stop", "scan_stop"):
                self.cmd_scan_stop(chat_id)
                return
            if cmd in ("/scan_discover", "scan_discover"):
                target = " ".join(parts[1:]).strip()
                self.cmd_scan_discover(chat_id, target)
                return
            if cmd in ("/scan_quick", "scan_quick", "/quick_scan", "quick_scan"):
                proto = "TCP"
                target_parts = []
                
                # Examine parts from index 1 onwards
                for part in parts[1:]:
                    u_part = part.upper()
                    if u_part in ("TCP", "UDP", "BOTH"):
                        proto = u_part
                    else:
                        target_parts.append(part)
                
                target = ",".join(target_parts) # Join with comma for _parse_targets_text
                self.cmd_scan_quick(chat_id, target, proto)
                return
            if cmd in ("/scan_custom", "scan_custom") and len(parts) >= 3:
                target = parts[1]
                ports = parts[2]
                proto = parts[3].upper() if len(parts) >= 4 else "TCP"
                self.cmd_scan_custom(chat_id, target, ports, proto)
                return
            if cmd in ("/dump", "dump"):
                minutes = 1
                if len(parts) >= 2:
                    try:
                        minutes = int(parts[1])
                    except:
                        pass
                self.cmd_dump(chat_id, minutes)
                return
            if cmd in ("/dump_custom", "dump_custom") and len(parts) >= 6:
                # /dump_custom <PROTO> <SRC_IP> <DST_IP> <SRC_PORT> <DST_PORT> [MINUTES]
                proto = parts[1]
                src_ip = parts[2]
                dst_ip = parts[3]
                src_port = parts[4]
                dst_port = parts[5]
                minutes = 1
                if len(parts) >= 7:
                    try:
                        minutes = int(parts[6])
                    except:
                        pass
                self.cmd_dump_custom(chat_id, proto, src_ip, dst_ip, src_port, dst_port, minutes)
                return
            if cmd in ("/dump_stop", "dump_stop"):
                self.cmd_dump_stop(chat_id)
                return
            if cmd in ("/set_ip_eth0", "set_ip_eth0") and len(parts) >= 2:
                # /set_ip_eth0 <ip> <mask> <gw> [dns] OR /set_ip_eth0 dhcp
                if parts[1].lower() == 'dhcp':
                     self.cmd_set_ip_eth0(chat_id, 'dhcp')
                elif len(parts) >= 4:
                    dns = parts[4] if len(parts) >= 5 else None
                    self.cmd_set_ip_eth0(chat_id, parts[1], parts[2], parts[3], dns)
                else:
                    self.send_telegram_message_to(chat_id, "❌ Формат: /set_ip_eth0 dhcp ИЛИ <ip> <mask> <gw> [dns]")
                return
            if cmd in ("/set_ip_wlan0", "set_ip_wlan0") and len(parts) >= 2:
                # /set_ip_wlan0 <ip> <mask> <gw> [dns] OR /set_ip_wlan0 dhcp
                if parts[1].lower() == 'dhcp':
                     self.cmd_set_ip_wlan0(chat_id, 'dhcp')
                elif len(parts) >= 4:
                    dns = parts[4] if len(parts) >= 5 else None
                    self.cmd_set_ip_wlan0(chat_id, parts[1], parts[2], parts[3], dns)
                else:
                    self.send_telegram_message_to(chat_id, "❌ Формат: /set_ip_wlan0 dhcp ИЛИ <ip> <mask> <gw> [dns]")
                return
            if cmd in ("/set_mac_eth0", "set_mac_eth0") and len(parts) >= 2:
                self.cmd_set_mac_eth0(chat_id, parts[1])
                return
            if cmd in ("/set_mac_wlan0", "set_mac_wlan0") and len(parts) >= 2:
                self.cmd_set_mac_wlan0(chat_id, parts[1])
                return
            
            # SFTP commands
            if cmd in ("/sftp_start", "sftp_start"):
                self.cmd_sftp_start(chat_id)
                return
            if cmd in ("/sftp_stop", "sftp_stop"):
                self.cmd_sftp_stop(chat_id)
                return
            if cmd in ("/sftp_files", "sftp_files"):
                self.cmd_sftp_files(chat_id)
                return
            if cmd in ("/sftp_upload", "sftp_upload"):
                self.cmd_sftp_upload(chat_id)
                return
            if cmd in ("/sftp_download", "sftp_download"):
                self.cmd_sftp_download(chat_id, " ".join(parts[1:]))
                return
            if cmd in ("/sftp_delete", "sftp_delete"):
                self.cmd_sftp_delete(chat_id, " ".join(parts[1:]))
                return
            if cmd in ("/set_sftp_user", "set_sftp_user"):
                self.cmd_set_sftp_user(chat_id, parts[1] if len(parts) > 1 else None)
                return
            if cmd in ("/set_sftp_password", "set_sftp_password"):
                self.cmd_set_sftp_password(chat_id, parts[1] if len(parts) > 1 else None)
                return
            if cmd in ("/set_sftp_port", "set_sftp_port"):
                self.cmd_set_sftp_port(chat_id, parts[1] if len(parts) > 1 else None)
                return
            
            self.send_telegram_message_to(chat_id, "Неизвестная команда. Используйте /help")
        except:
            try:
                self.send_telegram_message_to(chat_id, "Ошибка обработки команды")
            except:
                pass
    
    def cmd_help(self, chat_id):
        msg = []
        msg.append("<b>Команды:</b>")
        msg.append("/status - текущее состояние сети")
        msg.append("/refresh - обновить статус (alias for /status)")
        msg.append("/settings - список текущих настроек")
        msg.append("/set key value - изменить настройку")
        msg.append("/chat_add &lt;id&gt; - добавить ID чата")
        msg.append("/chat_remove &lt;id&gt; - удалить ID чата")
        msg.append("/scan_discover &lt;target&gt; - поиск хостов")
        msg.append("/scan_quick &lt;target&gt; [TCP|UDP|BOTH] - быстрый скан")
        msg.append("/scan_custom &lt;target&gt; &lt;ports&gt; [TCP|UDP|BOTH] - кастомный скан")
        msg.append("/scan_stop - остановить сканирование")
        msg.append("/dump [min] - сбор полного дампа трафика")
        msg.append("/dump_custom &lt;PROTO&gt; &lt;SRC_IP&gt; &lt;DST_IP&gt; &lt;SRC_PORT&gt; &lt;DST_PORT&gt; [min] - кастомный дамп")
        msg.append("/dump_stop - остановить сбор дампа")
        msg.append("/set_ip_eth0 &lt;ip&gt; &lt;mask&gt; &lt;gw&gt; [dns] - статический IP eth0")
        msg.append("/set_ip_wlan0 &lt;ip&gt; &lt;mask&gt; &lt;gw&gt; [dns] - статический IP wlan0")
        msg.append("/set_mac_eth0 &lt;mac&gt; - сменить MAC eth0")
        msg.append("/set_mac_wlan0 &lt;mac&gt; - сменить MAC wlan0")
        msg.append("/nslookup &lt;host&gt; - DNS запрос")
        msg.append("/restart - перезапуск сервиса")
        msg.append("/reboot_os - перезагрузка системы")
        msg.append("/shutdown_os - выключение системы")
        msg.append("")
        msg.append("<b>SFTP Сервер:</b>")
        msg.append("/sftp_start - запустить SFTP сервер")
        msg.append("/sftp_stop - остановить SFTP сервер")
        msg.append("/sftp_files - список файлов на SFTP")
        msg.append("/sftp_upload - режим загрузки файлов")
        msg.append("/sftp_download &lt;file&gt; - скачать файл")
        msg.append("/sftp_delete &lt;file&gt; - удалить файл")
        msg.append("/set_sftp_user &lt;user&gt; - имя пользователя SFTP")
        msg.append("/set_sftp_password &lt;pass&gt; - пароль SFTP")
        msg.append("/set_sftp_port &lt;port&gt; - порт SFTP")
        msg.append("\n<b>Примеры /set:</b>")
        msg.append("<code>/set debug_enabled true</code>")
        msg.append("<code>/set check_interval 5</code>")
        msg.append("<code>/set monitor_eth0 off</code>")
        msg.append("<code>/set nmap_workers 10</code>")
        self.send_telegram_message_to(chat_id, "\n".join(msg))
    
    def cmd_restart(self, chat_id):
        debug_print("Command: /restart triggered via Telegram", "INFO")
        self.send_telegram_message_to(chat_id, "🔄 Перезапуск сервиса...")
        self.restart_pending = True
    
    def cmd_reboot_os(self, chat_id):
        debug_print("Command: /reboot_os triggered via Telegram", "INFO")
        self.send_telegram_message_to(chat_id, "🔄 Перезагрузка системы...")
        try:
            # Гарантируем сохранение настроек перед перезагрузкой
            debug_print("Saving config before reboot...", "INFO")
            saved = self.save_config()
            
            # Подтверждаем получение сообщения и статус сохранения
            if self.telegram_update_offset is not None:
                try:
                    status_msg = "✅ Настройки сохранены. " if saved else f"⚠️ Ошибка сохранения: {self.last_save_error}. "
                    self.send_telegram_message_to(chat_id, status_msg + "Перезагрузка через 5 секунд...")
                    
                    url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/getUpdates"
                    requests.get(url, params={'offset': self.telegram_update_offset, 'timeout': 0}, verify=False)
                except:
                    pass
            
            # Даем время сообщению отправиться и системе "продышаться"
            time.sleep(5)
            # Linux soft reboot
            os.system("reboot")
        except Exception as e:
            debug_print(f"Error during reboot: {e}", "ERROR")
            self.send_telegram_message_to(chat_id, f"❌ Ошибка при перезагрузке: {e}")

    def cmd_shutdown_os(self, chat_id):
        debug_print("Command: /shutdown_os triggered via Telegram", "INFO")
        self.send_telegram_message_to(chat_id, "🔌 Выключение системы...")
        try:
            # Гарантируем сохранение настроек перед выключением
            debug_print("Saving config before shutdown...", "INFO")
            saved = self.save_config()
            
            # Подтверждаем получение сообщения и статус сохранения
            if self.telegram_update_offset is not None:
                try:
                    status_msg = "✅ Настройки сохранены. " if saved else f"⚠️ Ошибка сохранения: {self.last_save_error}. "
                    self.send_telegram_message_to(chat_id, status_msg + "Завершение работы через 5 секунд...")
                    
                    url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/getUpdates"
                    requests.get(url, params={'offset': self.telegram_update_offset, 'timeout': 0}, verify=False)
                except:
                    pass
            
            # Даем время сообщению отправиться и системе "продышаться"
            time.sleep(5)
            # Linux soft shutdown
            os.system("shutdown -h now")
        except Exception as e:
            debug_print(f"Error during shutdown: {e}", "ERROR")
            self.send_telegram_message_to(chat_id, f"❌ Ошибка при выключении: {e}")

    def cmd_nslookup(self, chat_id, host):
        debug_print(f"Command: /nslookup {host} triggered", "INFO")
        if not host:
            self.send_telegram_message_to(chat_id, "❌ Укажите хост: /nslookup <ip_or_domain>")
            return

        try:
            result = []
            host = host.strip()
            
            # Try to determine if input is IP or Domain
            is_ip = False
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False
            
            result.append(f"<b>NSLOOKUP: {host}</b>")
            
            # 1. System Resolver (Default)
            result.append("\n<b>System Resolver:</b>")
            if is_ip:
                # Reverse lookup (IP -> Hostname)
                try:
                    hostname, aliases, _ = socket.gethostbyaddr(host)
                    result.append(f"PTR: <code>{hostname}</code>")
                    if aliases:
                        result.append(f"Aliases: {', '.join(aliases)}")
                except socket.herror:
                    result.append("PTR: Не найдено (NXDOMAIN)")
                except Exception as e:
                    result.append(f"Ошибка PTR: {e}")
            else:
                # Forward lookup (Hostname -> IP)
                try:
                    # Get all addresses (IPv4 and IPv6)
                    addr_info = socket.getaddrinfo(host, None)
                    seen_ips = set()
                    
                    for family, _, _, _, sockaddr in addr_info:
                        ip = sockaddr[0]
                        if ip in seen_ips:
                            continue
                        seen_ips.add(ip)
                        
                        if family == socket.AF_INET:
                            result.append(f"A: <code>{ip}</code>")
                        elif family == socket.AF_INET6:
                            result.append(f"AAAA: <code>{ip}</code>")
                            
                except socket.gaierror:
                    result.append("Ошибка: Хост не найден (NXDOMAIN)")
                except Exception as e:
                    result.append(f"Ошибка A/AAAA: {e}")

            # 2. Check specific DNS servers
            dns_servers_info = self.get_dns_servers()
            if dns_servers_info and dns_servers_info != ['None']:
                result.append(f"\n<b>Specific DNS Servers ({len(dns_servers_info)}):</b>")
                
                # Check if dig is available
                has_dig = shutil.which("dig") is not None
                
                for dns_info in dns_servers_info:
                    dns = dns_info.get('server')
                    iface = dns_info.get('interface', 'Unknown')
                    if not dns or dns == 'None': continue
                    
                    try:
                        res_lines = []
                        if has_dig:
                            # Use dig for specific server query
                            cmd = ["dig", f"@{dns}", "+short", "+time=2", "+tries=1"]
                            if is_ip:
                                cmd.append("-x")
                            cmd.append(host)
                            
                            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                            output = proc.stdout.strip()
                            
                            if proc.returncode == 0 and output:
                                # Dig returns just the answers with +short
                                answers = [line.strip() for line in output.split('\n') if line.strip()]
                                if answers:
                                    res_lines.append(f"✅ OK: {', '.join(answers)}")
                                else:
                                    res_lines.append("⚠️ No answer")
                            else:
                                res_lines.append("❌ Failed/Timeout")
                        else:
                            # Fallback to nslookup tool if available
                            if shutil.which("nslookup"):
                                cmd = ["nslookup", host, dns]
                                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                                if proc.returncode == 0:
                                    # Very basic parsing
                                    if "Address:" in proc.stdout or "name =" in proc.stdout:
                                        res_lines.append("✅ OK (Resolved)")
                                    else:
                                        res_lines.append("⚠️ No answer")
                                else:
                                     res_lines.append("❌ Failed")
                            else:
                                res_lines.append("⚠️ 'dig'/'nslookup' tools missing")
                                
                        result.append(f"<b>{iface} ({dns}):</b> {' '.join(res_lines)}")
                        
                    except Exception as e:
                        result.append(f"<b>{iface} ({dns}):</b> ❌ Error: {str(e)}")
            else:
                 result.append("\n⚠️ Системные DNS серверы не обнаружены")

            self.send_telegram_message_to(chat_id, "\n".join(result))
            
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка выполнения nslookup: {e}")

    def cmd_status(self, chat_id):
        debug_print("Command: /status requested", "INFO")
        try:
            st = dict(self.current_state)
            st['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = self.format_state_for_telegram(st)
            self.send_telegram_message_to(chat_id, msg)
        except:
            self.send_telegram_message_to(chat_id, "Ошибка формирования статуса")
    
    def cmd_settings(self, chat_id):
        try:
            cfg_path = self.get_config_path()
            
            vals = []
            vals.append("<b>⚙️ ТЕКУЩИЕ НАСТРОЙКИ</b>")
            vals.append(f"📍 Конфиг: <code>{cfg_path}</code>")
            vals.append("")
            vals.append(f"<code>telegram_enabled</code>: {self.telegram_enabled}")
            vals.append(f"<code>telegram_notify_on_change</code>: {self.telegram_notify_on_change}")
            vals.append(f"<code>downtime_notifications</code>: {self.downtime_report_on_recovery}")
            vals.append(f"<code>monitor_eth0</code>: {self.monitor_eth0}")
            vals.append(f"<code>monitor_wlan0</code>: {self.monitor_wlan0}")
            vals.append(f"<code>lldp_enabled</code>: {self.lldp_enabled}")
            vals.append(f"<code>lldp_eth0</code>: {getattr(self, 'lldp_eth0', True)}")
            vals.append(f"<code>lldp_wlan0</code>: {getattr(self, 'lldp_wlan0', True)}")
            vals.append(f"<code>auto_scan_on_network_up</code>: {self.auto_scan_on_network_up}")
            vals.append(f"<code>check_interval</code>: {self.check_interval}")
            vals.append(f"<code>nmap_workers</code>: {getattr(self, 'nmap_workers', 8)}")
            vals.append(f"<code>ttl_interfaces</code>: {self.ttl_interfaces}")
            vals.append(f"<code>ttl_dns_servers</code>: {self.ttl_dns_servers}")
            vals.append(f"<code>ttl_dns_status</code>: {self.ttl_dns_status}")
            vals.append(f"<code>ttl_gateway</code>: {self.ttl_gateway}")
            vals.append(f"<code>ttl_external_ip</code>: {self.ttl_external_ip}")
            
            self.send_telegram_message_to(chat_id, "\n".join(vals))
        except Exception as e:
            debug_print(f"Error in cmd_settings: {e}", "ERROR")
            self.send_telegram_message_to(chat_id, "Ошибка получения настроек")
    
    def get_config_path(self):
        """Get the most appropriate configuration file path with fallback"""
        # 1. Base path: same directory as the script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cfg_path = os.path.join(base_dir, 'nwscan_config.json')
        
        # 2. If base_dir is not writable (e.g., /usr/local/bin), use user home
        if not os.access(base_dir, os.W_OK) or (os.path.exists(cfg_path) and not os.access(cfg_path, os.W_OK)):
            home_dir = os.path.expanduser("~")
            config_home = os.environ.get('XDG_CONFIG_HOME', os.path.join(home_dir, '.config'))
            app_config_dir = os.path.join(config_home, 'nwscan')
            
            try:
                os.makedirs(app_config_dir, exist_ok=True)
                user_cfg_path = os.path.join(app_config_dir, 'nwscan_config.json')
                
                # Migrate existing config if it's readable but not writable in original location
                if os.path.exists(cfg_path) and not os.path.exists(user_cfg_path):
                    try:
                        import shutil
                        shutil.copy2(cfg_path, user_cfg_path)
                        debug_print(f"Migrated config to user home: {user_cfg_path}", "INFO")
                    except:
                        pass
                
                return user_cfg_path
            except:
                # Last resort fallback to /tmp or similar if even home is not writable (unlikely)
                return cfg_path
                
        return cfg_path

    def save_config(self):
        self.last_save_error = None
        # Используем блокировку для предотвращения одновременной записи из разных потоков одного процесса
        with self.lock:
            try:
                cfg_path = self.get_config_path()
                base_dir = os.path.dirname(cfg_path)
                
                settings = {
                    'lldp_enabled': self.lldp_enabled,
                    'lldp_eth0': getattr(self, 'lldp_eth0', True),
                    'lldp_wlan0': getattr(self, 'lldp_wlan0', True),
                    'cdp_enabled': getattr(self, 'cdp_enabled', self.lldp_enabled),
                    'telegram_enabled': self.telegram_enabled,
                    'downtime_notifications': self.downtime_report_on_recovery,
                    'debug_enabled': self.debug_enabled,
                    'debug_lldp': self.debug_lldp,
                    'monitor_eth0': self.monitor_eth0,
                    'monitor_wlan0': self.monitor_wlan0,
                    'check_interval': int(self.check_interval),
                    'lldp_recheck_interval': int(self.lldp_recheck_interval),
                    'ttl_interfaces': int(self.ttl_interfaces),
                    'ttl_dns_servers': int(self.ttl_dns_servers),
                    'ttl_dns_status': int(self.ttl_dns_status),
                    'ttl_gateway': int(self.ttl_gateway),
                    'ttl_external_ip': int(self.ttl_external_ip),
                    'telegram_token': str(self.telegram_bot_token or ""),
                    'telegram_api_url': str(self.telegram_api_base_url or "https://api.telegram.org"),
                    'telegram_chat_ids': list(self.telegram_chat_ids),
                    'telegram_notify_on_change': self.telegram_notify_on_change,
                    'nmap_max_workers': int(getattr(self, 'nmap_workers', 8)),
                    'auto_scan_on_network_up': self.auto_scan_on_network_up,
                    'sftp_enabled': getattr(self, 'sftp_enabled', False),
                    'sftp_user': getattr(self, 'sftp_user', "admin"),
                    'sftp_password': getattr(self, 'sftp_password', "password"),
                    'sftp_port': int(getattr(self, 'sftp_port', 2222))
                }
                
                # Try to save to file with retries (for Windows file locking)
                file_saved = False
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        # 1. Проверяем права доступа для диагностики
                        if os.path.exists(cfg_path):
                            if not os.access(cfg_path, os.W_OK):
                                try:
                                    os.chmod(cfg_path, 0o666)
                                except:
                                    pass
                        
                        # 2. Пытаемся записать во временный файл и переименовать (атомарная запись)
                        temp_path = cfg_path + ".tmp"
                        with open(temp_path, 'w', encoding='utf-8') as f:
                            json.dump(settings, f, indent=4)
                            f.flush()
                            try:
                                os.fsync(f.fileno())
                            except:
                                pass
                        
                        # Используем os.replace
                        try:
                            os.replace(temp_path, cfg_path)
                        except Exception as e_replace:
                            if os.path.exists(cfg_path):
                                try:
                                    os.remove(cfg_path)
                                except:
                                    pass
                            os.rename(temp_path, cfg_path)
                        
                        # Сброс буферов директории (Linux)
                        if os.name != 'nt':
                            try:
                                fd = os.open(base_dir, os.O_RDONLY)
                                os.fsync(fd)
                                os.close(fd)
                            except:
                                pass
                        
                        file_saved = True
                        debug_print(f"Config successfully saved and synced to {cfg_path}", "INFO")
                        break # Success!
                    except Exception as e:
                        self.last_save_error = str(e)
                        debug_print(f"Save attempt {attempt+1} failed: {e}", "WARNING")
                        if attempt < max_retries - 1:
                            time.sleep(0.2) # Wait and retry
                        else:
                            # Final attempt: direct write
                            try:
                                with open(cfg_path, 'w', encoding='utf-8') as f:
                                    json.dump(settings, f, indent=4)
                                    f.flush()
                                    os.fsync(f.fileno())
                                file_saved = True
                                self.last_save_error = None
                                debug_print(f"Config saved via direct write fallback", "INFO")
                            except Exception as e2:
                                self.last_save_error = f"Atomic failed: {e}, Direct failed: {e2}"
                                debug_print(f"All save attempts failed: {e2}", "ERROR")

                # Always call callback if possible to sync GUI
                if self.config_callback:
                    try:
                        self.config_callback(settings)
                    except Exception as e:
                        debug_print(f"Error in config callback: {e}", "ERROR")
                
                return file_saved
            except Exception as e:
                self.last_save_error = str(e)
                debug_print(f"Error in save_config: {e}", "ERROR")
                return False
    
    def cmd_set(self, chat_id, key, val):
        ok = True
        try:
            # Handle key=val in first argument
            if "=" in key and not val:
                k, v = key.split("=", 1)
                key, val = k.strip(), v.strip()

            debug_print(f"Telegram set command from {chat_id}: key={key}, val={val}", "INFO")
            
            # 1. Boolean parameters
            bool_keys = (
                "telegram_enabled", "downtime_notifications", "monitor_eth0", 
                "monitor_wlan0", "lldp_enabled", "cdp_enabled", 
                "telegram_notify_on_change", "auto_scan_on_network_up",
                "lldp_eth0", "lldp_wlan0"
            )
            
            # 2. Integer parameters
            int_keys = (
                "check_interval", "ttl_interfaces", "ttl_dns_servers", 
                "ttl_dns_status", "ttl_gateway", "ttl_external_ip",
                "nmap_workers", "nmap_max_workers"
            )

            if key in bool_keys:
                b = str(val).strip().lower() in ("1", "true", "yes", "on")
                target_attr = "downtime_report_on_recovery" if key == "downtime_notifications" else key
                setattr(self, target_attr, b)
                debug_print(f"Set boolean {target_attr} = {b}", "INFO")
                
                # Special logic for some bool keys
                if key == "telegram_enabled":
                    if b and not self.telegram_initialized: self.init_telegram()
                    if not b: self.telegram_initialized = False
                if key == "lldp_enabled" and b:
                    try: self.start_lldp_service()
                    except: pass
                    
            elif key in int_keys:
                try:
                    v = int(str(val).strip())
                    if "nmap" in key:
                        v = max(1, min(64, v))
                        self.nmap_workers = v
                        debug_print(f"Set nmap_workers = {v}", "INFO")
                    else:
                        setattr(self, key, max(1, v))
                        debug_print(f"Set integer {key} = {max(1, v)}", "INFO")
                except ValueError:
                    self.send_telegram_message_to(chat_id, f"❌ Значение {val} должно быть числом")
                    return
                    
            elif key == "telegram_token":
                self.telegram_bot_token = str(val).strip()
                self.telegram_initialized = False
                self.init_telegram()
                debug_print(f"Set telegram_token", "INFO")
                
            elif key == "telegram_chat_ids":
                # Expecting comma separated IDs
                try:
                    ids = [str(i.strip()) for i in str(val).split(",") if i.strip()]
                    self.telegram_chat_ids = set(ids)
                    debug_print(f"Set telegram_chat_ids: {self.telegram_chat_ids}", "INFO")
                except:
                    self.send_telegram_message_to(chat_id, "❌ Ошибка в формате ID чатов")
                    return
            else:
                ok = False

            if ok:
                saved = self.save_config()
                
                # Get current value for confirmation
                target_attr = "downtime_report_on_recovery" if key == "downtime_notifications" else (
                    "nmap_workers" if "nmap" in key else key
                )
                try:
                    cur_val = getattr(self, target_attr, val)
                except:
                    cur_val = val

                if not saved:
                    debug_print("Failed to save config in cmd_set", "ERROR")
                    base_dir = os.path.dirname(os.path.abspath(__file__))
                    cfg_path = os.path.join(base_dir, 'nwscan_config.json')
                    writable = os.access(base_dir, os.W_OK)
                    exists = os.path.exists(cfg_path)
                    file_writable = os.access(cfg_path, os.W_OK) if exists else "N/A"
                    
                    err_details = f"Dir writable: {writable}, File exists: {exists}, File writable: {file_writable}"
                    if self.last_save_error:
                        err_details += f"\nОшибка: {self.last_save_error}"
                    
                    self.send_telegram_message_to(chat_id, f"⚠️ Настройка {key} применена в памяти ({cur_val}), но НЕ СОХРАНЕНА в файл!\n\nДиагностика: <code>{err_details}</code>\nПуть: <code>{cfg_path}</code>")
                    return

                self.send_telegram_message_to(chat_id, f"✅ Настройка {key} установлена и сохранена: {cur_val}")
                debug_print(f"Successfully set and saved {key}={cur_val}", "INFO")
            else:
                self.send_telegram_message_to(chat_id, f"❌ Неизвестный параметр: {key}")
                debug_print(f"Unknown parameter: {key}", "WARNING")
                
        except Exception as e:
            debug_print(f"Error in cmd_set: {e}", "ERROR")
            self.send_telegram_message_to(chat_id, f"⚠️ Ошибка применения параметра: {e}")
    
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
    
    def cmd_scan_stop(self, chat_id):
        debug_print("Command: /scan_stop triggered", "INFO")
        try:
            self.nmap_stop_event.set()
            self._kill_nmap_procs()
            try:
                if self.nmap_thread:
                    self.nmap_thread.join(timeout=1)
            except:
                pass
            self.send_telegram_message_to(chat_id, "Сканирование остановлено")
        except:
            self.send_telegram_message_to(chat_id, "Ошибка остановки сканирования")
    
    def _parse_nmap_open_ports(self, output):
        """Extract open ports from nmap output"""
        ports = []
        if not output:
            return ports
        for line in output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                if 'open' in line:
                    parts = line.split('/')
                    if parts:
                        try:
                            port = int(parts[0].strip())
                            ports.append(port)
                        except:
                            pass
        return sorted(list(set(ports)))

    def _parse_targets_text(self, text):
        val = str(text or "").strip()
        if not val:
            return self._get_fallback_ips()
            
        # Split by comma or space
        raw_parts = re.split(r'[,\s]+', val)
        ips = []
        
        for part in raw_parts:
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part and "/" not in part:
                    start_str, end_str = part.split("-", 1)
                    start_str = start_str.strip()
                    end_str = end_str.strip()
                    
                    if "." not in end_str:
                        # 192.168.1.1-10
                        parts = start_str.split(".")
                        if len(parts) == 4:
                            prefix = ".".join(parts[:3])
                            start_last = int(parts[3])
                            end_last = int(end_str)
                            if start_last > end_last:
                                start_last, end_last = end_last, start_last
                            for i in range(start_last, end_last + 1):
                                if 0 <= i <= 255:
                                    ips.append(f"{prefix}.{i}")
                    else:
                        # 192.168.1.1-192.168.1.10
                        start_ip = ipaddress.ip_address(start_str)
                        end_ip = ipaddress.ip_address(end_str)
                        if int(end_ip) < int(start_ip):
                            start_ip, end_ip = end_ip, start_ip
                        cur = int(start_ip)
                        end = int(end_ip)
                        while cur <= end and len(ips) < 2048:
                            ips.append(str(ipaddress.ip_address(cur)))
                            cur += 1
                elif "/" in part:
                    net = ipaddress.ip_network(part, strict=False)
                    for ip in net.hosts():
                        if len(ips) < 2048:
                            ips.append(str(ip))
                else:
                    # Single IP
                    ipaddress.ip_address(part)
                    ips.append(part)
            except:
                continue
                
        if not ips:
            return self._get_fallback_ips()
            
        # Unique IPs
        seen = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                unique_ips.append(ip)
                seen.add(ip)
        return unique_ips[:2048]

    def _get_progress_bar(self, current, total, width=20):
        if total <= 0:
            return "." * width
        filled = int(width * current / total)
        bar = '★' * filled + '·' * (width - filled)
        return f"|{bar}|"

    def _notify_scan_progress(self, chat_id, scan_name, processed, total):
        """Отправляет уведомление о прогрессе в Telegram (вспомогательная функция)"""
        try:
            bar = self._get_progress_bar(processed, total)
            percent = int((processed / total) * 100) if total > 0 else 0
            self.send_telegram_message_to(chat_id, f"⏳ {scan_name}: {processed}/{total} {bar} {percent}%")
        except:
            pass

    def _get_fallback_ips(self):
        ips = []
        subnet = None
        try:
            # 1. Пробуем получить из текущего состояния интерфейсов
            interfaces = self.current_state.get('interfaces', [])
            for iface in interfaces:
                if isinstance(iface, dict) and not iface.get('name', '').startswith('lo'):
                    for ip_info in iface.get('ip_addresses', []):
                        cidr = ip_info.get('cidr')
                        if cidr and ':' not in cidr: # Только IPv4
                            try:
                                net = ipaddress.ip_network(cidr, strict=False)
                                if not net.is_loopback:
                                    subnet = net
                                    break
                            except:
                                continue
                    if subnet:
                        break
            
            # 2. Фолбэк на определение через socket
            if not subnet:
                local_ip = self.get_local_ip()
                if local_ip and not local_ip.startswith('127.'):
                    try:
                        ip_parts = local_ip.split('.')
                        if len(ip_parts) == 4:
                            subnet_str = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                            subnet = ipaddress.ip_network(subnet_str, strict=False)
                    except:
                        pass
        except Exception as e:
            debug_print(f"Error in _get_fallback_ips: {e}", "ERROR")
            subnet = None
        
        if subnet:
            # Generate hosts list (limit to 2048 to support up to /21 subnets)
            try:
                hosts = list(subnet.hosts())
                for ip in hosts:
                    if len(ips) >= 2048:
                        break
                    ips.append(str(ip))
            except:
                pass
        return ips
    
    def _ping_host(self, ip):
        try:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return r.returncode == 0
        except:
            return False
    
    def cmd_scan_discover(self, chat_id, target_text):
        debug_print(f"Command: /scan_discover {target_text} triggered", "INFO")
        self.beep_notify()
        def task():
            try:
                self.scanning_in_progress = True
                self.update_network_state()
                
                ips = self._parse_targets_text(target_text)
                if not ips:
                    self.send_telegram_message_to(chat_id, "Цели не найдены")
                    return
                live = []
                total = len(ips)
                processed = 0
                last_notify_time = time.time()
                
                def notify():
                    nonlocal last_notify_time
                    now = time.time()
                    if now - last_notify_time >= 10:
                        last_notify_time = now
                        self._notify_scan_progress(chat_id, "Discovery", processed, total)

                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_workers) as ex:
                        futs = {ex.submit(self._ping_host, ip): ip for ip in ips}
                        for f in concurrent.futures.as_completed(futs):
                            if self.nmap_stop_event.is_set():
                                break
                            ip = futs[f]
                            processed += 1
                            try:
                                up = f.result()
                                if up:
                                    live.append(ip)
                            except:
                                pass
                            notify()
                            time.sleep(0.01) # Small delay to reduce CPU spike during large scans
                except:
                    pass
                
                msg = ["<b>NMAP DISCOVERY</b>"]
                msg.append(f"Targets: {total}")
                msg.append(f"Up hosts: {len(live)}")
                if live:
                    msg.append("Hosts:")
                    # Sort for readability
                    try:
                        sorted_live = sorted(live, key=lambda x: ipaddress.ip_address(x))
                    except:
                        sorted_live = sorted(live)
                    for h in sorted_live:
                        msg.append(f" • {h}")
                self.send_telegram_message_to(chat_id, "\n".join(msg))
            
            except Exception as e:
                debug_print(f"Scan error: {e}", "ERROR")
            finally:
                self.scanning_in_progress = False
                self.update_network_state()

        try:
            self.nmap_stop_event.clear()
            t = Thread(target=task, daemon=True)
            self.nmap_thread = t
            t.start()
            self.send_telegram_message_to(chat_id, "🔍 Поиск активных хостов запущен...")
        except:
            self.send_telegram_message_to(chat_id, "Ошибка запуска сканирования")
    
    def _run_nmap_single(self, ip, ports, proto):
        ports_str = ",".join(str(p) for p in ports)
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
            return out
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
            return ""
        except:
            return ""
        finally:
            if proc:
                self._unregister_nmap_proc(proc)
    
    def _run_nmap_cli_batch(self, ips, ports, proto):
        results = []
        ports_str = ",".join(str(p) for p in ports)
        def worker(ip):
            if self.nmap_stop_event.is_set():
                return None
            out = self._run_nmap_single(ip, ports, proto)
            return (ip, out)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_workers) as ex:
                futs = [ex.submit(worker, ip) for ip in ips]
                for f in concurrent.futures.as_completed(futs):
                    try:
                        res = f.result()
                        if res:
                            results.append(res)
                    except:
                        pass
        except:
            pass
        return results
    
    def cmd_scan_quick(self, chat_id, target_text, proto):
        debug_print(f"Command: /scan_quick {target_text} ({proto}) triggered", "INFO")
        self.beep_notify()
        def task():
            try:
                self.scanning_in_progress = True
                self.update_network_state()
                
                ips = self._parse_targets_text(target_text)
                if not ips:
                    self.send_telegram_message_to(chat_id, "Цели не найдены")
                    return
                common = [21,22,23,25,53,80,110,139,143,443,445,587,993,995,3306,5432,8080,8443]
                use_cli = shutil.which("nmap") is not None
                total = len(ips)
                processed = 0
                start_time = time.time()
                last_notify_time = start_time
                
                results = [] # List of (ip, open_ports)
                
                def notify_progress():
                    nonlocal last_notify_time
                    now = time.time()
                    if now - last_notify_time >= 10:
                        last_notify_time = now
                        self._notify_scan_progress(chat_id, "Quick Scan", processed, total)

                if use_cli:
                    # Use multi-threaded batch scan for CLI
                    msg = ["<b>NMAP QUICK SCAN</b>"]
                    msg.append(f"Targets: {total}")
                    msg.append(f"Protocol: {proto}")
                    
                    # We need to track progress inside _run_nmap_cli_batch or implement it here
                    # To keep it simple and effective, we'll implement the loop here
                    def scan_worker(ip):
                        if self.nmap_stop_event.is_set():
                            return None
                        out = self._run_nmap_single(ip, common, proto)
                        return (ip, out)

                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_workers) as executor:
                        future_to_ip = {executor.submit(scan_worker, ip): ip for ip in ips}
                        for future in concurrent.futures.as_completed(future_to_ip):
                            if self.nmap_stop_event.is_set():
                                break
                            res = future.result()
                            processed += 1
                            if res:
                                ip, out = res
                                open_ports = self._parse_nmap_open_ports(out)
                                if open_ports:
                                    results.append((ip, open_ports))
                            notify_progress()
                    
                    if results:
                        # Sort results by IP address
                        try:
                            results.sort(key=lambda x: ipaddress.ip_address(x[0]))
                        except:
                            results.sort()
                            
                        for ip, ports in results:
                            msg.append(f" • {ip}: {', '.join(str(p) for p in ports)}")
                    else:
                        msg.append("No open common ports found")
                    
                    self.send_telegram_message_to(chat_id, "\n".join(msg))
                    return

                # Fallback to internal socket scanner (also multi-threaded)
                msg = ["<b>QUICK SCAN</b>"]
                msg.append(f"Targets: {total}")
                msg.append(f"Protocol: {proto}")
                
                def internal_worker(ip):
                    if self.nmap_stop_event.is_set():
                        return None
                    found_ports = []
                    if proto in ("TCP", "BOTH"):
                        p_tcp = self._scan_ports_quick(ip, common)
                        if p_tcp:
                            found_ports.extend([f"{p}/tcp" for p in p_tcp])
                    if proto in ("UDP", "BOTH"):
                        p_udp = self._scan_udp_quick(ip, common)
                        if p_udp:
                            found_ports.extend([f"{p}/udp" for p in p_udp])
                    return (ip, found_ports) if found_ports else None

                with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_workers) as executor:
                    future_to_ip = {executor.submit(internal_worker, ip): ip for ip in ips}
                    for future in concurrent.futures.as_completed(future_to_ip):
                        if self.nmap_stop_event.is_set():
                            break
                        res = future.result()
                        processed += 1
                        if res:
                            results.append(res)
                        notify_progress()

                if results:
                    # Sort results by IP address
                    try:
                        results.sort(key=lambda x: ipaddress.ip_address(x[0]))
                    except:
                        results.sort()
                        
                    for ip, ports in results:
                        msg.append(f" • {ip}: {', '.join(ports)}")
                else:
                    msg.append("No open ports detected")
                
                self.send_telegram_message_to(chat_id, "\n".join(msg))
            except Exception as e:
                debug_print(f"Scan error: {e}", "ERROR")
            finally:
                self.scanning_in_progress = False
                self.update_network_state()

        try:
            self.nmap_stop_event.clear()
            t = Thread(target=task, daemon=True)
            self.nmap_thread = t
            t.start()
            self.send_telegram_message_to(chat_id, "🚀 Запущено многопоточное сканирование...")
        except:
            self.send_telegram_message_to(chat_id, "Ошибка запуска сканирования")
    
    def _scan_ports_quick(self, ip, ports):
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
    
    def _scan_udp_quick(self, ip, ports):
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
    
    def cmd_dump(self, chat_id, minutes):
        debug_print(f"Command: /dump {minutes}m triggered", "INFO")
        
        # Check if tcpdump is available
        if not shutil.which("tcpdump"):
            self.send_telegram_message_to(chat_id, "❌ Утилита 'tcpdump' не найдена. Установите её: sudo apt install tcpdump")
            return

        if self.dump_in_progress:
            self.send_telegram_message_to(chat_id, "⚠️ Сбор дампа уже запущен. Остановите его с помощью /dump_stop")
            return
            
        minutes = max(1, min(60, minutes)) # Limit 1-60 mins
        
        # Run in background
        Thread(target=self._run_dump_task, args=(chat_id, minutes), daemon=True).start()
        
    def cmd_dump_custom(self, chat_id, proto, src_ip, dst_ip, src_port, dst_port, minutes=1):
        debug_print(f"Command: /dump_custom {proto} {src_ip} {dst_ip} {src_port} {dst_port} {minutes}m triggered", "INFO")
        
        # Check if tcpdump is available
        if not shutil.which("tcpdump"):
            self.send_telegram_message_to(chat_id, "❌ Утилита 'tcpdump' не найдена")
            return

        if self.dump_in_progress:
            self.send_telegram_message_to(chat_id, "⚠️ Сбор дампа уже запущен. Остановите его с помощью /dump_stop")
            return

        filters = []
        
        # Protocol
        p = proto.lower()
        if p in ('tcp', 'udp'):
            filters.append(p)
        
        # IPs logic
        sip = src_ip.lower()
        dip = dst_ip.lower()
        has_src = sip not in ('any', '0.0.0.0')
        has_dst = dip not in ('any', '0.0.0.0')

        if has_src and has_dst and sip == dip:
            if filters: filters.append("and")
            filters.extend(["host", src_ip])
        else:
            if has_src:
                if filters: filters.append("and")
                filters.extend(["src", "host", src_ip])
            if has_dst:
                if filters: filters.append("and")
                filters.extend(["dst", "host", dst_ip])
            
        # Ports logic
        sp = src_port.lower()
        dp = dst_port.lower()
        if sp != 'any':
            if filters: filters.append("and")
            filters.extend(["src", "port", src_port])
            
        if dp != 'any':
            if filters: filters.append("and")
            filters.extend(["dst", "port", dst_port])
        
        # Duration limit
        minutes = max(1, min(60, minutes))
        
        Thread(target=self._run_dump_task, args=(chat_id, minutes, filters), daemon=True).start()

    def cmd_dump_stop(self, chat_id):
        debug_print("Command: /dump_stop triggered", "INFO")
        if self.dump_process and self.dump_process.poll() is None:
            self.send_telegram_message_to(chat_id, "🛑 Остановка сбора дампа...")
            self.dump_stop_event.set()
        else:
            self.send_telegram_message_to(chat_id, "⚠️ Активный сбор дампа не найден")




    def _run_dump_task(self, chat_id, minutes, filter_args=None):
        try:
            self.dump_in_progress = True
            self.update_network_state()
            
            self.dump_stop_event.clear()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dump_{timestamp}.pcap"
            filepath = os.path.join(os.getcwd(), filename)
            
            filter_str = " ".join(filter_args) if filter_args else "no_filter"
            self.send_telegram_message_to(chat_id, f"🦈 Запущен сбор дампа трафика на {minutes} мин...\nФильтр: {filter_str}\nФайл: {filename}")
            
            # Start tcpdump
            # -i any: all interfaces
            # -w file: write to file
            # -U: packet-buffered (immediate write)
            # -n: no DNS lookups
            cmd = ["tcpdump", "-i", "any", "-U", "-n", "-w", filepath]
            
            # Add filters if provided
            if filter_args:
                # Joining filter tokens into a single string is safer for tcpdump via subprocess
                cmd.append(" ".join(filter_args))
            
            # Using subprocess directly to allow killing later
            # Capture stderr to debug potential filter issues
            self.dump_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            
            # Wait for duration or stop event
            self.dump_stop_event.wait(minutes * 60)
            
            # Stop capture
            stderr_output = ""
            if self.dump_process:
                if self.dump_process.poll() is None:
                    self.dump_process.terminate()
                    try:
                        _, stderr_output = self.dump_process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.dump_process.kill()
                        _, stderr_output = self.dump_process.communicate()
                    except Exception as e:
                        debug_print(f"Error communicating with tcpdump: {e}", "ERROR")
                else:
                    _, stderr_output = self.dump_process.communicate()
                self.dump_process = None
            
            # Verify file
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                size_mb = os.path.getsize(filepath) / (1024*1024)
                caption = f"📦 Дамп трафика (завершено)\nРазмер: {size_mb:.2f} MB"
                
                self.send_telegram_message_to(chat_id, "📤 Отправка файла...")
                if self.send_telegram_document(chat_id, filepath, caption):
                    pass # Success
                else:
                    self.send_telegram_message_to(chat_id, "❌ Ошибка отправки файла")
                
                # Cleanup
                try:
                    os.remove(filepath)
                    debug_print(f"Deleted dump file {filepath}", "INFO")
                except:
                    pass
            else:
                error_msg = "⚠️ Файл дампа пуст или не создан"
                if stderr_output:
                    # Clean up stderr to show only relevant info
                    clean_stderr = stderr_output.strip().split('\n')[-1]
                    error_msg += f"\nОшибка tcpdump: {clean_stderr}"
                    
                    if "Operation not permitted" in stderr_output:
                        error_msg += "\n💡 Попробуйте запустить скрипт с правами root (sudo)."
                self.send_telegram_message_to(chat_id, error_msg)
                
        except Exception as e:
            debug_print(f"Error in dump task: {e}", "ERROR")
            self.send_telegram_message_to(chat_id, f"❌ Ошибка сбора дампа: {e}")
            self.dump_process = None
        finally:
            self.dump_in_progress = False
            self.update_network_state()

    def cmd_scan_custom(self, chat_id, target_text, ports_csv, proto):
        debug_print(f"Command: /scan_custom {target_text} ports={ports_csv} ({proto}) triggered", "INFO")
        self.beep_notify()
        def task():
            try:
                self.scanning_in_progress = True
                self.update_network_state()
                
                ips = self._parse_targets_text(target_text)
                if not ips:
                    self.send_telegram_message_to(chat_id, "Цели не найдены")
                    return
                try:
                    ports = [int(x) for x in ports_csv.split(",") if x.strip().isdigit()]
                except:
                    ports = []
                if not ports:
                    self.send_telegram_message_to(chat_id, "Нет валидных портов")
                    return
                
                use_cli = shutil.which("nmap") is not None
                total = len(ips)
                processed = 0
                last_notify_time = time.time()
                results = [] # List of (ip, open_ports)

                def notify():
                    nonlocal last_notify_time
                    now = time.time()
                    if now - last_notify_time >= 10:
                        last_notify_time = now
                        self._notify_scan_progress(chat_id, "Custom Scan", processed, total)

                if use_cli:
                    def scan_worker(ip):
                        if self.nmap_stop_event.is_set():
                            return None
                        out = self._run_nmap_single(ip, ports, proto)
                        return (ip, out)

                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_workers) as executor:
                        future_to_ip = {executor.submit(scan_worker, ip): ip for ip in ips}
                        for future in concurrent.futures.as_completed(future_to_ip):
                            if self.nmap_stop_event.is_set():
                                break
                            res = future.result()
                            processed += 1
                            if res:
                                ip, out = res
                                open_ports = self._parse_nmap_open_ports(out)
                                if open_ports:
                                    results.append((ip, open_ports))
                            notify()
                    
                    msg = ["<b>NMAP CUSTOM SCAN</b>"]
                else:
                    def internal_worker(ip):
                        if self.nmap_stop_event.is_set():
                            return None
                        found = []
                        if proto in ("TCP", "BOTH"):
                            p_tcp = self._scan_ports_quick(ip, ports)
                            if p_tcp:
                                found.extend([f"{p}/tcp" for p in p_tcp])
                        if proto in ("UDP", "BOTH"):
                            p_udp = self._scan_udp_quick(ip, ports)
                            if p_udp:
                                found.extend([f"{p}/udp" for p in p_udp])
                        return (ip, found) if found else None

                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.nmap_workers) as executor:
                        future_to_ip = {executor.submit(internal_worker, ip): ip for ip in ips}
                        for future in concurrent.futures.as_completed(future_to_ip):
                            if self.nmap_stop_event.is_set():
                                break
                            res = future.result()
                            processed += 1
                            if res:
                                results.append(res)
                            notify()
                    
                    msg = ["<b>CUSTOM SCAN</b>"]

                msg.append(f"Targets: {total}")
                msg.append(f"Protocol: {proto}")
                msg.append(f"Ports: {ports_csv}")
                
                if results:
                    # Sort results by IP address
                    try:
                        results.sort(key=lambda x: ipaddress.ip_address(x[0]))
                    except:
                        results.sort()
                        
                    for ip, fports in results:
                        msg.append(f" • {ip}: {', '.join(str(p) for p in fports)}")
                else:
                    msg.append("No open ports found")
                
                self.send_telegram_message_to(chat_id, "\n".join(msg))
            except Exception as e:
                debug_print(f"Scan error: {e}", "ERROR")
            finally:
                self.scanning_in_progress = False
                self.update_network_state()

        try:
            self.nmap_stop_event.clear()
            t = Thread(target=task, daemon=True)
            self.nmap_thread = t
            t.start()
            self.send_telegram_message_to(chat_id, "🛠 Запущено многопоточное кастомное сканирование...")
        except:
            self.send_telegram_message_to(chat_id, "Ошибка запуска сканирования")
    
    def check_and_install_lldp_tools(self):
        """Check if LLDP/CDP tools are available and install if needed"""
        if not self.lldp_enabled:
            return
        
        tools_to_check = [
            ('lldpctl', 'lldpd'),  # lldpctl is part of lldpd package
            ('tcpdump', 'tcpdump'),
            ('ethtool', 'ethtool')
        ]
        
        for tool, package in tools_to_check:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True)
                if result.returncode != 0:
                    debug_print(f"{tool} not found", "LLDP")
                    
                    if self.auto_install_lldp and package:
                        debug_print(f"Attempting to install {package}...", "LLDP")
                        try:
                            # Update package list
                            subprocess.run(['apt-get', 'update'], 
                                         stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL)
                            
                            # Install package non-interactively
                            install_cmd = ['apt-get', 'install', '-y', package]
                            install_result = subprocess.run(install_cmd, 
                                                          capture_output=True, 
                                                          text=True)
                            
                            if install_result.returncode == 0:
                                debug_print(f"Successfully installed {package}", "SUCCESS")
                            else:
                                debug_print(f"Failed to install {package}: {install_result.stderr}", "ERROR")
                                if tool == 'lldpctl':
                                    self.lldp_enabled = False
                        except Exception as e:
                            debug_print(f"Error installing {package}: {e}", "ERROR")
                            if tool == 'lldpctl':
                                self.lldp_enabled = False
                else:
                    debug_print(f"{tool} found", "LLDP")
            except Exception as e:
                debug_print(f"Error checking {tool}: {e}", "ERROR")
                if tool == 'lldpctl':
                    self.lldp_enabled = False
    
    def start_lldp_service(self):
        """Start LLDP service if needed"""
        if not self.lldp_enabled:
            return
        
        try:
            # Check if lldpd service is running
            result = subprocess.run(['systemctl', 'is-active', 'lldpd'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0 or result.stdout.strip() != 'active':
                debug_print("LLDP service not running, attempting to start...", "LLDP")
                
                # Enable and start the service
                subprocess.run(['systemctl', 'enable', 'lldpd'], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
                
                start_result = subprocess.run(['systemctl', 'start', 'lldpd'], 
                                            capture_output=True, text=True)
                
                if start_result.returncode == 0:
                    debug_print("LLDP service started successfully", "SUCCESS")
                    self.lldp_service_running = True
                    
                    # Give service time to start
                    time.sleep(2)
                else:
                    debug_print(f"Failed to start LLDP service: {start_result.stderr}", "ERROR")
                    self.lldp_enabled = False
            else:
                debug_print("LLDP service is already running", "LLDP")
                self.lldp_service_running = True
                
        except Exception as e:
            debug_print(f"Error starting LLDP service: {e}", "ERROR")
            self.lldp_enabled = False
    
    def check_lldp_service(self):
        """Check if LLDP service is running and restart if needed"""
        if not self.lldp_enabled or not self.lldp_service_checked:
            return
        
        try:
            result = subprocess.run(['systemctl', 'is-active', 'lldpd'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip() == 'active':
                self.lldp_service_running = True
            else:
                self.lldp_service_running = False
                debug_print("LLDP service is not running", "WARNING")
                
                # Try to restart service
                subprocess.run(['systemctl', 'restart', 'lldpd'], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
                
        except Exception as e:
            debug_print(f"Error checking LLDP service: {e}", "ERROR")
            self.lldp_service_running = False
    
    def get_lldp_neighbors(self):
        """Get LLDP neighbors using lldpctl or lldpcli"""
        neighbors = []
        
        if not self.lldp_enabled or not self.lldp_service_running:
            return neighbors
        
        # Try different LLDP commands
        lldp_commands = [
            ['lldpctl', '-f', 'json'],      # Most common - JSON format
            ['lldpcli', 'show', 'neighbors', 'details', '-f', 'json'],  # Alternative JSON
            ['lldpctl']                      # Plain text fallback
        ]
        
        for cmd in lldp_commands:
            try:
                debug_print(f"Trying LLDP command: {' '.join(cmd)}", "LLDP")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.lldp_timeout)
                
                if result.returncode == 0 and result.stdout:
                    debug_print(f"LLDP command succeeded, output length: {len(result.stdout)}", "LLDP")
                    
                    # Try to parse JSON output
                    if '-f' in cmd and 'json' in cmd:
                        try:
                            data = json.loads(result.stdout)
                            parsed_neighbors = self.parse_lldp_json(data)
                            if parsed_neighbors:
                                debug_print(f"Parsed {len(parsed_neighbors)} neighbors from JSON", "LLDP")
                                neighbors = parsed_neighbors
                                break
                        except json.JSONDecodeError as e:
                            debug_print(f"Failed to parse JSON: {e}", "LLDP")
                            # Try to parse plain text output
                            parsed_neighbors = self.parse_lldp_text(result.stdout)
                            if parsed_neighbors:
                                debug_print(f"Parsed {len(parsed_neighbors)} neighbors from text", "LLDP")
                                neighbors = parsed_neighbors
                                break
                    else:
                        # Parse plain text output
                        parsed_neighbors = self.parse_lldp_text(result.stdout)
                        if parsed_neighbors:
                            debug_print(f"Parsed {len(parsed_neighbors)} neighbors from text", "LLDP")
                            neighbors = parsed_neighbors
                            break
                
            except subprocess.TimeoutExpired:
                debug_print(f"LLDP command timeout: {' '.join(cmd)}", "WARNING")
                continue
            except FileNotFoundError:
                debug_print(f"LLDP command not found: {cmd[0]}", "LLDP")
                continue
            except Exception as e:
                debug_print(f"Error running LLDP command {cmd}: {e}", "ERROR")
                continue
        
        # Filter out invalid or empty neighbors
        filtered_neighbors = []
        for neighbor in neighbors:
            # Check interface filtering
            ifname = neighbor.get('interface', '')
            if ifname == 'eth0' and not getattr(self, 'lldp_eth0', True):
                continue
            if ifname == 'wlan0' and not getattr(self, 'lldp_wlan0', True):
                continue
                
            # Check if this is a valid neighbor with meaningful information
            if self.is_valid_neighbor(neighbor):
                filtered_neighbors.append(neighbor)
            else:
                debug_print(f"Filtering out invalid neighbor: {neighbor.get('chassis_name', 'Unknown')}", "LLDP")
        
        debug_print(f"Found {len(filtered_neighbors)} valid LLDP neighbors", "LLDP")
        return filtered_neighbors
    
    def is_valid_neighbor(self, neighbor):
        """Check if a neighbor record is valid and contains meaningful information"""
        if not isinstance(neighbor, dict):
            return False
        
        # Must have at least interface and protocol
        if not neighbor.get('interface'):
            return False
        
        # Filter out docker interfaces
        if str(neighbor.get('interface', '')).startswith('docker'):
            return False
        
        # Check for meaningful identifying information
        has_identifying_info = (
            neighbor.get('chassis_name') or
            neighbor.get('chassis_id') or
            neighbor.get('port_id') or
            neighbor.get('management_ip') or
            neighbor.get('management_ips')
        )
        
        if not has_identifying_info:
            # Check if it's a self-entry (some LLDP implementations show local info)
            if neighbor.get('system_description') and 'localhost' in neighbor.get('system_description', '').lower():
                return False
            
            # Check for empty or placeholder values
            port_id = neighbor.get('port_id', '')
            if port_id in ['', '0', '00:00:00:00:00:00', 'N/A', 'Unknown']:
                return False
        
        # Filter out neighbors that are likely the local system
        chassis_name = neighbor.get('chassis_name', '').lower()
        if chassis_name in ['localhost', 'local', 'self', '']:
            return False
        
        # Filter out empty or placeholder chassis IDs
        chassis_id = neighbor.get('chassis_id', '')
        if chassis_id in ['', '00:00:00:00:00:00', '0.0.0.0', 'N/A']:
            # If chassis_id is empty but we have other info, it might still be valid
            if not neighbor.get('chassis_name') and not neighbor.get('port_id'):
                return False
        
        return True
    
    def parse_lldp_json(self, data):
        """Parse JSON output from lldpctl/lldpcli"""
        neighbors = []
        
        try:
            # Different JSON structures from different commands
            if 'lldp' in data and 'interface' in data['lldp']:
                # lldpcli format
                for iface_name, iface_data in data['lldp']['interface'].items():
                    if 'chassis' in iface_data:
                        for chassis_data in iface_data['chassis']:
                            neighbor = self.extract_neighbor_info(iface_name, chassis_data)
                            if neighbor:
                                neighbor['protocol'] = 'LLDP'
                                neighbor['source'] = 'lldpcli'
                                # Filter duplicates before adding
                                if not self.is_duplicate_neighbor(neighbors, neighbor):
                                    neighbors.append(neighbor)
            elif isinstance(data, list):
                # lldpctl -f json format (array of interfaces)
                for item in data:
                    if isinstance(item, dict) and 'interface' in item:
                        iface_name = item['interface'].get('name', '')
                        chassis_data = item.get('chassis', {})
                        neighbor = self.extract_neighbor_info(iface_name, chassis_data)
                        if neighbor:
                            neighbor['protocol'] = 'LLDP'
                            neighbor['source'] = 'lldpctl'
                            # Filter duplicates before adding
                            if not self.is_duplicate_neighbor(neighbors, neighbor):
                                neighbors.append(neighbor)
            elif isinstance(data, dict) and 'interface' in data:
                # Alternative lldpctl format
                for iface_name, iface_data in data['interface'].items():
                    if isinstance(iface_data, dict) and 'chassis' in iface_data:
                        chassis_data = iface_data['chassis']
                        neighbor = self.extract_neighbor_info(iface_name, chassis_data)
                        if neighbor:
                            neighbor['protocol'] = 'LLDP'
                            neighbor['source'] = 'lldpctl'
                            # Filter duplicates before adding
                            if not self.is_duplicate_neighbor(neighbors, neighbor):
                                neighbors.append(neighbor)
                            
        except Exception as e:
            debug_print(f"Error parsing LLDP JSON: {e}", "ERROR")
        
        return neighbors
    
    def is_duplicate_neighbor(self, existing_neighbors, new_neighbor):
        """Check if a neighbor is a duplicate of an existing one"""
        if not self.filter_duplicates:
            return False
        
        new_chassis_id = new_neighbor.get('chassis_id')
        new_chassis_name = new_neighbor.get('chassis_name')
        new_port_id = new_neighbor.get('port_id')
        new_interface = new_neighbor.get('interface')
        new_serial = new_neighbor.get('serial_number')
        
        for existing in existing_neighbors:
            matches = 0
            
            # Match on chassis ID (most reliable)
            if new_chassis_id and existing.get('chassis_id') == new_chassis_id:
                matches += 1
            
            # Match on chassis name
            if new_chassis_name and existing.get('chassis_name') == new_chassis_name:
                matches += 1
            
            # Match on port ID
            if new_port_id and existing.get('port_id') == new_port_id:
                matches += 1
            
            # Match on interface
            if new_interface and existing.get('interface') == new_interface:
                matches += 1
            
            # Match on serial number
            if new_serial and existing.get('serial_number') == new_serial:
                matches += 1
            
            # If we have at least 2 matching identifiers, it's likely a duplicate
            if matches >= 2:
                debug_print(f"Filtering duplicate neighbor: {new_chassis_name or new_chassis_id}", "LLDP")
                return True
        
        return False
    
    def parse_lldp_text(self, text):
        """Parse plain text output from lldpctl"""
        neighbors = []
        
        try:
            sections = text.split('\n\n')  # LLDP output is typically separated by blank lines
            
            for section in sections:
                if not section.strip():
                    continue
                    
                lines = section.split('\n')
                current_neighbor = {}
                current_interface = None
                
                for line in lines:
                    line = line.strip()
                    
                    # Look for interface line
                    if line.startswith('Interface:'):
                        if current_neighbor and current_interface:
                            current_neighbor['interface'] = current_interface
                            current_neighbor['protocol'] = 'LLDP'
                            current_neighbor['source'] = 'lldpctl-text'
                            # Only add if valid and not duplicate
                            if self.is_valid_neighbor(current_neighbor) and not self.is_duplicate_neighbor(neighbors, current_neighbor):
                                neighbors.append(current_neighbor)
                            current_neighbor = {}
                        
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_interface = parts[1].strip().split(',')[0].strip()
                    
                    # Look for chassis information
                    elif line.startswith('Chassis:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            chassis_info = parts[1].strip()
                            if 'id' in chassis_info.lower():
                                match = re.search(r'id\s+([0-9a-f:]+)', chassis_info, re.IGNORECASE)
                                if match:
                                    current_neighbor['chassis_id'] = match.group(1)
                    
                    # Look for port information
                    elif line.startswith('Port:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            port_info = parts[1].strip()
                            # Extract port ID
                            match = re.search(r'id\s+([^,]+)', port_info, re.IGNORECASE)
                            if match:
                                current_neighbor['port_id'] = match.group(1).strip()
                            
                            # Extract port description
                            match = re.search(r'descr:\s+(.+)', port_info, re.IGNORECASE)
                            if match:
                                current_neighbor['port_description'] = match.group(1).strip()
                    
                    # Look for system name
                    elif line.startswith('SysName:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_neighbor['chassis_name'] = parts[1].strip()
                    
                    # Look for system description
                    elif line.startswith('SysDescr:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_neighbor['system_description'] = parts[1].strip()
                    
                    # Look for capabilities
                    elif line.startswith('Capability:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            caps = parts[1].strip().split(',')
                            current_neighbor['capabilities'] = [cap.strip() for cap in caps]
                    
                    # Look for management addresses
                    elif line.startswith('MgmtIP:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_neighbor['management_ip'] = parts[1].strip()
                    
                    # Look for serial number in system description or chassis info
                    elif 'serial' in line.lower() or 'sn:' in line.lower() or 's/n:' in line.lower():
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            # Try to extract serial number
                            serial_text = parts[1].strip()
                            # Look for common serial number patterns
                            serial_match = re.search(r'([A-Z0-9\-]{8,20})', serial_text)
                            if serial_match and len(serial_match.group(1)) > 6:
                                current_neighbor['serial_number'] = serial_match.group(1)
                    
                    # Look for asset information (often contains serial)
                    elif line.startswith('Asset:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            asset_info = parts[1].strip()
                            # Try to extract serial from asset info
                            serial_match = re.search(r'sn[:\s]*([A-Z0-9\-]+)', asset_info, re.IGNORECASE)
                            if serial_match:
                                current_neighbor['serial_number'] = serial_match.group(1)
                
                # Add the last neighbor in the section
                if current_neighbor and current_interface:
                    current_neighbor['interface'] = current_interface
                    current_neighbor['protocol'] = 'LLDP'
                    current_neighbor['source'] = 'lldpctl-text'
                    
                    # Try to extract serial number from system description if not found
                    if not current_neighbor.get('serial_number') and current_neighbor.get('system_description'):
                        serial = self.extract_serial_from_description(current_neighbor['system_description'])
                        if serial:
                            current_neighbor['serial_number'] = serial
                    
                    # Only add if valid and not duplicate
                    if self.is_valid_neighbor(current_neighbor) and not self.is_duplicate_neighbor(neighbors, current_neighbor):
                        neighbors.append(current_neighbor)
                    
        except Exception as e:
            debug_print(f"Error parsing LLDP text: {e}", "ERROR")
        
        return neighbors
    
    def extract_serial_from_description(self, description):
        """Extract serial number from system description"""
        if not description:
            return None
        
        # Common patterns for serial numbers in descriptions
        patterns = [
            r'Serial\s*[#:]?\s*([A-Z0-9\-]{8,20})',  # Serial: ABC123456
            r'SN\s*[#:]?\s*([A-Z0-9\-]{8,20})',       # SN: ABC123456
            r'S/N\s*[#:]?\s*([A-Z0-9\-]{8,20})',      # S/N: ABC123456
            r'([A-Z]{2,4}[0-9]{6,10})',              # ABC123456
            r'([0-9]{4}[A-Z]{2,4}[0-9]{4,8})',       # 1234ABC5678
            r'([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})', # ABCD-1234-EFGH
            r'([A-Z0-9]{10,15})'                     # Generic long alphanumeric
        ]
        
        for pattern in patterns:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                serial = match.group(1).strip()
                # Validate it looks like a serial number (not MAC, not IP, etc.)
                if (len(serial) >= 8 and len(serial) <= 20 and 
                    not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', serial, re.IGNORECASE) and
                    not re.match(r'^\d+\.\d+\.\d+\.\d+$', serial)):
                    return serial
        
        return None
    
    def extract_neighbor_info(self, iface_name, chassis_data):
        """Extract neighbor information from chassis data"""
        neighbor = {
            'interface': iface_name
        }
        
        try:
            # Extract chassis name
            if 'name' in chassis_data:
                if isinstance(chassis_data['name'], list) and len(chassis_data['name']) > 0:
                    if 'value' in chassis_data['name'][0]:
                        neighbor['chassis_name'] = chassis_data['name'][0]['value']
                elif isinstance(chassis_data['name'], dict) and 'value' in chassis_data['name']:
                    neighbor['chassis_name'] = chassis_data['name']['value']
                elif isinstance(chassis_data['name'], str):
                    neighbor['chassis_name'] = chassis_data['name']
            
            # Extract chassis ID
            if 'id' in chassis_data:
                if isinstance(chassis_data['id'], list) and len(chassis_data['id']) > 0:
                    if 'value' in chassis_data['id'][0]:
                        neighbor['chassis_id'] = chassis_data['id'][0]['value']
                elif isinstance(chassis_data['id'], dict) and 'value' in chassis_data['id']:
                    neighbor['chassis_id'] = chassis_data['id']['value']
                elif isinstance(chassis_data['id'], str):
                    neighbor['chassis_id'] = chassis_data['id']
            
            # Extract port information
            if 'port' in chassis_data:
                port_data = chassis_data['port']
                if isinstance(port_data, list) and len(port_data) > 0:
                    port_data = port_data[0]
                
                if 'id' in port_data:
                    if isinstance(port_data['id'], list) and len(port_data['id']) > 0:
                        if 'value' in port_data['id'][0]:
                            neighbor['port_id'] = port_data['id'][0]['value']
                    elif isinstance(port_data['id'], dict) and 'value' in port_data['id']:
                        neighbor['port_id'] = port_data['id']['value']
                    elif isinstance(port_data['id'], str):
                        neighbor['port_id'] = port_data['id']
                
                if 'descr' in port_data:
                    if isinstance(port_data['descr'], list) and len(port_data['descr']) > 0:
                        if 'value' in port_data['descr'][0]:
                            neighbor['port_description'] = port_data['descr'][0]['value']
                    elif isinstance(port_data['descr'], dict) and 'value' in port_data['descr']:
                        neighbor['port_description'] = port_data['descr']['value']
                    elif isinstance(port_data['descr'], str):
                        neighbor['port_description'] = port_data['descr']
            
            # Extract capabilities
            if 'capability' in chassis_data:
                capabilities = []
                cap_data = chassis_data['capability']
                if isinstance(cap_data, list):
                    for cap in cap_data:
                        if 'type' in cap and 'enabled' in cap:
                            if cap.get('enabled'):
                                cap_type = cap['type']
                                if isinstance(cap_type, list) and len(cap_type) > 0:
                                    if 'value' in cap_type[0]:
                                        capabilities.append(cap_type[0]['value'])
                                elif isinstance(cap_type, dict) and 'value' in cap_type:
                                    capabilities.append(cap_type['value'])
                                elif isinstance(cap_type, str):
                                    capabilities.append(cap_type)
                elif isinstance(cap_data, dict):
                    for cap_type, enabled in cap_data.items():
                        if enabled:
                            capabilities.append(cap_type)
                
                if capabilities:
                    neighbor['capabilities'] = capabilities
            
            # Extract system description
            if 'descr' in chassis_data:
                if isinstance(chassis_data['descr'], list) and len(chassis_data['descr']) > 0:
                    if 'value' in chassis_data['descr'][0]:
                        descr_value = chassis_data['descr'][0]['value']
                        neighbor['system_description'] = descr_value
                        
                        # Try to extract serial number from description
                        serial = self.extract_serial_from_description(descr_value)
                        if serial:
                            neighbor['serial_number'] = serial
                elif isinstance(chassis_data['descr'], dict) and 'value' in chassis_data['descr']:
                    descr_value = chassis_data['descr']['value']
                    neighbor['system_description'] = descr_value
                    
                    # Try to extract serial number from description
                    serial = self.extract_serial_from_description(descr_value)
                    if serial:
                        neighbor['serial_number'] = serial
                elif isinstance(chassis_data['descr'], str):
                    descr_value = chassis_data['descr']
                    neighbor['system_description'] = descr_value
                    
                    # Try to extract serial number from description
                    serial = self.extract_serial_from_description(descr_value)
                    if serial:
                        neighbor['serial_number'] = serial
            
            # Extract management addresses
            if 'mgmt-ip' in chassis_data:
                mgmt_ips = []
                mgmt_data = chassis_data['mgmt-ip']
                if isinstance(mgmt_data, list):
                    for ip in mgmt_data:
                        if isinstance(ip, dict) and 'value' in ip:
                            mgmt_ips.append(ip['value'])
                        elif isinstance(ip, str):
                            mgmt_ips.append(ip)
                elif isinstance(mgmt_data, str):
                    mgmt_ips.append(mgmt_data)
                
                if mgmt_ips:
                    neighbor['management_ips'] = mgmt_ips
            
            # Try to extract serial number from other fields
            if not neighbor.get('serial_number'):
                # Check for serial in chassis name (some devices include SN in name)
                if neighbor.get('chassis_name'):
                    serial_match = re.search(r'\[SN:([A-Z0-9\-]+)\]', neighbor['chassis_name'])
                    if serial_match:
                        neighbor['serial_number'] = serial_match.group(1)
                
                # Check in port description
                if not neighbor.get('serial_number') and neighbor.get('port_description'):
                    serial = self.extract_serial_from_description(neighbor['port_description'])
                    if serial:
                        neighbor['serial_number'] = serial
            
            # Filter out entries that are clearly invalid
            chassis_id = neighbor.get('chassis_id', '')
            chassis_name = neighbor.get('chassis_name', '')
            
            # Skip entries with empty or placeholder chassis IDs
            if not chassis_id or chassis_id in ['', '0', '00:00:00:00:00:00']:
                # But keep if we have at least a name or port ID
                if not chassis_name and not neighbor.get('port_id'):
                    return None
            
            # Skip localhost/self entries
            if chassis_name and chassis_name.lower() in ['localhost', 'local', 'self']:
                return None
            
            return neighbor
                
        except Exception as e:
            debug_print(f"Error extracting neighbor info: {e}", "ERROR")
            return None
    
    def get_cdp_neighbors(self):
        """Get CDP neighbors using tcpdump"""
        neighbors = []
        
        if not self.cdp_enabled:
            return neighbors
        
        # Get active interfaces
        active_ifaces = []
        for iface in self.current_state.get('active_interfaces', []):
            if isinstance(iface, dict):
                ifname = iface.get('name')
                if ifname and ifname != 'lo':
                    if ifname == 'eth0' and not getattr(self, 'lldp_eth0', True):
                        continue
                    if ifname == 'wlan0' and not getattr(self, 'lldp_wlan0', True):
                        continue
                    active_ifaces.append(ifname)
        
        if not active_ifaces:
            debug_print("No active interfaces for CDP discovery", "LLDP")
            return neighbors
        
        for iface in active_ifaces:
            try:
                debug_print(f"Looking for CDP packets on interface {iface}", "LLDP")
                
                # Run tcpdump to capture CDP packets
                cmd = ['timeout', '5', 'tcpdump', '-i', iface, '-s', '1500', '-c', '2', '-v', 'ether[20:2] == 0x2000']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and (result.stderr or result.stdout):
                    cdp_data = result.stderr if result.stderr else result.stdout
                    
                    if 'CDP' in cdp_data or 'Cisco Discovery Protocol' in cdp_data:
                        debug_print(f"Found CDP packets on {iface}", "LLDP")
                        
                        # Parse CDP information
                        neighbor = {
                            'interface': iface,
                            'protocol': 'CDP',
                            'source': 'tcpdump'
                        }
                        
                        # Extract device ID
                        device_id_match = re.search(r'Device ID[^:]*:\s*([^\n]+)', cdp_data, re.IGNORECASE)
                        if device_id_match:
                            neighbor['chassis_name'] = device_id_match.group(1).strip()
                        
                        # Extract port ID
                        port_id_match = re.search(r'Port ID[^:]*:\s*([^\n]+)', cdp_data, re.IGNORECASE)
                        if port_id_match:
                            neighbor['port_id'] = port_id_match.group(1).strip()
                        
                        # Extract capabilities
                        capabilities_match = re.search(r'Capabilities:\s*([^\n]+)', cdp_data, re.IGNORECASE)
                        if capabilities_match:
                            neighbor['capabilities'] = capabilities_match.group(1).strip().split()
                        
                        # Extract platform
                        platform_match = re.search(r'Platform:\s*([^,]+)', cdp_data, re.IGNORECASE)
                        if platform_match:
                            neighbor['platform'] = platform_match.group(1).strip()
                        
                        # Extract IP address
                        ip_match = re.search(r'(?:IP|Internet) address:\s*([\d\.]+)', cdp_data, re.IGNORECASE)
                        if ip_match:
                            neighbor['management_ip'] = ip_match.group(1).strip()
                        
                        # Extract software version
                        version_match = re.search(r'Version[^:]*:\s*([^\n]+(?:\n\s+[^\n]+)*)', cdp_data, re.IGNORECASE | re.DOTALL)
                        if version_match:
                            version_text = version_match.group(1).strip()
                            # Clean up the version text
                            version_text = re.sub(r'\s+', ' ', version_text)
                            neighbor['software_version'] = version_text[:100]  # Limit length
                        
                        # Extract serial number from CDP data
                        serial_match = re.search(r'Serial number[^:]*:\s*([^\n]+)', cdp_data, re.IGNORECASE)
                        if serial_match:
                            neighbor['serial_number'] = serial_match.group(1).strip()
                        
                        # Try to extract serial from other fields
                        if not neighbor.get('serial_number'):
                            # Check in device ID
                            if neighbor.get('chassis_name'):
                                serial_match = re.search(r'\(([A-Z0-9\-]{8,20})\)', neighbor['chassis_name'])
                                if serial_match:
                                    neighbor['serial_number'] = serial_match.group(1)
                            
                            # Check in platform description
                            if not neighbor.get('serial_number') and neighbor.get('platform'):
                                serial = self.extract_serial_from_description(neighbor['platform'])
                                if serial:
                                    neighbor['serial_number'] = serial
                        
                        # Only add if we found valid information and not a duplicate
                        if self.is_valid_neighbor(neighbor):
                            # Filter duplicates
                            if not self.is_duplicate_neighbor(neighbors, neighbor):
                                neighbors.append(neighbor)
                                debug_print(f"Found CDP neighbor on {iface}: {neighbor.get('chassis_name', 'Unknown')}", "LLDP")
                            else:
                                debug_print(f"Filtered duplicate CDP neighbor on {iface}", "LLDP")
                        else:
                            debug_print(f"Skipping invalid CDP neighbor on {iface}", "LLDP")
                    else:
                        debug_print(f"No CDP packets found on {iface}", "LLDP")
                
            except subprocess.TimeoutExpired:
                debug_print(f"CDP capture timeout on {iface}", "LLDP")
            except Exception as e:
                debug_print(f"Error getting CDP neighbors on {iface}: {e}", "ERROR")
        
        return neighbors
    
    def get_ethtool_neighbors(self):
        """Get neighbor information using ethtool (for some switches and SFP modules)"""
        neighbors = []
        
        # Get active interfaces
        active_ifaces = []
        for iface in self.current_state.get('active_interfaces', []):
            if isinstance(iface, dict):
                ifname = iface.get('name')
                if ifname and ifname.startswith('eth'):  # Only check Ethernet interfaces
                    active_ifaces.append(ifname)
        
        for iface in active_ifaces:
            try:
                # Check if interface supports ethtool DOM
                cmd = ['ethtool', '-m', iface]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                
                if result.returncode == 0:
                    # Parse DOM (Digital Optical Monitoring) information
                    lines = result.stdout.split('\n')
                    vendor = None
                    serial = None
                    part_number = None
                    transceiver_type = None
                    
                    for line in lines:
                        line_lower = line.lower()
                        if 'vendor' in line_lower and ':' in line:
                            vendor = line.split(':', 1)[1].strip()
                        elif 'serial' in line_lower and ':' in line:
                            serial = line.split(':', 1)[1].strip()
                        elif 'part number' in line_lower and ':' in line:
                            part_number = line.split(':', 1)[1].strip()
                        elif 'identifier' in line_lower and ':' in line:
                            transceiver_type = line.split(':', 1)[1].strip()
                    
                    if vendor or serial or part_number or transceiver_type:
                        neighbor = {
                            'interface': iface,
                            'protocol': 'ETHTOOL',
                            'source': 'ethtool'
                        }
                        
                        if vendor:
                            neighbor['vendor'] = vendor
                        if serial:
                            neighbor['serial_number'] = serial  # Store as serial_number for consistency
                        if part_number:
                            neighbor['part_number'] = part_number
                        if transceiver_type:
                            neighbor['transceiver_type'] = transceiver_type
                        
                        # Only add if valid and not duplicate
                        if self.is_valid_neighbor(neighbor):
                            if not self.is_duplicate_neighbor(neighbors, neighbor):
                                neighbors.append(neighbor)
                                debug_print(f"Found ethtool info on {iface}: {vendor or 'Unknown'}", "LLDP")
                            else:
                                debug_print(f"Filtered duplicate ethtool neighbor on {iface}", "LLDP")
                        else:
                            debug_print(f"Skipping invalid ethtool neighbor on {iface}", "LLDP")
                
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            except Exception as e:
                debug_print(f"Error getting ethtool info on {iface}: {e}", "ERROR")
        
        return neighbors
    
    def get_simple_lldp_info(self):
        """Get simple LLDP info using alternative methods"""
        neighbors = []
        
        # Try reading from /proc/net/lldp if available
        try:
            if os.path.exists('/proc/net/lldp'):
                with open('/proc/net/lldp', 'r') as f:
                    content = f.read()
                    # Simple parsing of lldp info
                    lines = content.split('\n')
                    for line in lines:
                        if ':' in line:
                            parts = line.split(':', 1)
                            iface = parts[0].strip()
                            info = parts[1].strip()
                            
                            if info and info != '(null)':
                                neighbor = {
                                    'interface': iface,
                                    'protocol': 'LLDP',
                                    'source': '/proc/net/lldp',
                                    'raw_info': info
                                }
                                
                                # Try to extract basic info
                                if ';' in info:
                                    info_parts = info.split(';')
                                    for part in info_parts:
                                        if '=' in part:
                                            key, value = part.split('=', 1)
                                            if key and value:
                                                neighbor[key.strip()] = value.strip()
                                
                                # Try to extract serial number
                                if not neighbor.get('serial_number'):
                                    serial = self.extract_serial_from_description(info)
                                    if serial:
                                        neighbor['serial_number'] = serial
                                
                                # Only add if valid and not duplicate
                                if self.is_valid_neighbor(neighbor):
                                    if not self.is_duplicate_neighbor(neighbors, neighbor):
                                        neighbors.append(neighbor)
                                        debug_print(f"Found LLDP info in /proc for {iface}", "LLDP")
                                    else:
                                        debug_print(f"Filtered duplicate LLDP neighbor from /proc for {iface}", "LLDP")
                                else:
                                    debug_print(f"Skipping invalid LLDP neighbor from /proc for {iface}", "LLDP")
        except:
            pass
        
        return neighbors
    
    def update_neighbors(self):
        """Update neighbor information (LLDP/CDP)"""
        if not self.lldp_enabled and not self.cdp_enabled:
            return []
        
        current_time = time.time()
        
        # Only recheck LLDP/CDP periodically to reduce load
        if current_time - self.last_lldp_check < self.lldp_recheck_interval:
            return self.lldp_neighbors.get('neighbors', [])
        
        debug_print("Checking for LLDP/CDP neighbors...", "LLDP")
        
        neighbors = []
        
        # Check LLDP service status periodically
        if not self.lldp_service_checked or current_time - self.last_lldp_check > 300:  # Every 5 minutes
            self.check_lldp_service()
            self.lldp_service_checked = True
        
        # Get LLDP neighbors
        if self.lldp_enabled and self.lldp_service_running:
            lldp_neighbors = self.get_lldp_neighbors()
            if not lldp_neighbors:
                # Try alternative method
                lldp_neighbors = self.get_simple_lldp_info()
            
            # Add LLDP neighbors if valid
            for neighbor in lldp_neighbors:
                if self.is_valid_neighbor(neighbor) and not self.is_duplicate_neighbor(neighbors, neighbor):
                    neighbors.append(neighbor)
        
        # Get CDP neighbors
        if self.cdp_enabled:
            cdp_neighbors = self.get_cdp_neighbors()
            for neighbor in cdp_neighbors:
                if self.is_valid_neighbor(neighbor) and not self.is_duplicate_neighbor(neighbors, neighbor):
                    neighbors.append(neighbor)
        
        # Get ethtool information (for SFP modules, etc.)
        ethtool_info = self.get_ethtool_neighbors()
        for neighbor in ethtool_info:
            if self.is_valid_neighbor(neighbor) and not self.is_duplicate_neighbor(neighbors, neighbor):
                neighbors.append(neighbor)
        
        # Sort neighbors by interface and name for consistent display
        neighbors.sort(key=lambda x: (x.get('interface', ''), x.get('chassis_name', '')))
        
        # Update cache
        self.lldp_neighbors = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'neighbors': neighbors
        }
        
        self.last_lldp_check = current_time
        
        debug_print(f"Total valid neighbors found: {len(neighbors)}", "LLDP")
        
        return neighbors
    
    def init_downtime_log(self):
        """Initialize downtime log file"""
        try:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(self.downtime_log_file)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except Exception as e_dir:
                    debug_print(f"Could not create log directory {log_dir}: {e_dir}", "WARNING")
                    # Fallback to current directory
                    base_dir = os.path.dirname(os.path.abspath(__file__))
                    self.downtime_log_file = os.path.join(base_dir, os.path.basename(self.downtime_log_file))
                    debug_print(f"Fallback downtime log path: {self.downtime_log_file}", "INFO")
            
            # Create file if it doesn't exist
            if not os.path.exists(self.downtime_log_file):
                with open(self.downtime_log_file, 'w', encoding='utf-8') as f:
                    f.write("# NWSCAN Internet Downtime Log\n")
                    f.write("# Format: downtime_start,downtime_end,duration_seconds\n")
                    f.write(f"# Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                debug_print(f"Created downtime log file: {self.downtime_log_file}", "DOWNTIME")
            else:
                debug_print(f"Using existing downtime log: {self.downtime_log_file}", "DOWNTIME")
        except Exception as e:
            debug_print(f"Error initializing downtime log: {e}", "ERROR")
    
    def beep(self, duration):
        """Make a beep sound"""
        try:
            def _beep_thread():
                try:
                    GPIO.output(BUZZER_PIN, GPIO.HIGH)
                    time.sleep(duration)
                    GPIO.output(BUZZER_PIN, GPIO.LOW)
                except:
                    pass
            
            # Run in separate thread to not block main loop
            Thread(target=_beep_thread, daemon=True).start()
        except:
            pass

    def beep_startup(self):
        """Long beep for startup"""
        self.beep(0.8)

    def beep_notify(self):
        """Short beep for notifications"""
        self.beep(0.1)

    def load_config(self):
        """Load all settings from JSON config"""
        try:
            cfg_path = self.get_config_path()
            
            if not os.path.exists(cfg_path):
                return
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            
            # 1. Telegram settings
            token = cfg.get('telegram_token') or cfg.get('TELEGRAM_BOT_TOKEN')
            if token and isinstance(token, str) and token.strip():
                self.telegram_bot_token = token.strip()
            
            api_url = cfg.get('telegram_api_url')
            if api_url and isinstance(api_url, str) and api_url.strip():
                self.telegram_api_base_url = api_url.strip()
            
            ids = cfg.get('telegram_chat_ids')
            if isinstance(ids, list):
                self.telegram_chat_ids = set(str(cid) for cid in ids)
            elif isinstance(ids, set):
                self.telegram_chat_ids = ids
            elif ids:
                self.telegram_chat_ids = set(str(ids).split(','))
            
            if 'telegram_enabled' in cfg: self.telegram_enabled = bool(cfg['telegram_enabled'])
            if 'telegram_notify_on_change' in cfg: self.telegram_notify_on_change = bool(cfg['telegram_notify_on_change'])
            if 'downtime_notifications' in cfg: self.downtime_report_on_recovery = bool(cfg['downtime_notifications'])
            
            # 2. General settings
            if 'lldp_enabled' in cfg: self.lldp_enabled = bool(cfg['lldp_enabled'])
            if 'lldp_eth0' in cfg: self.lldp_eth0 = bool(cfg['lldp_eth0'])
            if 'lldp_wlan0' in cfg: self.lldp_wlan0 = bool(cfg['lldp_wlan0'])
            if 'monitor_eth0' in cfg: self.monitor_eth0 = bool(cfg['monitor_eth0'])
            if 'monitor_wlan0' in cfg: self.monitor_wlan0 = bool(cfg['monitor_wlan0'])
            
            # 3. Intervals and TTLs
            if 'check_interval' in cfg: self.check_interval = int(cfg['check_interval'])
            if 'lldp_recheck_interval' in cfg: self.lldp_recheck_interval = int(cfg['lldp_recheck_interval'])
            if 'ttl_interfaces' in cfg: self.ttl_interfaces = int(cfg['ttl_interfaces'])
            if 'ttl_dns_servers' in cfg: self.ttl_dns_servers = int(cfg['ttl_dns_servers'])
            if 'ttl_dns_status' in cfg: self.ttl_dns_status = int(cfg['ttl_dns_status'])
            if 'ttl_gateway' in cfg: self.ttl_gateway = int(cfg['ttl_gateway'])
            if 'ttl_external_ip' in cfg: self.ttl_external_ip = int(cfg['ttl_external_ip'])
            
            # 4. Nmap settings
            if 'nmap_max_workers' in cfg: self.nmap_workers = int(cfg['nmap_max_workers'])
            if 'auto_scan_on_network_up' in cfg: self.auto_scan_on_network_up = bool(cfg['auto_scan_on_network_up'])
            
            # 5. SFTP settings
            if 'sftp_enabled' in cfg: self.sftp_enabled = bool(cfg['sftp_enabled'])
            if 'sftp_user' in cfg: self.sftp_user = str(cfg['sftp_user'])
            if 'sftp_password' in cfg: self.sftp_password = str(cfg['sftp_password'])
            if 'sftp_port' in cfg: self.sftp_port = int(cfg['sftp_port'])
            
            # Start SFTP if enabled
            if self.sftp_enabled:
                # We use a small delay to ensure everything is initialized
                Thread(target=self.start_sftp_server, daemon=True).start()
            
        except Exception as e:
            debug_print(f"Error loading config: {e}", "ERROR")
    
    def log_downtime(self, start_time, end_time, duration_seconds):
        """Log downtime to file"""
        try:
            with open(self.downtime_log_file, 'a') as f:
                start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
                end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"{start_str},{end_str},{duration_seconds:.1f}\n")
            
            debug_print(f"Downtime logged: {start_str} to {end_str} ({duration_seconds:.1f}s)", "DOWNTIME")
        except Exception as e:
            debug_print(f"Error logging downtime: {e}", "ERROR")
    
    def format_duration(self, seconds):
        """Format duration in seconds to human readable string"""
        if seconds < 60:
            return f"{seconds:.0f} секунд"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} минут"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f} часов"
        else:
            days = seconds / 86400
            return f"{days:.1f} дней"
    
    def send_downtime_report(self, start_time, end_time, duration_seconds):
        """Send downtime report via Telegram"""
        if not self.telegram_enabled or not self.telegram_initialized:
            return False
        
        try:
            # Hostname для идентификации системы
            hostname = "Unknown"
            try:
                hostname = subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()
            except:
                pass
            
            # Format message
            start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
            duration_str = self.format_duration(duration_seconds)
            
            message = f"<b>⚠️ ВОССТАНОВЛЕНИЕ ИНТЕРНЕТА - {hostname}</b>\n\n"
            message += f"<b>📉 Отсутствие интернета:</b>\n"
            message += f"Начало: <code>{start_str}</code>\n"
            message += f"Конец: <code>{end_str}</code>\n"
            message += f"Длительность: <b>{duration_str}</b>\n\n"
            message += f"<b>✅ Интернет восстановлен в {end_str}</b>\n"
            
            debug_print(f"Sending downtime report: {duration_str} downtime", "DOWNTIME")
            
            return self.send_telegram_message(message)
        except Exception as e:
            debug_print(f"Error sending downtime report: {e}", "ERROR")
            return False
    
    def check_internet_transition(self, has_internet_now):
        """Check if internet status changed and handle downtime tracking"""
        try:
            # If internet was up and now it's down
            if self.internet_was_up and not has_internet_now:
                # Internet went down
                self.downtime_start = datetime.now()
                debug_print(f"Internet DOWN at {self.downtime_start.strftime('%H:%M:%S')}", "DOWNTIME")
            
            # If internet was down and now it's up
            elif not self.internet_was_up and has_internet_now:
                # Internet came back up
                if self.downtime_start:
                    downtime_end = datetime.now()
                    duration = (downtime_end - self.downtime_start).total_seconds()
                    
                    debug_print(f"Internet UP at {downtime_end.strftime('%H:%M:%S')} "
                               f"(downtime: {duration:.1f}s)", "DOWNTIME")
                    
                    # Log downtime to file
                    self.log_downtime(self.downtime_start, downtime_end, duration)
                    
                    # Send report if enabled
                    if self.downtime_report_on_recovery and duration > 1:  # Report if downtime > 1s
                        self.send_downtime_report(self.downtime_start, downtime_end, duration)
                    
                    # Reset downtime tracking
                    self.downtime_start = None
            
            # Update previous state
            self.internet_was_up = has_internet_now
            
        except Exception as e:
            debug_print(f"Error in internet transition tracking: {e}", "ERROR")
    
    def init_telegram(self):
        """Initialize Telegram bot"""
        if not self.telegram_enabled:
            debug_print("Telegram notifications disabled by configuration", "INFO")
            return
        
        if self.debug_telegram:
            print(colored("\n" + "="*60, BLUE))
            print(colored("TELEGRAM INITIALIZATION", BLUE))
            print(colored("="*60, BLUE))
        
        # Check if token configured
        if self.telegram_bot_token == "YOUR_TELEGRAM_BOT_TOKEN":
            debug_print("Telegram bot token not configured!", "ERROR")
            self.telegram_enabled = False
            return
        if self.debug_telegram:
            print(colored(f"Bot Token: {self.telegram_bot_token[:10]}...", CYAN))
            try:
                ids_str = ", ".join(str(cid) for cid in self.telegram_chat_ids) if self.telegram_chat_ids else "(none yet)"
            except Exception:
                ids_str = "(unavailable)"
            print(colored(f"Chat IDs: {ids_str}", CYAN))
        
        try:
            # Test Telegram connection
            url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/getMe"
            
            if self.debug_telegram:
                debug_print("Testing Telegram API connection...", "TELEGRAM")
            
            try:
                response = requests.get(url, timeout=self.telegram_timeout, verify=False)
                
                if self.debug_telegram:
                    debug_print(f"HTTP Status: {response.status_code}", "TELEGRAM")
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get('ok'):
                        bot_info = result['result']
                        self.telegram_initialized = True
                        debug_print(f"Telegram bot connected: @{bot_info['username']}", "SUCCESS")
                        
                        # Test sending a message
                        if self.debug_telegram:
                            debug_print("Testing message sending...", "TELEGRAM")
                        
                        if not self.startup_message_sent:
                            test_msg = "NWSCAN Monitor initialized!\nSystem is now being monitored."
                            if self.send_telegram_message_simple(test_msg):
                                debug_print("Test message sent successfully", "SUCCESS")
                                self.startup_message_sent = True
                            else:
                                debug_print("Failed to send test message", "WARNING")
                    else:
                        error_msg = result.get('description', 'Unknown error')
                        debug_print(f"Telegram API error: {error_msg}", "ERROR")
                elif response.status_code in [404, 401]:
                    debug_print("Invalid bot token or unauthorized", "ERROR")
                else:
                    debug_print(f"Unexpected HTTP status: {response.status_code}", "ERROR")
                    
            except requests.exceptions.ConnectionError as e:
                debug_print(f"Connection error: {e}", "ERROR")
            except requests.exceptions.Timeout as e:
                debug_print(f"Connection timeout: {e}", "ERROR")
            except Exception as e:
                debug_print(f"Unexpected error: {e}", "ERROR")
                
        except Exception as e:
            debug_print(f"Telegram setup error: {e}", "ERROR")
            self.telegram_initialized = False
        
        if self.debug_telegram:
            print(colored("="*60, BLUE))
    
    def send_telegram_message_simple(self, message):
        """Простой метод отправки сообщения в Telegram"""
        if not self.telegram_enabled:
            return False
        
        if not self.telegram_initialized:
            return False
        
        if self.telegram_errors >= self.max_telegram_errors:
            debug_print("Too many Telegram errors, notifications disabled", "ERROR")
            return False
        
        url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/sendMessage"
        any_success = False
        for chat_id in list(self.telegram_chat_ids):
            try:
                params = {
                    'chat_id': chat_id,
                    'text': message,
                    'parse_mode': 'HTML',
                    'disable_web_page_preview': True
                }
                if self.debug_telegram:
                    debug_print(f"Sending message to chat {chat_id}", "TELEGRAM")
                    debug_print(f"Message length: {len(message)} chars", "TELEGRAM")
                response = requests.post(url, data=params, timeout=self.telegram_timeout, verify=False)
                if self.debug_telegram:
                    debug_print(f"HTTP Status: {response.status_code}", "TELEGRAM")
                if response.status_code == 200:
                    result = response.json()
                    if result.get('ok'):
                        any_success = True
                        self.telegram_errors = 0
                    else:
                        error_msg = result.get('description', 'Unknown error')
                        debug_print(f"Telegram API error: {error_msg}", "ERROR")
                        self.telegram_errors += 1
                else:
                    debug_print(f"Telegram HTTP error: {response.status_code}", "ERROR")
                    self.telegram_errors += 1
            except requests.exceptions.ConnectionError as e:
                debug_print(f"Telegram connection error: {e}", "ERROR")
                self.telegram_errors += 1
            except requests.exceptions.Timeout as e:
                debug_print(f"Telegram timeout error: {e}", "ERROR")
                self.telegram_errors += 1
            except requests.exceptions.RequestException as e:
                debug_print(f"Telegram request error: {e}", "ERROR")
                self.telegram_errors += 1
            except Exception as e:
                debug_print(f"Telegram unexpected error: {e}", "ERROR")
                self.telegram_errors += 1
        if self.debug_telegram:
            debug_print(f"Telegram errors count: {self.telegram_errors}/{self.max_telegram_errors}", "WARNING")
        return any_success
    
    def send_telegram_message(self, message):
        """Основной метод отправки сообщения в Telegram"""
        return self.send_telegram_message_simple(message)

    def send_telegram_document(self, chat_id, file_path, caption=None):
        """Отправка файла в Telegram"""
        if not self.telegram_enabled or not self.telegram_initialized:
            return False
            
        url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/sendDocument"
        try:
            if not os.path.exists(file_path):
                debug_print(f"File not found for Telegram upload: {file_path}", "ERROR")
                return False
                
            with open(file_path, 'rb') as f:
                files = {'document': f}
                data = {'chat_id': chat_id}
                if caption:
                    data['caption'] = caption
                    
                debug_print(f"Sending document {file_path} to {chat_id}", "TELEGRAM")
                response = requests.post(url, data=data, files=files, timeout=60, verify=False)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('ok'):
                        debug_print("Document sent successfully", "SUCCESS")
                        return True
                    else:
                        debug_print(f"Telegram API error: {result.get('description')}", "ERROR")
                else:
                    debug_print(f"Telegram HTTP error: {response.status_code}", "ERROR")
        except Exception as e:
            debug_print(f"Error sending document: {e}", "ERROR")
        return False
    
    def format_state_for_telegram(self, state):
        """Format network state for Telegram message"""
        ip_address = state.get('ip')
        has_internet = state.get('has_internet', False)
        active_interfaces = state.get('active_interfaces', [])
        gateway = state.get('gateway')
        dns_servers = state.get('dns', [])
        dns_status_list = state.get('dns_status', [])
        external_ip = state.get('external_ip')
        timestamp = state.get('timestamp', 'N/A')
        neighbors = state.get('neighbors', [])
        change_flags = state.get('change_flags', {})
        
        # Hostname для идентификации системы
        hostname = "Unknown"
        try:
            hostname = subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()
        except:
            pass
        
        # Emojis for Telegram
        emoji_status = "✅" if has_internet else "⚠️" if ip_address else "❌"
        emoji_up = "🟢"
        emoji_down = "🔴"
        emoji_dns_ok = "✅"
        emoji_dns_fail = "❌"
        emoji_interface = "🔌"
        emoji_neighbor = "🔗"
        emoji_serial = "🏷️"

        def hl(flag, text):
            try:
                return f"<u>{text}</u>" if change_flags.get(flag) else text
            except:
                return text
        def hl_any(flags, text):
            try:
                return f"<u>{text}</u>" if any(change_flags.get(f) for f in flags) else text
            except:
                return text
        def hl_code(flag, code_text):
            try:
                return f"<u><code>{code_text}</code></u>" if change_flags.get(flag) else f"<code>{code_text}</code>"
            except:
                return f"<code>{code_text}</code>"
        
        # Build message
        message = f"<b>🛰️ NWSCAN - {hostname}</b>\n"
        message += f"<i>{timestamp}</i>\n\n"
        
        # System status
        message += "<b>📊 SYSTEM STATUS</b>\n"
        if not ip_address:
            message += f"{emoji_down} <b>NO IP ADDRESS</b>\n"
        elif not has_internet:
            message += f"{emoji_status} IP: {hl_code('ip', ip_address)}\n{hl('internet','<b>NO INTERNET CONNECTION</b>')}\n"
            
            # Add current downtime duration if applicable
            if self.downtime_start:
                downtime_duration = (datetime.now() - self.downtime_start).total_seconds()
                duration_str = self.format_duration(downtime_duration)
                message += f"⏱️ Downtime: <b>{duration_str}</b>\n"
        else:
            message += f"{emoji_status} IP: {hl_code('ip', ip_address)}\n{hl('internet','<b>INTERNET AVAILABLE</b>')}\n"
        
        # External IP
        if has_internet and external_ip:
            message += f"🌍 External: {hl_code('external_ip', external_ip)}\n"
        
        message += "\n"
        
        # Active interfaces
        active_count = len(active_interfaces)
        message += f"<b>🔌 ACTIVE INTERFACES ({active_count})</b>\n"
        
        if active_interfaces:
            for iface in active_interfaces:
                if not isinstance(iface, dict):
                    continue
                    
                ifname = iface.get('name', 'N/A')
                if ifname.startswith('docker'):
                    continue
                mac = iface.get('mac', 'N/A')
                ip_addresses = iface.get('ip_addresses', [])
                
                message += f"\n{emoji_interface} <b>{ifname}</b> ({mac})\n"
                
                if ip_addresses:
                    for ip_info in ip_addresses:
                        cidr = ip_info.get('cidr', 'N/A')
                        mask = ip_info.get('mask', 'N/A')
                        network = ip_info.get('network', 'N/A')
                        broadcast = ip_info.get('broadcast', 'N/A')
                        
                        message += f"  📍 IP: <code>{cidr}</code>\n"
                        message += f"     Mask: <code>{mask}</code>\n"
                        message += f"     Net: <code>{network}</code> | Bcast: <code>{broadcast}</code>\n"
                        
                        prefix = ip_info.get('prefix', 0)
                        if isinstance(prefix, int) and prefix >= 24:
                            first = ip_info.get('first_usable', 'N/A')
                            last = ip_info.get('last_usable', 'N/A')
                            hosts = ip_info.get('usable_hosts', 'N/A')
                            message += f"     Range: <code>{first} - {last}</code>\n"
                            message += f"     Hosts: <code>{hosts}</code>\n"
                else:
                    message += "  📍 <i>no IP assigned</i>\n"
                
                # Traffic
                rx_bytes = iface.get('rx_bytes', 0)
                tx_bytes = iface.get('tx_bytes', 0)
                if rx_bytes > 0 or tx_bytes > 0:
                    message += f"  📥 {self.format_bytes(rx_bytes)} | 📤 {self.format_bytes(tx_bytes)}\n"
        else:
            message += "<i>No active network interfaces</i>\n"
        
        message += "\n"
        
        # Gateway
        message += f"{hl_any(['gateway_address','gateway_available'],'<b>🌐 GATEWAY</b>')}\n"
        if gateway:
            gateway_addr = gateway.get('address', 'N/A')
            available = gateway.get('available', False)
            status_emoji = emoji_up if available else emoji_down
            
            message += f"{status_emoji} {hl_code('gateway_address', gateway_addr)}\n"
            if not available:
                message += f"{hl('gateway_available','  <i>(unreachable)</i>')}\n"
            else:
                if change_flags.get('gateway_available'):
                    message += f"{hl('gateway_available','  <i>(available)</i>')}\n"
        else:
            message += f"{emoji_down} <i>Not configured</i>\n"
        
        message += "\n"
        
        # DNS servers
        message += f"{hl_any(['dns','dns_status'],'<b>🔍 DNS SERVERS</b>')}\n"
        if dns_servers and dns_servers[0] != 'None':
            working_dns = sum(1 for s in dns_status_list if s.get('working', False))
            total_dns = len(dns_servers)
            
            status_emoji = "✅" if working_dns == total_dns else "⚠️" if working_dns > 0 else "❌"
            message += f"{status_emoji} {hl('dns_status', f'<b>{working_dns}/{total_dns} working</b>')}\n"
            
            for i, dns_server in enumerate(dns_servers):
                status_info = dns_status_list[i] if i < len(dns_status_list) else {}
                working = status_info.get('working', False)
                response_time = status_info.get('response_time')
                
                status_emoji = emoji_dns_ok if working else emoji_dns_fail
                time_text = f" ({response_time*1000:.0f} ms)" if response_time else ""
                
                # Format DNS server display
                dns_display = str(dns_server)
                if isinstance(dns_server, dict):
                    srv = dns_server.get('server', 'N/A')
                    iface = dns_server.get('interface')
                    if iface and iface != 'Unknown' and iface != 'Global':
                         dns_display = f"{srv} ({iface})"
                    else:
                         dns_display = srv

                message += f"  {status_emoji} {hl_code('dns', dns_display)}{time_text}\n"
        else:
            message += "❌ <i>No DNS servers configured</i>\n"
        
        # Neighbors (LLDP/CDP)
        if neighbors:
            message += "\n"
            message += f"{hl('neighbors', f'<b>{emoji_neighbor} NETWORK NEIGHBORS ({len(neighbors)})</b>')}\n"
            
            for i, neighbor in enumerate(neighbors):
                iface = neighbor.get('interface', 'N/A')
                protocol = neighbor.get('protocol', 'Unknown')
                chassis_name = neighbor.get('chassis_name')
                
                if chassis_name:
                    message += f"\n{emoji_neighbor} <b>{chassis_name}</b>\n"
                else:
                    # Try to use other identifying information
                    port_id = neighbor.get('port_id')
                    chassis_id = neighbor.get('chassis_id')
                    if port_id:
                        message += f"\n{emoji_neighbor} <b>Port: {port_id}</b>\n"
                    elif chassis_id:
                        message += f"\n{emoji_neighbor} <b>ID: {chassis_id}</b>\n"
                    else:
                        message += f"\n{emoji_neighbor} <b>Neighbor #{i+1}</b>\n"
                
                message += f"  📡 Interface: <code>{iface}</code>\n"
                message += f"  📋 Protocol: {protocol}\n"
                
                if 'port_id' in neighbor and not chassis_name and not chassis_id:
                    # Already shown as title
                    pass
                elif 'port_id' in neighbor:
                    message += f"  🔌 Remote Port: <code>{neighbor['port_id']}</code>\n"
                
                # Serial number
                if 'serial_number' in neighbor:
                    message += f"  {emoji_serial} Serial: <code>{neighbor['serial_number']}</code>\n"
                
                if 'capabilities' in neighbor:
                    caps = neighbor['capabilities']
                    if isinstance(caps, list):
                        caps_str = ', '.join(caps)
                    else:
                        caps_str = str(caps)
                    message += f"  ⚙️ Capabilities: {caps_str}\n"
                
                if 'management_ip' in neighbor:
                    message += f"  🌐 Management IP: <code>{neighbor['management_ip']}</code>\n"
                elif 'management_ips' in neighbor:
                    ips = ', '.join(neighbor['management_ips'])
                    message += f"  🌐 Management IPs: <code>{ips}</code>\n"
                
                if 'platform' in neighbor:
                    message += f"  💻 Platform: {neighbor['platform']}\n"
                
                if 'vendor' in neighbor:
                    message += f"  🏭 Vendor: {neighbor['vendor']}\n"
        
        # Change indicator if present
        if 'change_indicator' in state:
            message = f"<b>🔄 NETWORK STATUS</b>\n\n" + message
        
        return message
    
    def send_telegram_notification(self, state, force=False):
        """Send notification to Telegram if state changed"""
        if not self.telegram_enabled or not self.telegram_initialized:
            if self.debug_telegram:
                debug_print("Telegram not enabled or initialized", "TELEGRAM")
            return
        
        # Определяем, нужно ли отправлять сообщение
        if not self.telegram_notify_on_change:
            # Если отключена отправка только при изменениях - отправляем всегда
            should_send = True
            if self.debug_telegram:
                debug_print("Sending notification (notify_on_change=False)", "TELEGRAM")
        else:
            # Проверяем изменения
            should_send = False
            
            if self.last_telegram_state is None:
                # Первое сообщение после старта
                should_send = True
                state = state.copy()
                state['change_indicator'] = " • System started"
                if self.debug_telegram:
                    debug_print("First notification after start", "TELEGRAM")
            else:
                # Проверяем изменения состояния
                old_state = self.last_telegram_state
                new_state = state
                
                changes = []
                change_flags = {}
                
                # Проверяем основные параметры
                old_ip = old_state.get('ip')
                new_ip = new_state.get('ip')
                if old_ip != new_ip:
                    changes.append("IP address")
                    change_flags['ip'] = True
                
                old_internet = old_state.get('has_internet', False)
                new_internet = new_state.get('has_internet', False)
                if old_internet != new_internet:
                    changes.append("Internet connectivity")
                    change_flags['internet'] = True
                
                old_gateway_addr = old_state.get('gateway', {}).get('address')
                new_gateway_addr = new_state.get('gateway', {}).get('address')
                if old_gateway_addr != new_gateway_addr:
                    changes.append("Gateway")
                    change_flags['gateway_address'] = True
                old_gateway_avail = old_state.get('gateway', {}).get('available')
                new_gateway_avail = new_state.get('gateway', {}).get('available')
                if old_gateway_avail != new_gateway_avail:
                    change_flags['gateway_available'] = True
                
                old_if_count = len(old_state.get('active_interfaces', []))
                new_if_count = len(new_state.get('active_interfaces', []))
                if old_if_count != new_if_count:
                    changes.append(f"Active interfaces: {old_if_count}→{new_if_count}")
                    change_flags['interfaces'] = True
                else:
                    try:
                        def iface_sig(lst):
                            sig = []
                            for it in lst:
                                if isinstance(it, dict):
                                    name = it.get('name')
                                    ips = it.get('ip_addresses', [])
                                    cidrs = []
                                    for ip in ips:
                                        if isinstance(ip, dict):
                                            cidrs.append(ip.get('cidr'))
                                    sig.append((name, tuple(sorted([c for c in cidrs if c]))))
                            return sorted(sig)
                        if iface_sig(old_state.get('active_interfaces', [])) != iface_sig(new_state.get('active_interfaces', [])):
                            change_flags['interfaces'] = True
                    except:
                        pass
                
                old_dns = old_state.get('dns', [])
                new_dns = new_state.get('dns', [])
                if old_dns != new_dns:
                    changes.append("DNS servers")
                    change_flags['dns'] = True
                try:
                    if old_state.get('dns_status', []) != new_state.get('dns_status', []):
                        change_flags['dns_status'] = True
                except:
                    pass
                
                # Check for neighbor changes
                old_neighbors = old_state.get('neighbors', [])
                new_neighbors = new_state.get('neighbors', [])
                if len(old_neighbors) != len(new_neighbors):
                    changes.append(f"Neighbors: {len(old_neighbors)}→{len(new_neighbors)}")
                    change_flags['neighbors'] = True
                else:
                    # Compare neighbor details
                    old_names = [n.get('chassis_name', '') for n in old_neighbors]
                    new_names = [n.get('chassis_name', '') for n in new_neighbors]
                    if sorted(old_names) != sorted(new_names):
                        changes.append("Neighbor devices changed")
                        change_flags['neighbors'] = True
                
                # External IP change
                try:
                    if old_state.get('external_ip') != new_state.get('external_ip'):
                        change_flags['external_ip'] = True
                except:
                    pass
                
                if changes:
                    should_send = True
                    state = state.copy()
                    state['change_indicator'] = " • " + "\n • ".join(changes)
                    state['change_flags'] = change_flags
                    if self.debug_telegram:
                        debug_print(f"Changes detected: {len(changes)} changes", "TELEGRAM")
                elif self.debug_telegram:
                    debug_print("No changes detected", "TELEGRAM")
        
        if should_send or force:
            # Beep on notification
            self.beep_notify()
            
            message = self.format_state_for_telegram(state)
            
            if self.debug_telegram:
                debug_print(f"Preparing to send message ({len(message)} chars)", "TELEGRAM")
            
            if self.send_telegram_message(message):
                self.last_telegram_state = state.copy()
                if self.debug_telegram:
                    debug_print("Notification sent successfully", "SUCCESS")
            else:
                if self.debug_telegram:
                    debug_print("Failed to send notification", "ERROR")
        else:
            if self.debug_telegram:
                debug_print("Skipping notification (no changes)", "TELEGRAM")
    
    def start_led_thread(self):
        """Start the LED control thread"""
        self.led_thread = Thread(target=self.led_control_thread)
        self.led_thread.daemon = True
        self.led_thread.start()
    
    def led_control_thread(self):
        """Separate thread for LED control with RGB support"""
        while not self.stop_led_thread:
            with self.lock:
                current_led_state = self.led_state
            
            # Helper to set LED colors
            def set_led(red, green, blue):
                GPIO.output(LED_RED_PIN, GPIO.HIGH if red else GPIO.LOW)
                GPIO.output(LED_GREEN_PIN, GPIO.HIGH if green else GPIO.LOW)
                GPIO.output(LED_BLUE_PIN, GPIO.HIGH if blue else GPIO.LOW)

            if current_led_state == "OFF":
                set_led(False, False, False)
                time.sleep(0.1)
            elif current_led_state == "RED":
                set_led(True, False, False)
                time.sleep(0.1)
            elif current_led_state == "GREEN":
                set_led(False, True, False)
                time.sleep(0.1)
            elif current_led_state == "BLUE":
                set_led(False, False, True)
                time.sleep(0.1)
            elif current_led_state == "BLINKING_GREEN":
                set_led(False, True, False)
                time.sleep(BLINK_INTERVAL)
                set_led(False, False, False)
                time.sleep(BLINK_INTERVAL)
            elif current_led_state == "BLINKING_BLUE":
                set_led(False, False, True)
                time.sleep(BLINK_INTERVAL)
                set_led(False, False, False)
                time.sleep(BLINK_INTERVAL)
            elif current_led_state == "ON": # Legacy support
                set_led(False, True, False)
                time.sleep(0.1)
            elif current_led_state == "BLINKING": # Legacy support
                set_led(False, True, False)
                time.sleep(BLINK_INTERVAL)
                set_led(False, False, False)
                time.sleep(BLINK_INTERVAL)
            else:
                time.sleep(0.1)
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        self.stop_led_thread = True
        
        # Wait for LED thread to stop
        if self.led_thread:
            self.led_thread.join(timeout=1)
        
        # Turn off all LED components
        try:
            GPIO.output(LED_GREEN_PIN, GPIO.LOW)
            GPIO.output(LED_RED_PIN, GPIO.LOW)
            GPIO.output(LED_BLUE_PIN, GPIO.LOW)
            time.sleep(0.1)
            GPIO.cleanup()
        except:
            pass
        
        # Log final downtime if internet is still down
        if not self.internet_was_up and self.downtime_start:
            downtime_end = datetime.now()
            duration = (downtime_end - self.downtime_start).total_seconds()
            self.log_downtime(self.downtime_start, downtime_end, duration)
            debug_print(f"Final downtime logged: {duration:.1f}s", "DOWNTIME")
        
        # Send shutdown notification
        if self.telegram_enabled and self.telegram_initialized:
            if self.debug_telegram:
                debug_print("Sending shutdown notification", "TELEGRAM")
            self.send_telegram_message("🛑 NWSCAN Monitor stopped\nSystem monitoring ended.")
        
    def run_command(self, cmd):
        """Run shell command safely"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""
    
    def test_dns_resolution(self, dns_server):
        """Test if DNS server can resolve DNS_TEST_HOSTNAME (google.com)"""
        # Method 1: Socket UDP query
        try:
            # Create UDP socket for DNS query
            dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_socket.settimeout(2)
            
            # Build a simple DNS query for the test hostname (type A)
            query_id = os.getpid() & 0xFFFF # Use PID for some uniqueness
            flags = 0x0100  # Standard query, recursion desired
            questions = 1
            answer_rrs = 0
            authority_rrs = 0
            additional_rrs = 0
            
            # Header
            header = struct.pack('!HHHHHH', query_id, flags, questions, 
                                answer_rrs, authority_rrs, additional_rrs)
            
            # Query for DNS_TEST_HOSTNAME
            domain_parts = DNS_TEST_HOSTNAME.split('.')
            query = b''
            for part in domain_parts:
                query += struct.pack('B', len(part)) + part.encode()
            query += b'\x00'  # End of domain name
            
            # Type A (1), Class IN (1)
            query += struct.pack('!HH', 1, 1)
            
            # Send query
            dns_socket.sendto(header + query, (dns_server, 53))
            
            # Receive response
            response, addr = dns_socket.recvfrom(512)
            dns_socket.close()
            
            # Check if response is valid
            if len(response) > 12:
                # Check response ID matches query ID
                resp_id = struct.unpack('!H', response[:2])[0]
                if resp_id == query_id:
                    # Check response code (bits 12-15)
                    rcode = (struct.unpack('!H', response[2:4])[0] & 0x000F)
                    # 0 = No error, 3 = NXDOMAIN (still means server is working and responding)
                    if rcode in (0, 3):
                        return True
        except Exception as e:
            # Optional: more verbose debug for DNS failures if needed
            # debug_print(f"DNS Socket check failed for {dns_server}: {e}", "DEBUG")
            pass
        
        # Fallback method using nslookup/dig
        try:
            # Try using dig
            # Check for "status: NOERROR" which is standard in dig output
            result = subprocess.run(['dig', f'@{dns_server}', DNS_TEST_HOSTNAME, '+time=1', '+tries=1'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and 'status: NOERROR' in result.stdout:
                return True
        except:
            pass
        
        try:
            # Try using nslookup
            result = subprocess.run(['nslookup', DNS_TEST_HOSTNAME, dns_server],
                                  capture_output=True, text=True, timeout=2)
            
            # Check for success using exit code and IP pattern matching
            if result.returncode == 0:
                 # Look for any IP address in the output that is NOT the dns_server IP
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result.stdout)
                # Filter out the DNS server IP itself, localhost, and 0.0.0.0
                resolved_ips = [ip for ip in ips if ip != dns_server and ip != '0.0.0.0' and not ip.startswith('127.')]
                
                # On Windows, the server IP might be listed first. 
                # We need to ensure we found at least one IP that is likely the resolved address.
                if len(resolved_ips) > 0:
                    return True
        except Exception as e:
            debug_print(f"DNS nslookup check failed for {dns_server}: {e}", "WARNING")
        
        return False
    
    def get_local_ip(self):
        """Get local IP address with multiple fallback methods"""
        # Method 1: Socket connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith('127.'):
                return ip
        except:
            pass
        
        # Method 2: hostname command
        try:
            output = self.run_command(['hostname', '-I'])
            if output:
                ips = output.split()
                for ip in ips:
                    if ip and not ip.startswith('127.'):
                        return ip
        except:
            pass
        
        # Method 3: Check interfaces directly
        try:
            output = self.run_command(['ip', '-4', '-o', 'addr', 'show'])
            if output:
                for line in output.split('\n'):
                    if 'inet ' in line and ' lo ' not in line:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            ip_cidr = parts[3]
                            ip = ip_cidr.split('/')[0]
                            if not ip.startswith('127.'):
                                return ip
        except:
            pass
        
        return None
    
    def check_internet(self, interface=None, source_ip=None):
        """Check internet connectivity with timeout, optionally via specific interface and source IP"""
        try:
            socket.setdefaulttimeout(1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # 1. Bind to Source IP (Standard way to force interface selection)
            if source_ip:
                try:
                    sock.bind((source_ip, 0))
                except Exception as e:
                    # debug_print(f"Failed to bind to source IP {source_ip}: {e}", "WARNING")
                    sock.close()
                    return False

            # 2. Bind to Device (Linux specific, stronger enforcement)
            if interface:
                try:
                    iface_bytes = interface.encode('utf-8') + b'\0'
                    sock.setsockopt(socket.SOL_SOCKET, 25, iface_bytes)
                except (AttributeError, OSError):
                    if platform.system() == 'Linux':
                        sock.close()
                        return False
                    pass

            sock.connect((CHECK_HOST, CHECK_PORT))
            sock.close()
            return True
        except socket.timeout:
            return False
        except ConnectionRefusedError:
            return False
        except socket.error:
            return False
        except Exception:
            return False
    
    def get_interfaces_info(self):
        """Get detailed information about network interfaces with minimal shell calls"""
        interfaces_dict = {}
        
        # 1. Get names, status, and MAC addresses in one call
        link_output = self.run_command(['ip', '-o', 'link', 'show'])
        if link_output:
            for line in link_output.split('\n'):
                if not line: continue
                
                # Match interface name and status
                match = re.search(r'^\d+:\s+([^:]+):.*state\s+(\w+)', line)
                if match:
                    ifname = match.group(1).strip()
                    status = match.group(2).strip()
                    
                    if ifname == 'lo' or ifname.startswith('docker'): continue
                    if ifname == 'eth0' and not self.monitor_eth0: continue
                    if ifname == 'wlan0' and not self.monitor_wlan0: continue
                    
                    # Get MAC address from the same line
                    mac = 'N/A'
                    mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', line)
                    if mac_match:
                        mac = mac_match.group(1)
                    
                    interfaces_dict[ifname] = {
                        'name': ifname,
                        'status': status,
                        'mac': mac,
                        'ip_addresses': [],
                        'rx_bytes': 0,
                        'tx_bytes': 0
                    }

        # 2. Get all IP addresses in one call
        addr_output = self.run_command(['ip', '-o', '-4', 'addr', 'show'])
        if addr_output:
            for line in addr_output.split('\n'):
                if not line: continue
                parts = line.split()
                if len(parts) >= 4:
                    ifname = parts[1]
                    if ifname in interfaces_dict:
                        ip_cidr = parts[3]
                        ip_info = calculate_network_info(ip_cidr)
                        if ip_info:
                            interfaces_dict[ifname]['ip_addresses'].append(ip_info)

        # 3. Get traffic statistics from sysfs (fast)
        for ifname in interfaces_dict:
            try:
                rx_path = f'/sys/class/net/{ifname}/statistics/rx_bytes'
                tx_path = f'/sys/class/net/{ifname}/statistics/tx_bytes'
                if os.path.exists(rx_path):
                    with open(rx_path, 'r') as f:
                        interfaces_dict[ifname]['rx_bytes'] = int(f.read().strip())
                if os.path.exists(tx_path):
                    with open(tx_path, 'r') as f:
                        interfaces_dict[ifname]['tx_bytes'] = int(f.read().strip())
            except:
                pass
        
        interfaces = list(interfaces_dict.values())
        active_interfaces = [i for i in interfaces if i['status'] == 'UP']
        
        return interfaces, active_interfaces




    def normalize_mac(self, mac_str):
        """Normalize MAC address to XX:XX:XX:XX:XX:XX format"""
        # Remove all common separators
        clean = re.sub(r'[^a-fA-F0-9]', '', mac_str)
        if len(clean) != 12:
            raise ValueError(f"Invalid MAC length: {len(clean)} chars (expected 12 hex digits)")
        
        # Split into pairs and join with colon
        return ':'.join(clean[i:i+2] for i in range(0, 12, 2)).upper()

    def _write_file_root(self, filepath, content_lines):
        """Write content to a file using tee"""
        try:
            content = "".join(content_lines)
            proc = subprocess.Popen(['tee', filepath], 
                                  stdin=subprocess.PIPE, 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate(input=content.encode('utf-8'))
            if proc.returncode != 0:
                raise RuntimeError(f"tee failed: {stderr.decode()}")
            return True
        except Exception as e:
            debug_print(f"Failed to write privileged file {filepath}: {e}", "ERROR")
            raise e

    def _detect_network_manager(self):
        """Detect if NetworkManager is active"""
        try:
            # Check if service is active
            res = subprocess.run(['systemctl', 'is-active', 'NetworkManager'], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0 and res.stdout.strip() == 'active':
                return True
        except:
            pass
        return False

    def _set_ip_nm(self, iface, ip_cidr, gateway, dns_list, method='auto'):
        """Configure IP via NetworkManager"""
        debug_print(f"Using NetworkManager for {iface}", "INFO")
        
        # Find connection
        conn_out = self.run_command(['nmcli', '-t', '-f', 'GENERAL.CONNECTION', 'device', 'show', iface])
        if not conn_out:
            raise RuntimeError(f"No NM connection found for {iface}")
        parts = conn_out.split(':', 1)
        conn_name = parts[1].strip() if len(parts) > 1 else None
        if not conn_name or conn_name == '--':
            raise RuntimeError(f"No active connection profile for {iface}")

        if method == 'dhcp':
            # Bundle DHCP commands
            cmd = ['nmcli', 'con', 'mod', conn_name]
            cmd.extend(['ipv4.method', 'auto'])
            cmd.extend(['ipv4.addresses', ''])
            cmd.extend(['ipv4.gateway', ''])
            cmd.extend(['ipv4.dns', ''])
            cmd.extend(['ipv4.ignore-auto-dns', 'no'])
            cmd.extend(['connection.autoconnect', 'yes'])
            
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"DHCP config failed: {e.stderr.strip()}")
                
            subprocess.run(['nmcli', 'con', 'up', conn_name], check=True)
            
        else:
            # Static - Bundle all settings in one transaction to pass validation
            cmd = ['nmcli', 'con', 'mod', conn_name]
            cmd.extend(['ipv4.addresses', ip_cidr])
            cmd.extend(['ipv4.gateway', gateway])
            
            if dns_list:
                cmd.extend(['ipv4.dns', " ".join(dns_list)])
            else:
                cmd.extend(['ipv4.dns', ''])
                
            cmd.extend(['ipv4.ignore-auto-dns', 'yes'])
            cmd.extend(['ipv4.method', 'manual'])
            cmd.extend(['connection.autoconnect', 'yes'])
            
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Static config failed: {e.stderr.strip()}")
            
            subprocess.run(['nmcli', 'con', 'up', conn_name], check=True)

    def _set_ip_dhcpcd(self, iface, ip_cidr, gateway, dns_list, method='auto'):
        """Configure IP via dhcpcd.conf"""
        debug_print(f"Using dhcpcd for {iface}", "INFO")
        conf_file = '/etc/dhcpcd.conf'
        if not os.path.exists(conf_file):
            raise RuntimeError(f"{conf_file} not found")

        # Read existing
        with open(conf_file, 'r') as f:
            lines = f.readlines()

        new_lines = []
        skip = False
        for line in lines:
            stripped = line.strip()
            if stripped == f'interface {iface}':
                skip = True
                continue
            if skip and stripped.startswith('interface '):
                skip = False
            
            if not skip:
                new_lines.append(line)

        # Append new config if static
        if method != 'dhcp':
            if new_lines and not new_lines[-1].endswith('\n'):
                new_lines.append('\n')
            new_lines.append(f'interface {iface}\n')
            new_lines.append(f'static ip_address={ip_cidr}\n')
            new_lines.append(f'static routers={gateway}\n')
            if dns_list:
                new_lines.append(f'static domain_name_servers={" ".join(dns_list)}\n')

        # Write
        self._write_file_root(conf_file, new_lines)

        # Flush IP
        try:
            subprocess.run(['ip', 'addr', 'flush', 'dev', iface], check=False)
        except: pass

        # Restart service
        subprocess.run(['systemctl', 'restart', 'dhcpcd'], check=True)

    def set_interface_ip(self, iface, ip_cidr=None, gateway=None, dns_list=None, method='auto'):
        """Main entry point for IP configuration"""
        is_dhcp = (method == 'dhcp') or (ip_cidr is None)
        mode = "DHCP" if is_dhcp else f"Static {ip_cidr}"
        debug_print(f"Configuring {iface} mode={mode}", "INFO")

        # Invalidate cache to force immediate update on next cycle
        if hasattr(self, '_cache') and 'interfaces' in self._cache:
            self._cache['interfaces']['ts'] = 0

        # Detect manager
        use_nm = self._detect_network_manager()
        
        if use_nm:
            self._set_ip_nm(iface, ip_cidr, gateway, dns_list, 'dhcp' if is_dhcp else 'static')
        else:
            self._set_ip_dhcpcd(iface, ip_cidr, gateway, dns_list, 'dhcp' if is_dhcp else 'static')

    def change_interface_mac(self, iface, new_mac):
        """Change MAC address using nmcli (if managed) or ip link"""
        debug_print(f"Changing MAC for {iface} to {new_mac}", "INFO")
        
        # Try NetworkManager first
        nm_managed = False
        try:
            if shutil.which("nmcli"):
                # Check if device is managed by NM
                nm_status = self.run_command(['nmcli', '-t', '-f', 'GENERAL.STATE', 'device', 'show', iface])
                if nm_status and 'unmanaged' not in nm_status:
                    nm_managed = True
        except:
            pass

        if nm_managed:
            try:
                # Get connection name for the device
                conn_out = self.run_command(['nmcli', '-t', '-f', 'GENERAL.CONNECTION', 'device', 'show', iface])
                if conn_out:
                    # Output format: "GENERAL.CONNECTION:Wired connection 1"
                    parts = conn_out.split(':', 1)
                    if len(parts) > 1:
                        conn_name = parts[1].strip()
                        if conn_name and conn_name != '--':
                            debug_print(f"Updating NM connection '{conn_name}'", "INFO")
                            # Modify the connection profile
                            subprocess.run(['nmcli', 'connection', 'modify', conn_name, 'ethernet.cloned-mac-address', new_mac], check=True)
                            # Bring the connection up to apply changes
                            subprocess.run(['nmcli', 'connection', 'up', conn_name], check=True)
                            return
            except Exception as e:
                # If nmcli fails, log it and fall back to ip link
                debug_print(f"Error changing MAC via nmcli: {e}", "WARNING")

        # Fallback to ip link (original method)
        try:
            subprocess.run(['ip', 'link', 'set', 'dev', iface, 'down'], check=True)
            subprocess.run(['ip', 'link', 'set', 'dev', iface, 'address', new_mac], check=True)
            subprocess.run(['ip', 'link', 'set', 'dev', iface, 'up'], check=True)
        except Exception as e:
            raise e



    def get_permanent_mac(self, iface):
        try:
            result = subprocess.run(['ethtool', '-P', iface], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'Permanent address:' in line:
                        return line.split(':', 1)[1].strip()
        except Exception:
            pass
        return None

    def restore_interface_mac(self, iface):
        perm = self.get_permanent_mac(iface)
        if not perm:
            raise RuntimeError(f"Permanent MAC not available for {iface}")
        self.change_interface_mac(iface, perm)
    def get_gateway_info(self):
        """Get default gateway information"""
        output = self.run_command(['ip', 'route', 'show', 'default'])
        if output and 'default' in output:
            lines = output.split('\n')
            if lines:
                parts = lines[0].split()
                if len(parts) >= 3:
                    gateway = parts[2]
                    interface = parts[4] if len(parts) >= 5 else 'N/A'
                    
                    # Check gateway availability
                    try:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', gateway],
                                              stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL,
                                              timeout=2)
                        available = result.returncode == 0
                    except:
                        available = False
                    
                    return {
                        'address': gateway,
                        'interface': interface,
                        'available': available
                    }
        
        return None
    
    def get_dns_servers(self):
        """Get DNS servers associated with interfaces"""
        dns_map = [] # List of {'interface': 'eth0', 'server': '8.8.8.8'}
        
        # Method 1: resolvectl status (systemd-resolved)
        try:
            output = self.run_command(['resolvectl', 'status'])
            if output:
                current_iface = 'Global'
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('Link '):
                        # Format: Link 2 (eth0)
                        match = re.search(r'Link \d+ \((.+)\)', line)
                        if match:
                            current_iface = match.group(1)
                            if current_iface.startswith('docker'):
                                current_iface = 'Docker' # Mark as Docker to potentially skip later or just skip now
                                # Actually better to just skip processing this block if it is docker
                                
                    elif line.startswith('Global'):
                        current_iface = 'Global'
                    
                    if line.startswith('DNS Servers:') or line.startswith('Current DNS Server:'):
                        if current_iface == 'Docker': continue # Skip if docker interface
                        
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            servers = parts[1].split()
                            for s in servers:
                                if s and not any(d['server'] == s and d['interface'] == current_iface for d in dns_map):
                                    dns_map.append({'interface': current_iface, 'server': s})
        except: pass

        # Method 2: nmcli (NetworkManager)
        try:
            if shutil.which("nmcli"):
                # Get devices
                devs = self.run_command(['nmcli', '-t', '-f', 'DEVICE', 'dev']).split('\n')
                for dev in devs:
                    dev = dev.strip()
                    if not dev or dev == 'lo' or dev.startswith('docker'): continue
                    
                    info = self.run_command(['nmcli', '-t', '-f', 'IP4.DNS', 'dev', 'show', dev])
                    if info:
                        for line in info.split('\n'):
                            if 'IP4.DNS' in line:
                                parts = line.split(':', 1)
                                if len(parts) > 1:
                                    s = parts[1].strip()
                                    if s and not any(d['server'] == s and d['interface'] == dev for d in dns_map):
                                        dns_map.append({'interface': dev, 'server': s})
        except: pass

        # Method 2.5: dhcpcd
        try:
            if shutil.which("dhcpcd") and os.path.isdir('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    if iface == 'lo' or iface.startswith('docker'): continue
                    
                    # Try getting lease info from dhcpcd
                    output = self.run_command(['dhcpcd', '-U', iface])
                    if output:
                        for line in output.split('\n'):
                            # Match domain_name_servers='...' or new_domain_name_servers='...'
                            match = re.search(r'(?:new_)?domain_name_servers=[\'\"]([^\'\"]+)[\'\"]', line)
                            if match:
                                servers = match.group(1).split()
                                for s in servers:
                                    if s and not any(d['server'] == s and d['interface'] == iface for d in dns_map):
                                        dns_map.append({'interface': iface, 'server': s})
        except: pass

        # Method 3: /etc/resolv.conf (fallback, usually global)
        if not dns_map:
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.strip().startswith('nameserver'):
                            parts = line.strip().split()
                            if len(parts) > 1:
                                s = parts[1]
                                if not any(d['server'] == s for d in dns_map):
                                    dns_map.append({'interface': 'System', 'server': s})
            except: pass

        return dns_map

    def check_dns_status(self, dns_list):
        """Check status of DNS servers. Expects list of dicts or strings."""
        results = []
        
        # Normalize input to list of dicts
        normalized_list = []
        for item in dns_list:
            if isinstance(item, str):
                normalized_list.append({'interface': 'Unknown', 'server': item})
            elif isinstance(item, dict):
                normalized_list.append(item)
        
        for entry in normalized_list:
            server = entry.get('server')
            if not server or server == 'None': continue
            
            try:
                start = time.time()
                working = self.test_dns_resolution(server)
                duration = time.time() - start if working else None
                
                results.append({
                    'interface': entry.get('interface', 'Unknown'),
                    'server': server,
                    'working': working,
                    'response_time': duration
                })
            except:
                results.append({
                    'interface': entry.get('interface', 'Unknown'),
                    'server': server,
                    'working': False,
                    'response_time': None
                })
                
        return results
    
    def get_external_ip(self):
        """Get external IP address"""
        try:
            external_ip = self.run_command(['curl', '-s', '--max-time', '2', 'ifconfig.me'])
            if external_ip and len(external_ip.split('.')) == 4:
                return external_ip
            
            # Alternative service
            external_ip = self.run_command(['curl', '-s', '--max-time', '2', 'api.ipify.org'])
            if external_ip and len(external_ip.split('.')) == 4:
                return external_ip
        except:
            pass
        
        return None
    
    def start_sftp_server(self):
        """Start SFTP server in a background thread"""
        if self.sftp_server_instance:
            return

        def run_server():
            debug_print(f"Starting SFTP server on port {self.sftp_port}...", "INFO")
            try:
                host_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rsa_key.pem")
                if not os.path.exists(host_key_path):
                    key = paramiko.RSAKey.generate(2048)
                    key.write_private_key_file(host_key_path)
                
                host_key = paramiko.RSAKey(filename=host_key_path)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('', self.sftp_port))
                sock.listen(5)
                self.sftp_server_instance = sock
                
                while self.sftp_enabled:
                    try:
                        sock.settimeout(1.0)
                        client, addr = sock.accept()
                        
                        def handle_client(client_sock, client_addr):
                            t = None
                            try:
                                debug_print(f"SFTP: New connection from {client_addr}", "INFO")
                                t = paramiko.Transport(client_sock)
                                t.add_server_key(host_key)
                                # Subsystem handler must be set BEFORE starting the server
                                t.set_subsystem_handler('sftp', paramiko.SFTPServer, SimpleSFTPServerInterface, self.sftp_root)
                                
                                server = SimpleSSHServer(self.sftp_user, self.sftp_password)
                                try:
                                    t.start_server(server=server)
                                except paramiko.SSHException as e:
                                    debug_print(f"SFTP: SSH negotiation failed for {client_addr}: {e}", "ERROR")
                                    return

                                # IMPORTANT: We MUST call accept() to acknowledge the channel request
                                # and keep it alive. FileZilla requests a session channel first.
                                chan = t.accept(30)
                                if chan:
                                    debug_print(f"SFTP: Channel accepted for {client_addr}", "SUCCESS")
                                    # Keep the transport alive until the client disconnects
                                    while t.is_active():
                                        time.sleep(1)
                                else:
                                    debug_print(f"SFTP: No channel accepted for {client_addr} (timeout)", "WARNING")
                                    
                            except Exception as e:
                                debug_print(f"SFTP: session error ({client_addr}): {e}\n{traceback.format_exc()}", "ERROR")
                            finally:
                                if t:
                                    try:
                                        t.close()
                                    except:
                                        pass
                                debug_print(f"SFTP: Connection closed for {client_addr}", "INFO")
                        
                        Thread(target=handle_client, args=(client, addr), daemon=True).start()
                        
                    except socket.timeout:
                        continue
                    except:
                        break
            except Exception as e:
                debug_print(f"SFTP server error: {e}", "ERROR")
            finally:
                self.sftp_server_instance = None
                debug_print("SFTP server stopped", "INFO")

        self.sftp_thread = Thread(target=run_server, daemon=True)
        self.sftp_thread.start()

    def stop_sftp_server(self):
        """Stop the SFTP server"""
        self.sftp_enabled = False
        if self.sftp_server_instance:
            try:
                self.sftp_server_instance.close()
            except:
                pass
            self.sftp_server_instance = None

    def cmd_sftp_start(self, chat_id):
        if self.sftp_enabled and self.sftp_server_instance:
            self.send_telegram_message_to(chat_id, "✅ SFTP сервер уже запущен")
            return
            
        self.sftp_enabled = True
        self.save_config()
        self.start_sftp_server()
        self.send_telegram_message_to(chat_id, f"✅ SFTP сервер запущен на порту {self.sftp_port}\nПользователь: <code>{self.sftp_user}</code>\nПароль: <code>{self.sftp_password}</code>")

    def cmd_sftp_stop(self, chat_id):
        self.sftp_enabled = False
        self.save_config()
        self.stop_sftp_server()
        self.send_telegram_message_to(chat_id, "🛑 SFTP сервер остановлен")

    def cmd_sftp_files(self, chat_id):
        try:
            files = os.listdir(self.sftp_root)
            if not files:
                self.send_telegram_message_to(chat_id, "📁 Папка SFTP пуста")
                return
            
            msg = ["<b>📁 Список файлов SFTP:</b>"]
            for f in sorted(files):
                fpath = os.path.join(self.sftp_root, f)
                size = os.path.getsize(fpath)
                size_str = self.format_size(size)
                msg.append(f"• <code>{f}</code> ({size_str})")
            
            self.send_telegram_message_to(chat_id, "\n".join(msg))
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка получения списка файлов: {e}")

    def cmd_sftp_delete(self, chat_id, filename):
        if not filename:
            self.send_telegram_message_to(chat_id, "❌ Укажите имя файла: /sftp_delete <filename>")
            return
            
        fpath = os.path.join(self.sftp_root, filename)
        if not os.path.exists(fpath):
            self.send_telegram_message_to(chat_id, f"❌ Файл <code>{filename}</code> не найден")
            return
            
        try:
            os.remove(fpath)
            self.send_telegram_message_to(chat_id, f"✅ Файл <code>{filename}</code> удален")
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка при удалении: {e}")

    def cmd_sftp_download(self, chat_id, filename):
        if not filename:
            self.send_telegram_message_to(chat_id, "❌ Укажите имя файла: /sftp_download <filename>")
            return
            
        fpath = os.path.join(self.sftp_root, filename)
        if not os.path.exists(fpath):
            self.send_telegram_message_to(chat_id, f"❌ Файл <code>{filename}</code> не найден")
            return
            
        try:
            self.send_telegram_document(chat_id, fpath)
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка при отправке файла: {e}")

    def cmd_sftp_upload(self, chat_id):
        self.waiting_for_sftp_upload[chat_id] = True
        self.send_telegram_message_to(chat_id, "📤 Отправьте файл(ы) для загрузки на SFTP сервер")

    def check_sftp_files(self):
        """Check for new files in SFTP root and notify via Telegram"""
        now = time.time()
        # Scan every 5 seconds
        if now - self.last_sftp_scan < 5:
            return
            
        self.last_sftp_scan = now
        
        try:
            if not os.path.exists(self.sftp_root):
                return
                
            current_files = set(os.listdir(self.sftp_root))
            new_files = current_files - self.known_sftp_files
            
            if new_files:
                for fname in new_files:
                    fpath = os.path.join(self.sftp_root, fname)
                    if os.path.isfile(fpath):
                        size = os.path.getsize(fpath)
                        size_str = self.format_size(size)
                        msg = f"🆕 <b>Новый файл на SFTP:</b>\n📄 <code>{fname}</code>\n📦 Размер: {size_str}"
                        self.send_telegram_message(msg)
                
                self.known_sftp_files = current_files
                
        except Exception as e:
            debug_print(f"Error checking SFTP files: {e}", "ERROR")

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def handle_telegram_file(self, chat_id, message):
        """Handle incoming file from Telegram"""
        if chat_id not in self.waiting_for_sftp_upload or not self.waiting_for_sftp_upload[chat_id]:
            return False
            
        doc = message.get('document') or message.get('video') or message.get('audio') or message.get('photo')
        if not doc:
            return False
            
        # Handle multiple photos (Telegram sends them as a list)
        if isinstance(doc, list):
            doc = doc[-1] # Take largest photo
            
        file_id = doc.get('file_id')
        file_name = doc.get('file_name') or doc.get('file_unique_id')
        
        # If it's a photo, it might not have a filename
        if 'photo' in message and not file_name.endswith('.jpg'):
            file_name += ".jpg"

        try:
            # Get file path from Telegram
            url = f"{self.telegram_api_base_url}/bot{self.telegram_bot_token}/getFile"
            r = requests.get(url, params={'file_id': file_id}, timeout=20, verify=False)
            if r.status_code != 200:
                return False
                
            file_path_tg = r.json().get('result', {}).get('file_path')
            if not file_path_tg:
                return False
                
            # Download file
            download_url = f"{self.telegram_api_base_url}/file/bot{self.telegram_bot_token}/{file_path_tg}"
            r = requests.get(download_url, timeout=60, verify=False)
            if r.status_code == 200:
                target_path = os.path.join(self.sftp_root, file_name)
                with open(target_path, 'wb') as f:
                    f.write(r.content)
                self.send_telegram_message_to(chat_id, f"✅ Файл <code>{file_name}</code> успешно загружен")
                # We don't reset waiting_for_sftp_upload here to allow multiple files
                return True
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка при загрузке файла: {e}")
            
        return False

    def cmd_set_sftp_user(self, chat_id, user):
        if not user:
            self.send_telegram_message_to(chat_id, f"Текущий пользователь SFTP: <code>{self.sftp_user}</code>")
            return
        self.sftp_user = user
        self.save_config()
        self.send_telegram_message_to(chat_id, f"✅ Пользователь SFTP изменен на: <code>{self.sftp_user}</code>\nПерезапустите SFTP сервер для применения.")

    def cmd_set_sftp_password(self, chat_id, password):
        if not password:
            self.send_telegram_message_to(chat_id, "❌ Укажите пароль")
            return
        self.sftp_password = password
        self.save_config()
        self.send_telegram_message_to(chat_id, "✅ Пароль SFTP изменен\nПерезапустите SFTP сервер для применения.")

    def cmd_set_sftp_port(self, chat_id, port):
        if not port:
            self.send_telegram_message_to(chat_id, f"Текущий порт SFTP: <code>{self.sftp_port}</code>")
            return
        try:
            self.sftp_port = int(port)
            self.save_config()
            self.send_telegram_message_to(chat_id, f"✅ Порт SFTP изменен на: <code>{self.sftp_port}</code>\nПерезапустите SFTP сервер для применения.")
        except:
            self.send_telegram_message_to(chat_id, "❌ Некорректный порт")

    def get_system_resources(self):
        """Get CPU load and RAM usage from /proc"""
        resources = {'cpu': 'N/A', 'ram_free': 'N/A', 'ram_total': 'N/A'}
        try:
            # CPU Load (1 min average)
            if os.path.exists('/proc/loadavg'):
                with open('/proc/loadavg', 'r') as f:
                    resources['cpu'] = f.read().split()[0]
            
            # RAM Usage
            if os.path.exists('/proc/meminfo'):
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                    total = re.search(r'MemTotal:\s+(\d+)', meminfo)
                    free = re.search(r'MemAvailable:\s+(\d+)', meminfo)
                    if total:
                        resources['ram_total'] = f"{int(total.group(1)) // 1024}MB"
                    if free:
                        resources['ram_free'] = f"{int(free.group(1)) // 1024}MB"
        except:
            pass
        return resources

    def update_network_state(self):
        """Update the current network state"""
        with self.lock:
            # Get all network information
            now = time.time()
            
            # 1. Get Interfaces FIRST to know what to check
            if now - self._cache['interfaces']['ts'] > self.ttl_interfaces:
                all_interfaces, active_interfaces = self.get_interfaces_info()
                self._cache['interfaces'] = {'ts': now, 'value': (all_interfaces, active_interfaces)}
            else:
                all_interfaces, active_interfaces = self._cache['interfaces']['value']

            # 2. Check Internet on MONITORED interfaces only
            monitored_has_ip = False
            monitored_has_internet = False
            
            # Helper to check a specific interface
            def check_iface_status(if_name):
                # Find interface data in all_interfaces (even if DOWN) to correctly detect assigned IP
                if_data = next((i for i in all_interfaces if i['name'] == if_name), None)
                if if_data and if_data.get('ip_addresses'):
                    # Interface has IP
                    has_ip = True
                    # Get first IPv4 address for binding
                    src_ip = if_data['ip_addresses'][0].get('ip')
                    # Check internet via this interface
                    try:
                        has_net = self.check_internet(if_name, src_ip)
                        # debug_print(f"Check {if_name} ({src_ip}): Net={has_net}", "DEBUG")
                    except:
                        has_net = False
                    return has_ip, has_net
                # debug_print(f"Check {if_name}: No IP or Down", "DEBUG")
                return False, False

            # Check eth0 if monitored
            if getattr(self, 'monitor_eth0', True):
                ip_ok, net_ok = check_iface_status('eth0')
                if ip_ok: monitored_has_ip = True
                if net_ok: monitored_has_internet = True
            
            # Check wlan0 if monitored
            if getattr(self, 'monitor_wlan0', True):
                ip_ok, net_ok = check_iface_status('wlan0')
                if ip_ok: monitored_has_ip = True
                if net_ok: monitored_has_internet = True

            # Use these aggregated results for system state
            has_ip = monitored_has_ip
            has_internet = monitored_has_internet
            
            # debug_print(f"State: IP={has_ip}, Net={has_internet} -> LED={self.led_state}", "DEBUG")
            
            # Get local IP (just for display/legacy compatibility)
            ip_address = self.get_local_ip() 
            # If monitored interfaces don't have IP, we might want to show None or whatever get_local_ip found
            # But for LED logic, we stick to `has_ip` calculated above.
            
            # Update LED state moved to end of function to avoid flickering and respect priorities
            
            # Check internet status transition and track downtime
            # NOTE: self.check_internet_transition calls self.send_downtime_report which calls 
            # self.send_telegram_message. This is currently inside the lock. 
            # If telegram sending blocks, it might delay the LED thread slightly (1 blink cycle).
            # But since it happens rarely (only on transition), it should be acceptable.
            # If "periodic" LED freezing persists, we should move this call outside the lock.
            self.check_internet_transition(has_internet)
            
            if self.telegram_enabled and not self.telegram_initialized and has_internet:
                try:
                    if time.time() - self.telegram_last_init_attempt >= self.telegram_reinit_interval:
                        self.telegram_last_init_attempt = time.time()
                        self.init_telegram()
                except:
                    pass
            
            # Get DNS servers and check their status with caching
            # NOTE: dns checking involves network IO. Moving it OUT of the lock.
        
        # --- END OF LOCKED SECTION (Initial thought) ---
        # Actually, we need to move DNS checking and Neighbor updating OUT of the lock as well.
        # Previously they were inside.
        
        # Get DNS servers and check their status with caching (OUTSIDE LOCK)
        if now - self._cache['dns_servers']['ts'] > self.ttl_dns_servers:
            dns_servers = self.get_dns_servers()
            self._cache['dns_servers'] = {'ts': now, 'value': dns_servers}
        else:
            dns_servers = self._cache['dns_servers']['value']
        
        if now - self._cache['dns_status']['ts'] > self.ttl_dns_status:
            dns_status = self.check_dns_status(dns_servers)
            self._cache['dns_status'] = {'ts': now, 'value': dns_status}
        else:
            dns_status = self._cache['dns_status']['value']
        
        # Get neighbor information (LLDP/CDP) (OUTSIDE LOCK)
        neighbors = self.update_neighbors()
        
        # Gateway info with caching (OUTSIDE LOCK)
        if now - self._cache['gateway']['ts'] > self.ttl_gateway:
            gateway_info = self.get_gateway_info()
            self._cache['gateway'] = {'ts': now, 'value': gateway_info}
        else:
            gateway_info = self._cache['gateway']['value']
        
        # External IP with caching (OUTSIDE LOCK)
        external_ip = None
        if has_internet:
            if now - self._cache['external_ip']['ts'] > self.ttl_external_ip:
                external_ip = self.get_external_ip()
                self._cache['external_ip'] = {'ts': now, 'value': external_ip}
            else:
                external_ip = self._cache['external_ip']['value']
        
        # NOW ACQUIRE LOCK for state update
        with self.lock:
            # Check if any DNS server is working
            dns_working = any(d.get('working', False) for d in dns_status) if dns_status else False
            
            # Update LED state based on priority
            if getattr(self, 'scanning_in_progress', False):
                self.led_state = "BLUE"
            elif getattr(self, 'dump_in_progress', False):
                self.led_state = "BLINKING_BLUE"
            elif not has_ip:
                self.led_state = "RED"
            elif has_internet and dns_working:
                self.led_state = "GREEN"
            else:
                self.led_state = "BLINKING_GREEN"

            # Check internet status transition (updates self.downtime_start)
            self.check_internet_transition(has_internet)

            # Update network state
            self.current_state = {
                'ip': ip_address,
                'has_internet': has_internet,
                'interfaces': all_interfaces,
                'active_interfaces': active_interfaces,
                'gateway': gateway_info,
                'dns': dns_servers,
                'dns_status': dns_status,
                'external_ip': external_ip if has_internet else None,
                'neighbors': neighbors,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Telegram re-init check (fast, no IO usually)
            if self.telegram_enabled and not self.telegram_initialized and has_internet:
                try:
                    if time.time() - self.telegram_last_init_attempt >= self.telegram_reinit_interval:
                        self.telegram_last_init_attempt = time.time()
                        # init_telegram might block, but it's rare. Ideally move out too, but it needs state.
                        # For now leave it, it only runs once successfully.
                        self.init_telegram()
                except:
                    pass
            
            return self.current_state
    
    def should_display_update(self, new_state):
        """Check if we should update the display"""
        if self.last_display_state is None:
            return True
        
        # Check if state changed significantly
        if new_state.get('ip') != self.last_display_state.get('ip'):
            return True
        if new_state.get('has_internet') != self.last_display_state.get('has_internet'):
            return True
        
        # Check if gateway changed
        old_gateway = self.last_display_state.get('gateway')
        new_gateway = new_state.get('gateway')
        
        if old_gateway is None and new_gateway is not None:
            return True
        if old_gateway is not None and new_gateway is None:
            return True
        if old_gateway and new_gateway:
            if old_gateway.get('address') != new_gateway.get('address'):
                return True
        
        # Check if active interfaces changed
        old_active_interfaces = self.last_display_state.get('active_interfaces', [])
        new_active_interfaces = new_state.get('active_interfaces', [])
        
        if len(old_active_interfaces) != len(new_active_interfaces):
            return True
        
        for old_if, new_if in zip(old_active_interfaces, new_active_interfaces):
            # Handle interface dictionaries safely
            old_ips = []
            new_ips = []
            
            if isinstance(old_if, dict):
                old_ips = [ip.get('ip', '') for ip in old_if.get('ip_addresses', [])]
            if isinstance(new_if, dict):
                new_ips = [ip.get('ip', '') for ip in new_if.get('ip_addresses', [])]
            
            if old_ips != new_ips:
                return True
        
        # Check if DNS changed
        old_dns = self.last_display_state.get('dns', [])
        new_dns = new_state.get('dns', [])
        if old_dns != new_dns:
            return True
        
        # Check if DNS status changed
        old_dns_status = self.last_display_state.get('dns_status', [])
        new_dns_status = new_state.get('dns_status', [])
        
        if len(old_dns_status) != len(new_dns_status):
            return True
        
        for old_status, new_status in zip(old_dns_status, new_dns_status):
            if isinstance(old_status, dict) and isinstance(new_status, dict):
                if old_status.get('working') != new_status.get('working'):
                    return True
        
        # Check if neighbors changed
        old_neighbors = self.last_display_state.get('neighbors', [])
        new_neighbors = new_state.get('neighbors', [])
        
        if len(old_neighbors) != len(new_neighbors):
            return True
        
        # Compare neighbor details
        for i in range(min(len(old_neighbors), len(new_neighbors))):
            old_neighbor = old_neighbors[i]
            new_neighbor = new_neighbors[i]
            
            if old_neighbor.get('chassis_name') != new_neighbor.get('chassis_name'):
                return True
            if old_neighbor.get('interface') != new_neighbor.get('interface'):
                return True
            if old_neighbor.get('port_id') != new_neighbor.get('port_id'):
                return True
            if old_neighbor.get('serial_number') != new_neighbor.get('serial_number'):
                return True
        
        return False
    
    def display_network_info(self, state):
        """Display network information to console"""
        os.system('clear')
        
        # System status
        print(colored("▓▓▓ SYSTEM STATUS ▓▓▓", YELLOW))
        print()
        
        ip_address = state.get('ip')
        has_internet = state.get('has_internet', False)
        
        if not ip_address:
            print(colored("❌ NO IP ADDRESS", RED))
        elif not has_internet:
            print(colored("⚠️  IP: {}, NO INTERNET".format(ip_address), YELLOW))
            
            # Show current downtime if applicable
            if self.downtime_start:
                downtime_duration = (datetime.now() - self.downtime_start).total_seconds()
                duration_str = self.format_duration(downtime_duration)
                print(colored("⏱️  Downtime: {} (since {})".format(
                    duration_str, self.downtime_start.strftime("%H:%M:%S")), YELLOW))
        else:
            print(colored("✅ IP: {}, INTERNET AVAILABLE".format(ip_address), GREEN))
        print()
        
        # Network interfaces - ТОЛЬКО АКТИВНЫЕ
        print(colored("▓▓▓ ACTIVE NETWORK INTERFACES ▓▓▓", YELLOW))
        print()
        
        active_interfaces = state.get('active_interfaces', [])
        if active_interfaces:
            for iface in active_interfaces:
                # Check if iface is a dictionary
                if not isinstance(iface, dict):
                    continue
                    
                print(colored("▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬", CYAN))
                print(colored("Interface: ", PURPLE) + iface.get('name', 'N/A'))
                
                status = iface.get('status', 'DOWN')
                status_color = GREEN  # Все интерфейсы в этом списке уже активные
                status_text = "ACTIVE"
                print(colored("Status: ", CYAN) + colored(status_text, status_color))
                
                mac = iface.get('mac', 'N/A')
                if mac != 'N/A':
                    print(colored("MAC Address: ", CYAN) + mac)
                
                ip_addresses = iface.get('ip_addresses', [])
                if ip_addresses:
                    for i, ip_info in enumerate(ip_addresses):
                        if i > 0:
                            print()  # Empty line between multiple IPs
                        
                        ip = ip_info.get('ip', 'N/A')
                        cidr = ip_info.get('cidr', 'N/A')
                        mask = ip_info.get('mask', 'N/A')
                        prefix = ip_info.get('prefix', 'N/A')
                        network = ip_info.get('network', 'N/A')
                        broadcast = ip_info.get('broadcast', 'N/A')
                        
                        print(colored("IP Address: ", CYAN) + cidr)
                        print(colored("Subnet Mask: ", CYAN) + mask)
                        print(colored("Network Address: ", CYAN) + network)
                        print(colored("Broadcast Address: ", CYAN) + broadcast)
                        
                        # Additional network info for smaller networks
                        if isinstance(prefix, int) and prefix >= 24:  # Show for /24 and larger networks
                            first_usable = ip_info.get('first_usable', 'N/A')
                            last_usable = ip_info.get('last_usable', 'N/A')
                            usable_hosts = ip_info.get('usable_hosts', 0)
                            
                            print(colored("First Usable: ", CYAN) + first_usable)
                            print(colored("Last Usable: ", CYAN) + last_usable)
                            print(colored("Usable Hosts: ", CYAN) + str(usable_hosts))
                else:
                    print(colored("IP Address: ", CYAN) + colored("not assigned", RED))
                
                # Traffic statistics
                rx_bytes = iface.get('rx_bytes', 0)
                tx_bytes = iface.get('tx_bytes', 0)
                if rx_bytes > 0 or tx_bytes > 0:
                    print(colored("Traffic Statistics:", CYAN))
                    print(colored("  Received: ", CYAN) + self.format_bytes(rx_bytes))
                    print(colored("  Transmitted: ", CYAN) + self.format_bytes(tx_bytes))
                
                print()
        else:
            print(colored("No active network interfaces", RED))
            print()
        
        # Gateway
        print(colored("▓▓▓ GATEWAY ▓▓▓", YELLOW))
        print()
        
        gateway = state.get('gateway')
        if gateway:
            print(colored("Address: ", CYAN) + gateway.get('address', 'N/A'))
            interface = gateway.get('interface', 'N/A')
            if interface != 'N/A':
                print(colored("Interface: ", CYAN) + interface)
            
            available = gateway.get('available', False)
            avail_color = GREEN if available else RED
            avail_text = "✓ Available" if available else "✗ Unavailable"
            print(colored("Status: ", CYAN) + colored(avail_text, avail_color))
        else:
            print(colored("Default gateway not configured", RED))
        
        print()
        
        # DNS servers with status
        print(colored("▓▓▓ DNS SERVERS ▓▓▓", YELLOW))
        print()
        
        dns_servers = state.get('dns', [])
        dns_status_list = state.get('dns_status', [])
        
        if dns_servers and dns_servers[0] != 'None':
            print(colored("Configured DNS:", CYAN))
            
            # Match DNS servers with their status
            for i, dns_server in enumerate(dns_servers):
                status_info = None
                if i < len(dns_status_list):
                    status_info = dns_status_list[i]
                
                if status_info and isinstance(status_info, dict):
                    working = status_info.get('working', False)
                    response_time = status_info.get('response_time')
                    
                    if working:
                        status_indicator = colored("✓", GREEN)
                        status_text = colored("Working", GREEN)
                        if response_time:
                            time_text = f" ({response_time*1000:.0f} ms)"
                        else:
                            time_text = ""
                        print(f"  • {status_indicator} {dns_server} - {status_text}{time_text}")
                    else:
                        status_indicator = colored("✗", RED)
                        status_text = colored("Not responding", RED)
                        print(f"  • {status_indicator} {dns_server} - {status_text}")
                else:
                    status_indicator = colored("?", YELLOW)
                    status_text = colored("Unknown status", YELLOW)
                    print(f"  • {status_indicator} {dns_server} - {status_text}")
            
            # Show overall DNS status
            working_dns = sum(1 for s in dns_status_list if s.get('working', False))
            total_dns = len(dns_servers)
            
            print()
            if working_dns == total_dns:
                print(colored(f"DNS Status: All {total_dns} servers working", GREEN))
            elif working_dns > 0:
                print(colored(f"DNS Status: {working_dns} of {total_dns} servers working", YELLOW))
            else:
                print(colored("DNS Status: No DNS servers responding!", RED))
        else:
            print(colored("DNS servers not configured", RED))
        
        # Neighbors (LLDP/CDP)
        neighbors = state.get('neighbors', [])
        if neighbors:
            print()
            print(colored("▓▓▓ NETWORK NEIGHBORS (LLDP/CDP) ▓▓▓", YELLOW))
            print()
            
            for i, neighbor in enumerate(neighbors):
                protocol = neighbor.get('protocol', 'Unknown')
                iface = neighbor.get('interface', 'N/A')
                
                print(colored("▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬", BLUE))
                print(colored("Neighbor #{}".format(i+1), PURPLE))
                print(colored("Protocol: ", CYAN) + protocol)
                print(colored("Local Interface: ", CYAN) + iface)
                
                chassis_name = neighbor.get('chassis_name')
                if chassis_name:
                    print(colored("Device Name: ", CYAN) + colored(chassis_name, GREEN))
                elif neighbor.get('chassis_id'):
                    print(colored("Chassis ID: ", CYAN) + neighbor.get('chassis_id'))
                
                port_id = neighbor.get('port_id')
                if port_id:
                    print(colored("Remote Port: ", CYAN) + port_id)
                
                port_description = neighbor.get('port_description')
                if port_description:
                    print(colored("Port Description: ", CYAN) + port_description)
                
                # Serial number
                serial_number = neighbor.get('serial_number')
                if serial_number:
                    print(colored("Serial Number: ", CYAN) + colored(serial_number, YELLOW))
                
                capabilities = neighbor.get('capabilities')
                if capabilities:
                    if isinstance(capabilities, list):
                        caps_str = ', '.join(capabilities)
                    else:
                        caps_str = str(capabilities)
                    print(colored("Capabilities: ", CYAN) + caps_str)
                
                platform = neighbor.get('platform')
                if platform:
                    print(colored("Platform: ", CYAN) + platform)
                
                system_description = neighbor.get('system_description')
                if system_description:
                    # Truncate long descriptions
                    if len(system_description) > 60:
                        system_description = system_description[:57] + "..."
                    print(colored("System Description: ", CYAN) + system_description)
                
                management_ip = neighbor.get('management_ip')
                if management_ip:
                    print(colored("Management IP: ", CYAN) + management_ip)
                
                management_ips = neighbor.get('management_ips')
                if management_ips and isinstance(management_ips, list):
                    print(colored("Management IPs: ", CYAN) + ', '.join(management_ips))
                
                vendor = neighbor.get('vendor')
                if vendor:
                    print(colored("Vendor: ", CYAN) + vendor)
                
                # Part number (from ethtool)
                part_number = neighbor.get('part_number')
                if part_number:
                    print(colored("Part Number: ", CYAN) + part_number)
                
                print()
        else:
            # Show LLDP/CDP status even if no neighbors found
            print()
            print(colored("▓▓▓ NETWORK NEIGHBORS (LLDP/CDP) ▓▓▓", YELLOW))
            print()
            
            if not self.lldp_enabled and not self.cdp_enabled:
                print(colored("LLDP/CDP discovery disabled in configuration", YELLOW))
            elif not self.lldp_service_running:
                print(colored("⚠️  LLDP service is not running", YELLOW))
                print(colored("Run 'sudo systemctl start lldpd' to enable LLDP discovery", CYAN))
            else:
                print(colored("No network neighbors detected", CYAN))
                print(colored("Make sure connected switch supports LLDP or CDP", CYAN))
            print()
        
        # External IP
        if has_internet:
            external_ip = state.get('external_ip')
            if external_ip:
                print()
                print(colored("▓▓▓ EXTERNAL IP ▓▓▓", YELLOW))
                print()
                print(colored("Address: ", CYAN) + external_ip)
        
        # Footer
        print()
        print(colored("══════════════════════════════════════════════════════════════", PURPLE))
        print(colored("Status update: ", CYAN) + state.get('timestamp', 'N/A'))
        print(colored("Active interfaces: ", CYAN) + str(len(active_interfaces)))
        
        if neighbors:
            print(colored("Network neighbors: ", CYAN) + str(len(neighbors)))
        
        telegram_status = "✓ Enabled" if self.telegram_enabled and self.telegram_initialized else "✗ Disabled"
        print(colored("Telegram: ", CYAN) + telegram_status)
        
        # Show LLDP/CDP status
        lldp_status = "✓ LLDP" if self.lldp_enabled else "✗ LLDP"
        cdp_status = "✓ CDP" if self.cdp_enabled else "✗ CDP"
        lldp_service_status = "✓ Running" if self.lldp_service_running else "✗ Stopped"
        print(colored("Neighbor discovery: ", CYAN) + f"{lldp_status} ({lldp_service_status}), {cdp_status}")
        
        # Show downtime statistics
        if self.downtime_start and not has_internet:
            downtime_duration = (datetime.now() - self.downtime_start).total_seconds()
            print(colored("Downtime: ", CYAN) + self.format_duration(downtime_duration))
        
        print(colored("Debug: ", CYAN) + ("✓ ON" if self.debug_enabled else "✗ OFF"))
        print(colored("Press Ctrl+C to exit", YELLOW))
        
        sys.stdout.flush()
        
        # Save displayed state
        self.last_display_state = state.copy()
        
        # Send Telegram notification
        if self.telegram_enabled and self.telegram_initialized:
            self.send_telegram_notification(state)
    
    def format_bytes(self, bytes_count):
        """Format bytes to human readable"""
        if bytes_count == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
    def trigger_auto_scan(self, state):
        """Trigger automatic scan when network changes"""
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
                debug_print("Auto-scan triggered by network change", "INFO")
                # Trigger discovery scan for all authorized chats
                target = "local" # Use local subnet
                for chat_id in self.telegram_chat_ids:
                    self.cmd_scan_discover(chat_id, target)

    def monitoring_thread(self):
        """Background monitoring thread"""
        while self.running:
            try:
                # Pause monitoring if a task is in progress to save resources and avoid UI flicker
                if self.dump_in_progress or self.scanning_in_progress:
                    # Minimal sleep to not hog CPU but stay responsive to self.running change
                    time.sleep(1)
                    continue

                new_state = self.update_network_state()
                
                # Handle auto-scan and Telegram notifications
                self.trigger_auto_scan(new_state)
                self.send_telegram_notification(new_state)
                
                # Check for new files on SFTP
                self.check_sftp_files()
                
                if self.should_display_update(new_state):
                    self.display_network_info(new_state)
                
                # Sleep before next check
                time.sleep(self.check_interval)
                
                # Периодическое сохранение конфига для надежности (раз в 10 минут)
                if not hasattr(self, '_last_periodic_save'):
                    self._last_periodic_save = time.time()
                
                if time.time() - self._last_periodic_save > 600:
                    self.save_config()
                    self._last_periodic_save = time.time()
                    debug_print("Periodic config auto-save completed", "INFO")
                
                # Периодическое логирование ресурсов (раз в 5 минут)
                if not hasattr(self, '_last_resource_log'):
                    self._last_resource_log = time.time()
                
                if time.time() - self._last_resource_log > 300:
                    res = self.get_system_resources()
                    debug_print(f"System Resources: CPU Load={res['cpu']}, RAM Free={res['ram_free']}/{res['ram_total']}", "INFO")
                    self._last_resource_log = time.time()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                # Log error but continue running
                debug_print(f"Monitoring error: {e}", "ERROR")
                time.sleep(self.check_interval)
    
    def led_test(self):
        """Quick LED test on startup - cycles through Red, Green, Blue"""
        pins = [LED_RED_PIN, LED_GREEN_PIN, LED_BLUE_PIN]
        for pin in pins:
            GPIO.output(pin, GPIO.HIGH)
            time.sleep(0.2)
            GPIO.output(pin, GPIO.LOW)
            time.sleep(0.1)

    def cmd_set_ip_eth0(self, chat_id, ip, mask=None, gateway=None, dns_csv=None):
        debug_print(f"Command: /set_ip_eth0 {ip} ... triggered", "INFO")
        if ip.lower() == 'dhcp':
            try:
                self.set_interface_ip('eth0', method='dhcp')
                self.send_telegram_message_to(chat_id, "✅ Интерфейс eth0 переключен в режим DHCP")
            except Exception as e:
                self.send_telegram_message_to(chat_id, f"❌ Ошибка включения DHCP: {e}")
            return
            
        if not mask or not gateway:
             self.send_telegram_message_to(chat_id, "❌ Неверный формат. Используйте: /set_ip_eth0 dhcp ИЛИ /set_ip_eth0 <ip> <mask> <gw> [dns]")
             return
             
        # Parse DNS
        dns_list = []
        if dns_csv:
            for d in dns_csv.split(','):
                d = d.strip()
                try:
                    ipaddress.ip_address(d)
                    dns_list.append(d)
                except ValueError: pass
        
        try:
            # Validate IP/Gateway
            ipaddress.ip_address(ip)
            ipaddress.ip_address(gateway)
            
            # Form CIDR
            if '.' in mask:
                cidr = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            else:
                cidr = int(mask)
            
            ip_cidr = f"{ip}/{cidr}"
            
            self.send_telegram_message_to(chat_id, f"⚙️ Настройка eth0: {ip_cidr}, GW: {gateway}, DNS: {dns_list}")
            self.set_interface_ip('eth0', ip_cidr, gateway, dns_list, method='static')
            self.send_telegram_message_to(chat_id, "✅ Настройки eth0 применены")
            
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка: {e}")

    def cmd_set_ip_wlan0(self, chat_id, ip, mask=None, gateway=None, dns_csv=None):
        debug_print(f"Command: /set_ip_wlan0 {ip} ... triggered", "INFO")
        if ip.lower() == 'dhcp':
            try:
                self.set_interface_ip('wlan0', method='dhcp')
                self.send_telegram_message_to(chat_id, "✅ Интерфейс wlan0 переключен в режим DHCP")
            except Exception as e:
                self.send_telegram_message_to(chat_id, f"❌ Ошибка включения DHCP: {e}")
            return
            
        if not mask or not gateway:
             self.send_telegram_message_to(chat_id, "❌ Неверный формат. Используйте: /set_ip_wlan0 dhcp ИЛИ /set_ip_wlan0 <ip> <mask> <gw> [dns]")
             return

        # Parse DNS
        dns_list = []
        if dns_csv:
            for d in dns_csv.split(','):
                d = d.strip()
                try:
                    ipaddress.ip_address(d)
                    dns_list.append(d)
                except ValueError: pass
        
        try:
            ipaddress.ip_address(ip)
            ipaddress.ip_address(gateway)
            if '.' in mask:
                cidr = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            else:
                cidr = int(mask)
            ip_cidr = f"{ip}/{cidr}"
            
            self.send_telegram_message_to(chat_id, f"⚙️ Настройка wlan0: {ip_cidr}, GW: {gateway}, DNS: {dns_list}")
            self.set_interface_ip('wlan0', ip_cidr, gateway, dns_list, method='static')
            self.send_telegram_message_to(chat_id, "✅ Настройки wlan0 применены")
            
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка: {e}")

    def cmd_set_mac_eth0(self, chat_id, mac):
        debug_print(f"Command: /set_mac_eth0 {mac} triggered", "INFO")
        try:
            if mac.lower() == 'restore':
                self.restore_interface_mac('eth0')
                self.send_telegram_message_to(chat_id, "✅ Заводской MAC адрес eth0 восстановлен")
                return

            norm_mac = self.normalize_mac(mac)
            self.change_interface_mac('eth0', norm_mac)
            self.send_telegram_message_to(chat_id, f"✅ MAC адрес eth0 изменен на {norm_mac}")
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка смены MAC eth0: {e}")

    def cmd_set_mac_wlan0(self, chat_id, mac):
        debug_print(f"Command: /set_mac_wlan0 {mac} triggered", "INFO")
        try:
            if mac.lower() == 'restore':
                self.restore_interface_mac('wlan0')
                self.send_telegram_message_to(chat_id, "✅ Заводской MAC адрес wlan0 восстановлен")
                return

            norm_mac = self.normalize_mac(mac)
            self.change_interface_mac('wlan0', norm_mac)
            self.send_telegram_message_to(chat_id, f"✅ MAC адрес wlan0 изменен на {norm_mac}")
        except Exception as e:
            self.send_telegram_message_to(chat_id, f"❌ Ошибка смены MAC wlan0: {e}")


def main():
    """Main function"""
    # Check if running as root
    if os.name == 'posix' and os.geteuid() != 0:
        print(colored("ERROR: This script requires root privileges.", RED))
        print(colored("Attempting to re-run with sudo...", YELLOW))
        try:
            # Re-run the script with sudo
            os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
        except Exception as e:
            print(colored(f"Failed to re-run with sudo: {e}", RED))
            print(colored("Please run the script manually as root: sudo python3 " + sys.argv[0], RED))
            sys.exit(1)
    
    is_root = True
    monitor = None
    
    def signal_handler(sig, frame):
        """Handle Ctrl+C gracefully"""
        if monitor:
            print("\n" + colored("Shutting down NWSCAN...", BLUE))
            monitor.cleanup()
            os.system('clear')
            print(colored("NWSCAN stopped", GREEN))
            print(colored("Returning to command line...", CYAN))
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        monitor = NetworkMonitor(is_root=is_root)
        
        # Quick LED test
        monitor.led_test()
        
        # Initial display
        initial_state = monitor.update_network_state()
        monitor.display_network_info(initial_state)
        
        # Start monitoring thread
        monitor_thread = Thread(target=monitor.monitoring_thread)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Keep main thread alive
        while monitor.running:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                signal_handler(None, None)
                break
                
    except Exception as e:
        debug_print(f"Fatal error: {e}", "ERROR")
        if monitor:
            monitor.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    # Добавляем импорт struct для работы с DNS пакетами
    import struct
    main()
