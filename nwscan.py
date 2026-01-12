#!/usr/bin/env python3
"""
NWSCAN - Network Status Monitor
Background checks, display only on changes, stable LED blinking
With full IP mask display, Telegram notifications, and LLDP/CDP support
"""

import time
import socket
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
from threading import Thread, Lock

try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    from unittest.mock import MagicMock
    GPIO = MagicMock()

# ================= CONFIGURATION =================
LED_PIN = 18               # GPIO port (physical pin 12)
CHECK_HOST = "8.8.8.8"    # Server to check
CHECK_PORT = 53           # DNS port
CHECK_INTERVAL = 1        # Check interval in seconds
BLINK_INTERVAL = 0.15     # Stable blink interval
DNS_TEST_HOSTNAME = "google.com"  # Hostname for DNS resolution test

# Internet downtime logging
DOWNTIME_LOG_FILE = "/var/log/nwscan_downtime.log"  # File to log internet downtimes
DOWNTIME_REPORT_ON_RECOVERY = True  # Send report when internet is restored

# LLDP/CDP settings
LLDP_ENABLED = True        # Enable LLDP neighbor discovery
CDP_ENABLED = True         # Enable CDP neighbor discovery (Cisco)
LLDP_TIMEOUT = 2          # Timeout for LLDP/CDP commands in seconds
LLDP_RECHECK_INTERVAL = 5   # How often to recheck LLDP/CDP (seconds)

# Caching/TTL to reduce subprocess load on low-power devices
INTERFACES_TTL = 2
DNS_SERVERS_TTL = 15
DNS_STATUS_TTL = 8
GATEWAY_TTL = 5
EXTERNAL_IP_TTL = 120
AUTO_INSTALL_LLDP = True   # Automatically install LLDP tools if missing
FILTER_DUPLICATE_NEIGHBORS = True  # Filter duplicate neighbors

# Telegram configuration (ЗАМЕНИТЕ НА СВОИ ДАННЫЕ!)
TELEGRAM_BOT_TOKEN = "8545729783:AAFNhn9tBcZCEQ1PwtQF1TnwDRi9s4UrE2E"  # Получите у @BotFather
TELEGRAM_ENABLED = True                         # Включить/выключить Telegram уведомления
TELEGRAM_NOTIFY_ON_CHANGE = False               # Отправлять уведомления только при изменениях
TELEGRAM_TIMEOUT = 10                          # Таймаут для Telegram запросов (секунды)
TELEGRAM_CHAT_IDS = []                         # Список ID чатов; может быть пустым при старте

# Debug settings
DEBUG_ENABLED = False                           # Включить подробное логирование
DEBUG_TELEGRAM = False                          # Включить отладку Telegram
DEBUG_LLDP = False                              # Включить отладку LLDP/CDP
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
    """Вывод отладочной информации если включен DEBUG"""
    if DEBUG_ENABLED or (category == "LLDP" and DEBUG_LLDP) or (category == "TELEGRAM" and DEBUG_TELEGRAM):
        colors = {
            "INFO": CYAN,
            "TELEGRAM": PURPLE,
            "ERROR": RED,
            "SUCCESS": GREEN,
            "WARNING": YELLOW,
            "DOWNTIME": YELLOW,
            "LLDP": BLUE
        }
        
        color = colors.get(category, CYAN)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(colored(f"[{timestamp}] [{category}] {message}", color))

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

class NetworkMonitor:
    def __init__(self):
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
        self.lldp_timeout = LLDP_TIMEOUT
        self.lldp_recheck_interval = LLDP_RECHECK_INTERVAL
        self.auto_install_lldp = AUTO_INSTALL_LLDP
        self.filter_duplicates = FILTER_DUPLICATE_NEIGHBORS
        self.last_lldp_check = 0
        self.lldp_neighbors = {}
        self.lldp_service_checked = False
        self.lldp_service_running = False
        
        # Store config as instance variables
        self.telegram_enabled = TELEGRAM_ENABLED
        self.telegram_bot_token = TELEGRAM_BOT_TOKEN
        self.telegram_chat_ids = TELEGRAM_CHAT_IDS[:]
        self.telegram_notify_on_change = TELEGRAM_NOTIFY_ON_CHANGE
        self.telegram_timeout = TELEGRAM_TIMEOUT
        self.debug_enabled = DEBUG_ENABLED
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
        self._cache = {
            'interfaces': {'ts': 0, 'value': ([], [])},
            'dns_servers': {'ts': 0, 'value': []},
            'dns_status': {'ts': 0, 'value': []},
            'gateway': {'ts': 0, 'value': None},
            'external_ip': {'ts': 0, 'value': None},
        }
        
        # GPIO setup
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(LED_PIN, GPIO.OUT)
        GPIO.output(LED_PIN, GPIO.LOW)
        
        # Initialize Telegram
        self.init_telegram()
        
        # Start LED control thread
        self.start_led_thread()
        
        # Initialize downtime log file
        self.init_downtime_log()
        
        # Check and install LLDP tools if needed
        self.check_and_install_lldp_tools()
        
        # Start LLDP service if needed
        self.start_lldp_service()
    
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
                os.makedirs(log_dir, exist_ok=True)
            
            # Create file if it doesn't exist
            if not os.path.exists(self.downtime_log_file):
                with open(self.downtime_log_file, 'w') as f:
                    f.write("# NWSCAN Internet Downtime Log\n")
                    f.write("# Format: downtime_start,downtime_end,duration_seconds\n")
                    f.write(f"# Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                debug_print(f"Created downtime log file: {self.downtime_log_file}", "DOWNTIME")
            else:
                debug_print(f"Using existing downtime log: {self.downtime_log_file}", "DOWNTIME")
        except Exception as e:
            debug_print(f"Error initializing downtime log: {e}", "ERROR")
    
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
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/getMe"
            
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
                        
                        test_msg = "🔄 NWSCAN Monitor initialized!\nSystem is now being monitored."
                        if self.send_telegram_message_simple(test_msg):
                            debug_print("Test message sent successfully", "SUCCESS")
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
        
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
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
                ip_addresses = iface.get('ip_addresses', [])
                
                message += f"\n{emoji_interface} <b>{ifname}</b>\n"
                
                if ip_addresses:
                    for ip_info in ip_addresses:
                        cidr = ip_info.get('cidr', 'N/A')
                        message += f"  📍 <code>{cidr}</code>\n"
                else:
                    message += "  📍 <i>no IP assigned</i>\n"
                
                # Traffic
                rx_bytes = iface.get('rx_bytes', 0)
                tx_bytes = iface.get('tx_bytes', 0)
                if rx_bytes > 0 or tx_bytes > 0:
                    message += f"  📥 {self.format_bytes(rx_bytes)}\n"
                    message += f"  📤 {self.format_bytes(tx_bytes)}\n"
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
                
                message += f"  {status_emoji} {hl_code('dns', dns_server)}{time_text}\n"
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
            message = f"<b>🔄 NETWORK CHANGE DETECTED</b>\n\n" + message
        
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
        """Separate thread for LED control"""
        while not self.stop_led_thread:
            with self.lock:
                current_led_state = self.led_state
            
            if current_led_state == "OFF":
                GPIO.output(LED_PIN, GPIO.LOW)
                time.sleep(0.1)
            elif current_led_state == "BLINKING":
                GPIO.output(LED_PIN, GPIO.HIGH)
                time.sleep(BLINK_INTERVAL)
                GPIO.output(LED_PIN, GPIO.LOW)
                time.sleep(BLINK_INTERVAL)
            elif current_led_state == "ON":
                GPIO.output(LED_PIN, GPIO.HIGH)
                time.sleep(0.1)
            else:
                time.sleep(0.1)
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        self.stop_led_thread = True
        
        # Wait for LED thread to stop
        if self.led_thread:
            self.led_thread.join(timeout=1)
        
        GPIO.output(LED_PIN, GPIO.LOW)
        time.sleep(0.1)
        GPIO.cleanup()
        
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
        """Test if DNS server can resolve google.com"""
        # Method 1: Socket UDP query
        try:
            # Create UDP socket for DNS query
            dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_socket.settimeout(2)
            
            # Build a simple DNS query for google.com (type A)
            query_id = 12345
            flags = 0x0100  # Standard query, recursion desired
            questions = 1
            answer_rrs = 0
            authority_rrs = 0
            additional_rrs = 0
            
            # Header
            header = struct.pack('!HHHHHH', query_id, flags, questions, 
                                answer_rrs, authority_rrs, additional_rrs)
            
            # Query for google.com
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
            response, _ = dns_socket.recvfrom(512)
            dns_socket.close()
            
            # Check if response is valid
            if len(response) > 12:
                # Check response ID matches query ID
                resp_id = struct.unpack('!H', response[:2])[0]
                if resp_id == query_id:
                    # Check response code (bits 12-15)
                    rcode = (struct.unpack('!H', response[2:4])[0] & 0x000F)
                    if rcode == 0:  # No error
                        return True
        except Exception as e:
            debug_print(f"DNS Socket check failed for {dns_server}: {e}", "WARNING")
        
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
    
    def check_internet(self):
        """Check internet connectivity with timeout"""
        try:
            socket.setdefaulttimeout(1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
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
        """Get detailed information about network interfaces"""
        interfaces = []
        active_interfaces = []
        output = self.run_command(['ip', '-o', 'link', 'show'])
        
        if output:
            for line in output.split('\n'):
                if not line:
                    continue
                    
                parts = line.split(':')
                if len(parts) >= 2:
                    ifname = parts[1].strip()
                    
                    if ifname == 'lo':
                        continue
                    if ifname == 'eth0' and not self.monitor_eth0:
                        continue
                    if ifname == 'wlan0' and not self.monitor_wlan0:
                        continue
                    
                    status = 'UP' if 'UP' in line else 'DOWN'
                    is_active = status == 'UP'
                    
                    # Get MAC address
                    mac_output = self.run_command(['ip', 'link', 'show', ifname])
                    mac = 'N/A'
                    if mac_output:
                        mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', mac_output)
                        if mac_match:
                            mac = mac_match.group(1)
                    
                    # Get IP addresses with full information
                    ip_output = self.run_command(['ip', '-4', '-o', 'addr', 'show', ifname])
                    ip_addresses = []
                    
                    if ip_output:
                        for ip_line in ip_output.split('\n'):
                            if 'inet ' in ip_line:
                                parts = ip_line.strip().split()
                                if len(parts) >= 4:
                                    ip_cidr = parts[3]
                                    ip_info = calculate_network_info(ip_cidr)
                                    if ip_info:
                                        ip_addresses.append(ip_info)
                    
                    # Get traffic statistics
                    rx_bytes = 0
                    tx_bytes = 0
                    try:
                        rx_path = f'/sys/class/net/{ifname}/statistics/rx_bytes'
                        tx_path = f'/sys/class/net/{ifname}/statistics/tx_bytes'
                        if os.path.exists(rx_path):
                            with open(rx_path, 'r') as f:
                                rx_bytes = int(f.read().strip())
                        if os.path.exists(tx_path):
                            with open(tx_path, 'r') as f:
                                tx_bytes = int(f.read().strip())
                    except:
                        pass
                    
                    interface_info = {
                        'name': ifname,
                        'status': status,
                        'mac': mac,
                        'ip_addresses': ip_addresses,
                        'rx_bytes': rx_bytes,
                        'tx_bytes': tx_bytes
                    }
                    
                    interfaces.append(interface_info)
                    
                    # Добавляем в активные интерфейсы только если статус UP
                    if is_active:
                        active_interfaces.append(interface_info)
        
        return interfaces, active_interfaces

    def change_interface_mac(self, iface, new_mac):
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
        """Get DNS servers from resolv.conf and DHCP"""
        servers = []
        
        # Method 1: Check systemd-resolved
        try:
            resolvectl_output = self.run_command(['resolvectl', 'status'])
            if resolvectl_output:
                for line in resolvectl_output.split('\n'):
                    if 'DNS Servers:' in line:
                        dns_line = line.split(':', 1)[1].strip()
                        dns_servers = dns_line.split()
                        servers.extend(dns_servers)
        except Exception as e:
            pass
        
        # Method 2: Check resolv.conf
        try:
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_server = parts[1]
                                if dns_server not in servers:
                                    servers.append(dns_server)
        except Exception as e:
            pass
        
        # Method 3: Check DHCP leases
        try:
            # Check for dhclient leases
            lease_files = [
                '/var/lib/dhcp/dhclient.leases',
                '/var/lib/dhclient/dhclient.leases',
                '/var/lib/dhcp/dhclient.eth0.leases',
                '/var/lib/dhcp/dhclient.wlan0.leases'
            ]
            
            for lease_file in lease_files:
                if os.path.exists(lease_file):
                    try:
                        with open(lease_file, 'r') as f:
                            content = f.read()
                            # Искать DNS серверы в lease файле
                            dns_matches = re.findall(r'option\s+domain-name-servers\s+([\d\.\s,]+);', content)
                            for match in dns_matches:
                                dns_list = re.findall(r'\d+\.\d+\.\d+\.\d+', match)
                                for dns in dns_list:
                                    if dns not in servers:
                                        servers.append(dns)
                    except:
                        pass
        except Exception as e:
            pass
        
        # Method 4: Check NetworkManager
        try:
            nm_output = self.run_command(['nmcli', 'device', 'show'])
            if nm_output:
                for line in nm_output.split('\n'):
                    if 'IP4.DNS' in line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) >= 2:
                            dns_server = parts[1].strip()
                            if dns_server and dns_server not in servers:
                                servers.append(dns_server)
        except Exception as e:
            pass
        
        # Method 5: Check /etc/network/interfaces
        try:
            if os.path.exists('/etc/network/interfaces'):
                with open('/etc/network/interfaces', 'r') as f:
                    content = f.read()
                    # Искать dns-nameservers в конфигурации
                    dns_matches = re.findall(r'dns-nameservers\s+([\d\.\s]+)', content)
                    for match in dns_matches:
                        dns_servers = match.strip().split()
                        for dns in dns_servers:
                            if dns not in servers:
                                servers.append(dns)
        except Exception as e:
            pass
        
        # Remove duplicates and empty entries
        servers = [s for s in servers if s and s.strip() and s != '0.0.0.0']
        servers = list(dict.fromkeys(servers))  # Remove duplicates while preserving order
        
        # Fallback to common DNS servers if none found
        if not servers:
            servers = ['None']
        
        return servers
    
    def check_dns_status(self, dns_servers):
        """Check status of each DNS server"""
        dns_status = []
        
        for dns in dns_servers:
            if dns == 'None':
                dns_status.append({'server': 'None', 'working': False, 'response_time': None})
                continue
                
            try:
                start_time = time.time()
                working = self.test_dns_resolution(dns)
                response_time = time.time() - start_time if working else None
                
                dns_status.append({
                    'server': dns,
                    'working': working,
                    'response_time': response_time
                })
            except:
                dns_status.append({
                    'server': dns,
                    'working': False,
                    'response_time': None
                })
        
        return dns_status
    
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
    
    def update_network_state(self):
        """Update the current network state"""
        with self.lock:
            # Get all network information
            now = time.time()
            ip_address = self.get_local_ip()
            has_ip = ip_address is not None
            has_internet = False
            
            # Check internet only if we have an IP
            if has_ip:
                try:
                    has_internet = self.check_internet()
                except:
                    has_internet = False
            
            # Check internet status transition and track downtime
            self.check_internet_transition(has_internet)
            
            if self.telegram_enabled and not self.telegram_initialized and has_internet:
                try:
                    if time.time() - self.telegram_last_init_attempt >= self.telegram_reinit_interval:
                        self.telegram_last_init_attempt = time.time()
                        self.init_telegram()
                except:
                    pass
            
            # Update LED state (actual control happens in separate thread)
            if not has_ip:
                self.led_state = "OFF"
            elif has_ip and not has_internet:
                self.led_state = "BLINKING"
            else:
                self.led_state = "ON"
            
            # Get interfaces (все и активные отдельно) with caching
            if now - self._cache['interfaces']['ts'] > self.ttl_interfaces:
                all_interfaces, active_interfaces = self.get_interfaces_info()
                self._cache['interfaces'] = {'ts': now, 'value': (all_interfaces, active_interfaces)}
            else:
                all_interfaces, active_interfaces = self._cache['interfaces']['value']
            
            # Get DNS servers and check their status with caching
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
            
            # Get neighbor information (LLDP/CDP)
            neighbors = self.update_neighbors()
            
            # Gateway info with caching
            if now - self._cache['gateway']['ts'] > self.ttl_gateway:
                gateway_info = self.get_gateway_info()
                self._cache['gateway'] = {'ts': now, 'value': gateway_info}
            else:
                gateway_info = self._cache['gateway']['value']
            
            # External IP with caching
            external_ip = None
            if has_internet:
                if now - self._cache['external_ip']['ts'] > self.ttl_external_ip:
                    external_ip = self.get_external_ip()
                    self._cache['external_ip'] = {'ts': now, 'value': external_ip}
                else:
                    external_ip = self._cache['external_ip']['value']
            
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
    
    def monitoring_thread(self):
        """Background monitoring thread"""
        while self.running:
            try:
                new_state = self.update_network_state()
                
                if self.should_display_update(new_state):
                    self.display_network_info(new_state)
                
                # Sleep before next check
                time.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                # Log error but continue running
                debug_print(f"Monitoring error: {e}", "ERROR")
                time.sleep(self.check_interval)
    
    def led_test(self):
        """Quick LED test on startup"""
        for _ in range(3):
            GPIO.output(LED_PIN, GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(LED_PIN, GPIO.LOW)
            time.sleep(0.1)

def main():
    """Main function"""
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        print("Use: sudo python3", sys.argv[0])
        sys.exit(1)
    
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
        monitor = NetworkMonitor()
        
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
