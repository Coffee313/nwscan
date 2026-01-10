#!/usr/bin/env python3
"""
NWSCAN - Network Status Monitor
Background checks, display only on changes, stable LED blinking
With full IP mask display and Telegram notifications
"""

import RPi.GPIO as GPIO
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
from datetime import datetime
from threading import Thread, Lock

# ================= CONFIGURATION =================
LED_PIN = 18               # GPIO port (physical pin 12)
CHECK_HOST = "8.8.8.8"    # Server to check
CHECK_PORT = 53           # DNS port
CHECK_INTERVAL = 1        # Check interval in seconds
BLINK_INTERVAL = 0.15     # Stable blink interval
DNS_TEST_HOSTNAME = "google.com"  # Hostname for DNS resolution test

# Telegram configuration (ЗАМЕНИТЕ НА СВОИ ДАННЫЕ!)
# 1. Создайте бота через @BotFather в Telegram
# 2. Получите токен бота
# 3. Получите Chat ID (можно через @getidsbot или отправьте сообщение боту и проверьте /getUpdates)
TELEGRAM_BOT_TOKEN = "8545729783:AAFNhn9tBcZCEQ1PwtQF1TnwDRi9s4UrE2E"  # Получите у @BotFather
TELEGRAM_CHAT_ID = "161906598"      # ID чата для отправки сообщений
TELEGRAM_ENABLED = True                         # Включить/выключить Telegram уведомления
TELEGRAM_NOTIFY_ON_CHANGE = False               # Отправлять уведомления только при изменениях
TELEGRAM_TIMEOUT = 10                          # Таймаут для Telegram запросов (секунды)
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
        print(f"Error calculating network info for {ip_cidr}: {e}")
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
            'external_ip': None
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
        
        # Store Telegram config as instance variables
        self.telegram_enabled = TELEGRAM_ENABLED
        self.telegram_bot_token = TELEGRAM_BOT_TOKEN
        self.telegram_chat_id = TELEGRAM_CHAT_ID
        self.telegram_notify_on_change = TELEGRAM_NOTIFY_ON_CHANGE
        self.telegram_timeout = TELEGRAM_TIMEOUT
        
        # GPIO setup
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(LED_PIN, GPIO.OUT)
        GPIO.output(LED_PIN, GPIO.LOW)
        
        # Initialize Telegram
        self.init_telegram()
        
        # Start LED control thread
        self.start_led_thread()
    
    def init_telegram(self):
        """Initialize Telegram bot with detailed debugging"""
        if not self.telegram_enabled:
            print(colored("Telegram notifications disabled by configuration", YELLOW))
            return
        
        print(colored("\n" + "="*60, BLUE))
        print(colored("TELEGRAM INITIALIZATION", BLUE))
        print(colored("="*60, BLUE))
        
        # Check if token and chat_id are configured
        if self.telegram_bot_token == "YOUR_TELEGRAM_BOT_TOKEN":
            print(colored("✗ Telegram bot token not configured!", RED))
            print(colored("  Please set TELEGRAM_BOT_TOKEN in the configuration", YELLOW))
            self.telegram_enabled = False
            return
        
        if self.telegram_chat_id == "YOUR_TELEGRAM_CHAT_ID":
            print(colored("✗ Telegram chat ID not configured!", RED))
            print(colored("  Please set TELEGRAM_CHAT_ID in the configuration", YELLOW))
            self.telegram_enabled = False
            return
        
        print(colored(f"Bot Token: {self.telegram_bot_token[:10]}...", CYAN))
        print(colored(f"Chat ID: {self.telegram_chat_id}", CYAN))
        
        try:
            # Test Telegram connection
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/getMe"
            print(colored(f"\nTesting Telegram API connection...", CYAN))
            print(colored(f"URL: {url}", CYAN))
            
            try:
                response = requests.get(url, timeout=self.telegram_timeout, verify=False)
                print(colored(f"HTTP Status: {response.status_code}", CYAN))
                
                if response.status_code == 200:
                    result = response.json()
                    print(colored(f"API Response: {json.dumps(result, indent=2)}", CYAN))
                    
                    if result.get('ok'):
                        bot_info = result['result']
                        self.telegram_initialized = True
                        print(colored(f"✓ Telegram bot connected successfully!", GREEN))
                        print(colored(f"  Bot: @{bot_info['username']} (ID: {bot_info['id']})", GREEN))
                        
                        # Test sending a message
                        print(colored("\nTesting message sending...", CYAN))
                        test_msg = "🔄 NWSCAN Monitor initialized!\nSystem is now being monitored."
                        if self.send_telegram_message_simple(test_msg):
                            print(colored("✓ Test message sent successfully!", GREEN))
                        else:
                            print(colored("✗ Failed to send test message", YELLOW))
                    else:
                        error_msg = result.get('description', 'Unknown error')
                        print(colored(f"✗ Telegram API error: {error_msg}", RED))
                elif response.status_code == 404:
                    print(colored("✗ Invalid bot token or URL", RED))
                    print(colored("  Please check your TELEGRAM_BOT_TOKEN", YELLOW))
                elif response.status_code == 401:
                    print(colored("✗ Unauthorized - invalid bot token", RED))
                    print(colored("  Please check your TELEGRAM_BOT_TOKEN", YELLOW))
                else:
                    print(colored(f"✗ Unexpected HTTP status: {response.status_code}", RED))
                    print(colored(f"Response: {response.text}", RED))
                    
            except requests.exceptions.ConnectionError as e:
                print(colored(f"✗ Connection error: {e}", RED))
                print(colored("  Check your internet connection", YELLOW))
            except requests.exceptions.Timeout as e:
                print(colored(f"✗ Connection timeout: {e}", RED))
                print(colored("  Check your internet connection or increase TELEGRAM_TIMEOUT", YELLOW))
            except Exception as e:
                print(colored(f"✗ Unexpected error: {type(e).__name__}: {e}", RED))
                
        except Exception as e:
            print(colored(f"✗ Telegram setup error: {e}", RED))
            self.telegram_initialized = False
        
        print(colored("="*60, BLUE))
    
    def send_telegram_message_simple(self, message):
        """Простой метод отправки сообщения в Telegram с отладкой"""
        if not self.telegram_enabled:
            print(colored("Telegram disabled, not sending message", YELLOW))
            return False
        
        if not self.telegram_initialized:
            print(colored("Telegram not initialized, not sending message", YELLOW))
            return False
        
        if self.telegram_errors >= self.max_telegram_errors:
            print(colored("Too many Telegram errors, notifications disabled", RED))
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            
            # Подготовка параметров
            params = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }
            
            print(colored(f"\nSending Telegram message...", CYAN))
            print(colored(f"URL: {url}", CYAN))
            print(colored(f"Chat ID: {self.telegram_chat_id}", CYAN))
            print(colored(f"Message length: {len(message)} chars", CYAN))
            
            # Отправка запроса
            response = requests.post(url, data=params, timeout=self.telegram_timeout, verify=False)
            
            print(colored(f"HTTP Status: {response.status_code}", CYAN))
            
            if response.status_code == 200:
                result = response.json()
                print(colored(f"API Response: {json.dumps(result, indent=2)}", CYAN))
                
                if result.get('ok'):
                    print(colored("✓ Message sent successfully!", GREEN))
                    self.telegram_errors = 0  # Сброс счетчика ошибок
                    return True
                else:
                    error_msg = result.get('description', 'Unknown error')
                    print(colored(f"✗ Telegram API error: {error_msg}", RED))
                    self.telegram_errors += 1
            else:
                print(colored(f"✗ HTTP error: {response.status_code}", RED))
                print(colored(f"Response: {response.text}", RED))
                self.telegram_errors += 1
                
        except requests.exceptions.ConnectionError as e:
            print(colored(f"✗ Connection error: {e}", RED))
            self.telegram_errors += 1
        except requests.exceptions.Timeout as e:
            print(colored(f"✗ Timeout error: {e}", RED))
            self.telegram_errors += 1
        except requests.exceptions.RequestException as e:
            print(colored(f"✗ Request error: {e}", RED))
            self.telegram_errors += 1
        except Exception as e:
            print(colored(f"✗ Unexpected error: {type(e).__name__}: {e}", RED))
            self.telegram_errors += 1
        
        print(colored(f"Telegram errors count: {self.telegram_errors}/{self.max_telegram_errors}", RED))
        return False
    
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
        
        # Build message
        message = f"<b>🛰️ NWSCAN - {hostname}</b>\n"
        message += f"<i>{timestamp}</i>\n\n"
        
        # System status
        message += "<b>📊 SYSTEM STATUS</b>\n"
        if not ip_address:
            message += f"{emoji_down} <b>NO IP ADDRESS</b>\n"
        elif not has_internet:
            message += f"{emoji_status} IP: <code>{ip_address}</code>\n<b>NO INTERNET CONNECTION</b>\n"
        else:
            message += f"{emoji_status} IP: <code>{ip_address}</code>\n<b>INTERNET AVAILABLE</b>\n"
        
        # External IP
        if has_internet and external_ip:
            message += f"🌍 External: <code>{external_ip}</code>\n"
        
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
        message += "<b>🌐 GATEWAY</b>\n"
        if gateway:
            gateway_addr = gateway.get('address', 'N/A')
            available = gateway.get('available', False)
            status_emoji = emoji_up if available else emoji_down
            
            message += f"{status_emoji} <code>{gateway_addr}</code>\n"
            if not available:
                message += "  <i>(unreachable)</i>\n"
        else:
            message += f"{emoji_down} <i>Not configured</i>\n"
        
        message += "\n"
        
        # DNS servers
        message += "<b>🔍 DNS SERVERS</b>\n"
        if dns_servers and dns_servers[0] != 'None':
            working_dns = sum(1 for s in dns_status_list if s.get('working', False))
            total_dns = len(dns_servers)
            
            status_emoji = "✅" if working_dns == total_dns else "⚠️" if working_dns > 0 else "❌"
            message += f"{status_emoji} <b>{working_dns}/{total_dns} working</b>\n"
            
            for i, dns_server in enumerate(dns_servers):
                status_info = dns_status_list[i] if i < len(dns_status_list) else {}
                working = status_info.get('working', False)
                response_time = status_info.get('response_time')
                
                status_emoji = emoji_dns_ok if working else emoji_dns_fail
                time_text = f" ({response_time*1000:.0f} ms)" if response_time else ""
                
                message += f"  {status_emoji} <code>{dns_server}</code>{time_text}\n"
        else:
            message += "❌ <i>No DNS servers configured</i>\n"
        
        # Change indicator if present
        if 'change_indicator' in state:
            message = f"<b>🔄 NETWORK CHANGE DETECTED</b>\n\n" + message
        
        # Add debug info if enabled
        if self.telegram_errors > 0:
            message += f"\n<i>Telegram errors: {self.telegram_errors}</i>\n"
        
        return message
    
    def send_telegram_notification(self, state, force=False):
        """Send notification to Telegram if state changed"""
        print(colored(f"\n[Telegram] Checking if should send notification...", CYAN))
        print(colored(f"  Enabled: {self.telegram_enabled}", CYAN))
        print(colored(f"  Initialized: {self.telegram_initialized}", CYAN))
        print(colored(f"  Force send: {force}", CYAN))
        
        if not self.telegram_enabled:
            print(colored("  ✗ Telegram disabled, not sending", YELLOW))
            return
        
        if not self.telegram_initialized:
            print(colored("  ✗ Telegram not initialized, not sending", YELLOW))
            return
        
        # Check if we should send notification
        should_send = force or not self.telegram_notify_on_change
        
        print(colored(f"  Notify on change: {self.telegram_notify_on_change}", CYAN))
        print(colored(f"  Should send (before change check): {should_send}", CYAN))
        
        if self.telegram_notify_on_change and self.last_telegram_state:
            print(colored("  Checking for state changes...", CYAN))
            # Check if state changed significantly
            old_state = self.last_telegram_state
            new_state = state
            
            # Compare key parameters
            changes = []
            
            # IP address change
            old_ip = old_state.get('ip')
            new_ip = new_state.get('ip')
            if old_ip != new_ip:
                if old_ip and new_ip:
                    changes.append(f"IP changed: {old_ip} → {new_ip}")
                elif new_ip:
                    changes.append(f"IP assigned: {new_ip}")
                else:
                    changes.append("IP lost")
                print(colored(f"  ✓ IP changed: {old_ip} -> {new_ip}", GREEN))
            
            # Internet status change
            old_internet = old_state.get('has_internet', False)
            new_internet = new_state.get('has_internet', False)
            if old_internet != new_internet:
                if new_internet:
                    changes.append("Internet restored")
                else:
                    changes.append("Internet lost")
                print(colored(f"  ✓ Internet changed: {old_internet} -> {new_internet}", GREEN))
            
            # Gateway change
            old_gateway = old_state.get('gateway', {}).get('address')
            new_gateway = new_state.get('gateway', {}).get('address')
            if old_gateway != new_gateway:
                if old_gateway and new_gateway:
                    changes.append(f"Gateway changed: {old_gateway} → {new_gateway}")
                elif new_gateway:
                    changes.append(f"Gateway set: {new_gateway}")
                else:
                    changes.append("Gateway lost")
                print(colored(f"  ✓ Gateway changed: {old_gateway} -> {new_gateway}", GREEN))
            
            # Active interfaces count change
            old_if_count = len(old_state.get('active_interfaces', []))
            new_if_count = len(new_state.get('active_interfaces', []))
            if old_if_count != new_if_count:
                changes.append(f"Active interfaces: {old_if_count} → {new_if_count}")
                print(colored(f"  ✓ Interface count changed: {old_if_count} -> {new_if_count}", GREEN))
            
            if changes:
                should_send = True
                print(colored(f"  ✓ Changes detected: {len(changes)} changes", GREEN))
                # Add change indicator to message
                state = state.copy()
                state['change_indicator'] = " • " + "\n • ".join(changes)
            else:
                print(colored("  ✗ No significant changes detected", YELLOW))
        
        print(colored(f"  Final decision: should send = {should_send}", CYAN))
        
        if should_send:
            message = self.format_state_for_telegram(state)
            print(colored(f"  Message length: {len(message)} chars", CYAN))
            
            if self.send_telegram_message(message):
                print(colored("  ✓ Telegram notification sent successfully", GREEN))
                self.last_telegram_state = state.copy()
            else:
                print(colored("  ✗ Failed to send Telegram notification", RED))
        else:
            print(colored("  ✗ Skipping notification (no changes)", YELLOW))
    
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
        
        # Send shutdown notification
        if self.telegram_enabled and self.telegram_initialized:
            print(colored("\nSending shutdown notification to Telegram...", BLUE))
            self.send_telegram_message("🛑 NWSCAN Monitor stopped\nSystem monitoring ended.")
            print(colored("Shutdown notification sent", GREEN))
        
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
        except:
            pass
        
        # Fallback method using nslookup/dig
        try:
            # Try using dig
            result = subprocess.run(['dig', f'@{dns_server}', DNS_TEST_HOSTNAME, '+time=1', '+tries=1'],
                                  capture_output=True, text=True, timeout=2)
            if 'ANSWER SECTION' in result.stdout and 'google.com' in result.stdout:
                return True
        except:
            pass
        
        try:
            # Try using nslookup
            result = subprocess.run(['nslookup', DNS_TEST_HOSTNAME, dns_server],
                                  capture_output=True, text=True, timeout=2)
            if 'Address:' in result.stdout and 'google.com' in result.stdout:
                return True
        except:
            pass
        
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
            ip_address = self.get_local_ip()
            has_ip = ip_address is not None
            has_internet = False
            
            # Check internet only if we have an IP
            if has_ip:
                try:
                    has_internet = self.check_internet()
                except:
                    has_internet = False
            
            # Update LED state (actual control happens in separate thread)
            if not has_ip:
                self.led_state = "OFF"
            elif has_ip and not has_internet:
                self.led_state = "BLINKING"
            else:
                self.led_state = "ON"
            
            # Get interfaces (все и активные отдельно)
            all_interfaces, active_interfaces = self.get_interfaces_info()
            
            # Get DNS servers and check their status
            dns_servers = self.get_dns_servers()
            dns_status = self.check_dns_status(dns_servers)
            
            # Update network state
            self.current_state = {
                'ip': ip_address,
                'has_internet': has_internet,
                'interfaces': all_interfaces,
                'active_interfaces': active_interfaces,
                'gateway': self.get_gateway_info(),
                'dns': dns_servers,
                'dns_status': dns_status,
                'external_ip': self.get_external_ip() if has_internet else None,
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
        telegram_status = "✓ Enabled" if self.telegram_enabled and self.telegram_initialized else "✗ Disabled"
        print(colored("Telegram: ", CYAN) + telegram_status)
        print(colored("Press Ctrl+C to exit", YELLOW))
        
        sys.stdout.flush()
        
        # Save displayed state
        self.last_display_state = state.copy()
        
        # Send Telegram notification
        if self.telegram_enabled and self.telegram_initialized:
            print(colored("\n[Telegram] Calling send_telegram_notification...", BLUE))
            self.send_telegram_notification(state)
        else:
            print(colored("\n[Telegram] Not sending - disabled or not initialized", YELLOW))
            print(colored(f"  Enabled: {self.telegram_enabled}, Initialized: {self.telegram_initialized}", YELLOW))
    
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
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                # Log error but continue running
                print(f"Monitoring error: {e}", file=sys.stderr)
                time.sleep(CHECK_INTERVAL)
    
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
        
        # Send initial Telegram notification (if NOT notify on change)
        if monitor.telegram_enabled and monitor.telegram_initialized and not TELEGRAM_NOTIFY_ON_CHANGE:
            print(colored("\n[Telegram] Sending initial notification (notify on change is OFF)...", BLUE))
            monitor.send_telegram_notification(initial_state, force=True)
        
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
        print(f"Fatal error: {e}", file=sys.stderr)
        if monitor:
            monitor.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    # Добавляем импорт struct для работы с DNS пакетами
    import struct
    main()