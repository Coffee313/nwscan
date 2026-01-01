#!/usr/bin/env python3
"""
NWSCAN - Network Status Monitor
Background checks, display only on changes, stable LED blinking
With full IP mask display
"""

import RPi.GPIO as GPIO
import time
import socket
import subprocess
import os
import sys
import re
import signal
from datetime import datetime
from threading import Thread, Lock

# ================= CONFIGURATION =================
LED_PIN = 18               # GPIO port (physical pin 12)
CHECK_HOST = "8.8.8.8"    # Server to check
CHECK_PORT = 53           # DNS port
CHECK_INTERVAL = 1        # Check interval in seconds
BLINK_INTERVAL = 0.15     # Stable blink interval
# =================================================

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
    except:
        return None

class NetworkMonitor:
    def __init__(self):
        self.lock = Lock()
        self.current_state = {
            'ip': None,
            'has_internet': False,
            'interfaces': [],
            'gateway': None,
            'dns': [],
            'external_ip': None
        }
        self.last_display_state = None
        self.running = True
        self.led_state = "OFF"
        
        # GPIO setup
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(LED_PIN, GPIO.OUT)
        GPIO.output(LED_PIN, GPIO.LOW)
        
    def cleanup(self):
        self.running = False
        GPIO.output(LED_PIN, GPIO.LOW)
        GPIO.cleanup()
        
    def run_command(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return result.stdout.strip()
        except:
            return ""
    
    def get_local_ip(self):
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
        
        try:
            output = self.run_command(['hostname', '-I'])
            if output:
                ips = output.split()
                for ip in ips:
                    if ip and not ip.startswith('127.'):
                        return ip
        except:
            pass
        
        return None
    
    def check_internet(self):
        try:
            socket.setdefaulttimeout(2)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((CHECK_HOST, CHECK_PORT))
            sock.close()
            return True
        except:
            return False
    
    def get_interfaces_info(self):
        interfaces = []
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
                    
                    # Get MAC address
                    mac_output = self.run_command(['ip', 'link', 'show', ifname])
                    mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', mac_output)
                    mac = mac_match.group(1) if mac_match else 'N/A'
                    
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
                    
                    interfaces.append({
                        'name': ifname,
                        'status': status,
                        'mac': mac,
                        'ip_addresses': ip_addresses,
                        'rx_bytes': rx_bytes,
                        'tx_bytes': tx_bytes
                    })
        
        return interfaces
    
    def get_gateway_info(self):
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
        servers = []
        try:
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            servers.append(line.split()[1])
        except:
            pass
        return servers
    
    def get_external_ip(self):
        try:
            external_ip = self.run_command(['curl', '-s', 'ifconfig.me'])
            if external_ip and len(external_ip.split('.')) == 4:
                return external_ip
        except:
            pass
        return None
    
    def update_network_state(self):
        with self.lock:
            # Get all network information
            ip_address = self.get_local_ip()
            has_ip = ip_address is not None
            has_internet = self.check_internet() if has_ip else False
            
            # Update LED state
            if not has_ip:
                self.led_state = "OFF"
                GPIO.output(LED_PIN, GPIO.LOW)
            elif has_ip and not has_internet:
                self.led_state = "BLINKING"
                # Stable blinking
                GPIO.output(LED_PIN, GPIO.HIGH)
                time.sleep(BLINK_INTERVAL)
                GPIO.output(LED_PIN, GPIO.LOW)
            else:
                self.led_state = "ON"
                GPIO.output(LED_PIN, GPIO.HIGH)
            
            # Update network state
            self.current_state = {
                'ip': ip_address,
                'has_internet': has_internet,
                'interfaces': self.get_interfaces_info(),
                'gateway': self.get_gateway_info(),
                'dns': self.get_dns_servers(),
                'external_ip': self.get_external_ip() if has_internet else None,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            return self.current_state
    
    def should_display_update(self, new_state):
        if self.last_display_state is None:
            return True
        
        # Check if state changed significantly
        if new_state['ip'] != self.last_display_state.get('ip'):
            return True
        if new_state['has_internet'] != self.last_display_state.get('has_internet'):
            return True
        
        # Check if gateway changed
        old_gateway = self.last_display_state.get('gateway', {}).get('address')
        new_gateway = new_state.get('gateway', {}).get('address')
        if old_gateway != new_gateway:
            return True
        
        # Check if any interface IP changed
        old_interfaces = self.last_display_state.get('interfaces', [])
        new_interfaces = new_state.get('interfaces', [])
        
        if len(old_interfaces) != len(new_interfaces):
            return True
        
        for old_if, new_if in zip(old_interfaces, new_interfaces):
            old_ips = [ip.get('ip', '') for ip in old_if.get('ip_addresses', [])]
            new_ips = [ip.get('ip', '') for ip in new_if.get('ip_addresses', [])]
            if old_ips != new_ips:
                return True
        
        return False
    
    def display_network_info(self, state):
        os.system('clear')
        
        # System status
        print(colored("▓▓▓ SYSTEM STATUS ▓▓▓", YELLOW))
        print()
        
        if not state['ip']:
            print(colored("❌ NO IP ADDRESS", RED))
        elif not state['has_internet']:
            print(colored("⚠️  IP: {}, NO INTERNET".format(state['ip']), YELLOW))
        else:
            print(colored("✅ IP: {}, INTERNET AVAILABLE".format(state['ip']), GREEN))
        print()
        
        # Network interfaces
        print(colored("▓▓▓ NETWORK INTERFACES ▓▓▓", YELLOW))
        print()
        
        if state['interfaces']:
            for iface in state['interfaces']:
                print(colored("▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬", CYAN))
                print(colored("Interface: ", PURPLE) + iface['name'])
                
                status_color = GREEN if iface['status'] == 'UP' else RED
                status_text = "ACTIVE" if iface['status'] == 'UP' else "INACTIVE"
                print(colored("Status: ", CYAN) + colored(status_text, status_color))
                
                if iface['mac'] != 'N/A':
                    print(colored("MAC Address: ", CYAN) + iface['mac'])
                
                if iface['ip_addresses']:
                    for i, ip_info in enumerate(iface['ip_addresses']):
                        if i > 0:
                            print()  # Empty line between multiple IPs
                        
                        print(colored("IP Address: ", CYAN) + ip_info['ip'])
                        print(colored("CIDR Notation: ", CYAN) + ip_info['cidr'])
                        print(colored("Subnet Mask: ", CYAN) + ip_info['mask'] + colored(f" (/{ip_info['prefix']})", CYAN))
                        print(colored("Network Address: ", CYAN) + ip_info['network'])
                        print(colored("Broadcast Address: ", CYAN) + ip_info['broadcast'])
                        
                        # Additional network info for smaller networks
                        if ip_info['prefix'] >= 24:  # Show for /24 and larger networks
                            print(colored("First Usable: ", CYAN) + ip_info['first_usable'])
                            print(colored("Last Usable: ", CYAN) + ip_info['last_usable'])
                            print(colored("Usable Hosts: ", CYAN) + str(ip_info['usable_hosts']))
                else:
                    print(colored("IP Address: ", CYAN) + colored("not assigned", RED))
                
                # Traffic statistics
                if iface['rx_bytes'] > 0 or iface['tx_bytes'] > 0:
                    print(colored("Traffic Statistics:", CYAN))
                    print(colored("  Received: ", CYAN) + self.format_bytes(iface['rx_bytes']))
                    print(colored("  Transmitted: ", CYAN) + self.format_bytes(iface['tx_bytes']))
                
                print()
        else:
            print(colored("No active network interfaces", RED))
            print()
        
        # Gateway
        print(colored("▓▓▓ GATEWAY ▓▓▓", YELLOW))
        print()
        
        if state['gateway']:
            print(colored("Address: ", CYAN) + state['gateway']['address'])
            if state['gateway']['interface'] != 'N/A':
                print(colored("Interface: ", CYAN) + state['gateway']['interface'])
            
            avail_color = GREEN if state['gateway']['available'] else RED
            avail_text = "✓ Available" if state['gateway']['available'] else "✗ Unavailable"
            print(colored("Status: ", CYAN) + colored(avail_text, avail_color))
        else:
            print(colored("Default gateway not configured", RED))
        
        print()
        
        # DNS servers
        print(colored("▓▓▓ DNS SERVERS ▓▓▓", YELLOW))
        print()
        
        if state['dns']:
            print(colored("Configured DNS:", CYAN))
            for server in state['dns']:
                print("  • {}".format(server))
        else:
            print(colored("DNS servers not configured", RED))
        
        # External IP
        if state['external_ip']:
            print()
            print(colored("▓▓▓ EXTERNAL IP ▓▓▓", YELLOW))
            print()
            print(colored("Address: ", CYAN) + state['external_ip'])
        
        # Footer
        print()
        print(colored("══════════════════════════════════════════════════════════════", PURPLE))
        print(colored("Status update: ", CYAN) + state['timestamp'])
        print(colored("Press Ctrl+C to exit", YELLOW))
        
        sys.stdout.flush()
        
        # Save displayed state
        self.last_display_state = state.copy()
    
    def format_bytes(self, bytes_count):
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
    def monitoring_thread(self):
        """Background monitoring thread"""
        while self.running:
            new_state = self.update_network_state()
            
            if self.should_display_update(new_state):
                self.display_network_info(new_state)
            
            # Sleep before next check
            sleep_time = CHECK_INTERVAL
            if new_state['ip'] and not new_state['has_internet']:
                sleep_time = CHECK_INTERVAL - BLINK_INTERVAL
            
            if sleep_time > 0:
                time.sleep(sleep_time)
    
    def led_test(self):
        """Quick LED test on startup"""
        for _ in range(3):
            GPIO.output(LED_PIN, GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(LED_PIN, GPIO.LOW)
            time.sleep(0.1)

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        print("Use: sudo python3", sys.argv[0])
        sys.exit(1)
    
    monitor = NetworkMonitor()
    
    def signal_handler(sig, frame):
        print("\n" + colored("Shutting down NWSCAN...", BLUE))
        monitor.cleanup()
        os.system('clear')
        print(colored("NWSCAN stopped", GREEN))
        print(colored("Returning to command line...", CYAN))
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
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
    try:
        while monitor.running:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()