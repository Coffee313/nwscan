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
        
        # Convert IP to integer - ИСПРАВЛЕНА ОШИБКА В СКОБКАХ
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
            'gateway': None,
            'dns': [],
            'external_ip': None
        }
        self.last_display_state = None
        self.running = True
        self.led_state = "OFF"
        self.stop_led_thread = False
        self.led_thread = None
        
        # GPIO setup
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(LED_PIN, GPIO.OUT)
        GPIO.output(LED_PIN, GPIO.LOW)
        
        # Start LED control thread
        self.start_led_thread()
    
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
        
    def run_command(self, cmd):
        """Run shell command safely"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""
    
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
            print(f"resolvectl error: {e}")
        
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
            print(f"resolv.conf error: {e}")
        
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
            print(f"DHCP lease error: {e}")
        
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
            print(f"nmcli error: {e}")
        
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
            print(f"interfaces file error: {e}")
        
        # Remove duplicates and empty entries
        servers = [s for s in servers if s and s.strip() and s != '0.0.0.0']
        servers = list(dict.fromkeys(servers))  # Remove duplicates while preserving order
        
        # Fallback to common DNS servers if none found
        if not servers:
            servers = ['8.8.8.8', '8.8.4.4']  # Google DNS
        
        return servers
    
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
        
        # Check if any interface IP changed
        old_interfaces = self.last_display_state.get('interfaces', [])
        new_interfaces = new_state.get('interfaces', [])
        
        if len(old_interfaces) != len(new_interfaces):
            return True
        
        for old_if, new_if in zip(old_interfaces, new_interfaces):
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
        
        # Network interfaces
        print(colored("▓▓▓ NETWORK INTERFACES ▓▓▓", YELLOW))
        print()
        
        interfaces = state.get('interfaces', [])
        if interfaces:
            for iface in interfaces:
                # Check if iface is a dictionary
                if not isinstance(iface, dict):
                    continue
                    
                print(colored("▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬", CYAN))
                print(colored("Interface: ", PURPLE) + iface.get('name', 'N/A'))
                
                status = iface.get('status', 'DOWN')
                status_color = GREEN if status == 'UP' else RED
                status_text = "ACTIVE" if status == 'UP' else "INACTIVE"
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
                        
                        print(colored("IP Address: ", CYAN) + ip)
                        print(colored("CIDR Notation: ", CYAN) + cidr)
                        print(colored("Subnet Mask: ", CYAN) + mask + 
                              colored(f" (/{prefix})", CYAN))
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
        
        # DNS servers
        print(colored("▓▓▓ DNS SERVERS ▓▓▓", YELLOW))
        print()
        
        dns_servers = state.get('dns', [])
        if dns_servers:
            print(colored("Configured DNS:", CYAN))
            for server in dns_servers:
                print("  • {}".format(server))
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
        print(colored("Press Ctrl+C to exit", YELLOW))
        
        sys.stdout.flush()
        
        # Save displayed state
        self.last_display_state = state.copy()
    
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
    main()