I have successfully removed all the code related to `/set_ip_eth0`, `/set_ip_wlan0`, and their underlying implementations (`set_static_ip`, `set_dhcp`, etc.).

Now, I propose the following plan to implement the IP configuration functionality from scratch, ensuring robustness and compatibility.

### 1. Strategy: Explicit Network Manager Detection
Instead of mixing methods, we will strictly detect the active network manager and use **only** one method per system:
- **Priority 1: NetworkManager (`nmcli`)**. Standard on newer Raspbian (Bookworm). We will use it if `NetworkManager` service is active.
- **Priority 2: dhcpcd**. Standard on older Raspbian (Bullseye). We will use it only if NetworkManager is not active.

### 2. Implementation Details

#### A. NetworkManager (`nmcli`) Implementation
- **Static IP**:
  1. Identify the connection profile for the interface (e.g., `Wired connection 1`).
  2. Set `ipv4.method manual`.
  3. **Crucial**: Clear existing settings first (`ipv4.addresses ''`, `ipv4.dns ''`) to avoid "multiple IPs" and "appending DNS" issues.
  4. Set new `ipv4.addresses`, `ipv4.gateway`, `ipv4.dns`.
  5. Enable persistence: `connection.autoconnect yes`.
  6. Apply: `nmcli con up <name>`.
- **DHCP**:
  1. Set `ipv4.method auto`.
  2. Clear static fields (`addresses`, `gateway`, `dns`).
  3. Apply: `nmcli con up <name>`.

#### B. dhcpcd Implementation (Legacy/Fallback)
- **File Editing**: Re-implement a secure `write_file_sudo` helper using `sudo tee` to bypass permission issues.
- **Static IP**:
  1. Parse `/etc/dhcpcd.conf`.
  2. Remove any existing `interface <name>` block completely.
  3. Append a clean block:
     ```
     interface eth0
     static ip_address=192.168.1.10/24
     static routers=192.168.1.1
     static domain_name_servers=8.8.8.8
     ```
  4. **Flush**: Run `sudo ip addr flush dev <iface>` to remove old IPs immediately.
  5. Restart `dhcpcd` service.
- **DHCP**:
  1. Remove `interface <name>` block from config.
  2. Flush IPs.
  3. Restart `dhcpcd`.

### 3. Command Structure
- Restore `/set_ip_eth0` and `/set_ip_wlan0` commands.
- **Input Validation**: Strict parsing of IP, Mask (CIDR or 255.x.x.x), Gateway, and DNS.
- **Feedback**: Report success/failure to Telegram with detailed error logs if something fails.

### 4. Verification Steps
- Verify syntax of commands.
- Verify file writing permissions (using `sudo`).
- Verify service restart commands (`systemctl`).

Shall I proceed with this implementation?