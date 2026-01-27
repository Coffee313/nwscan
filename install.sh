#!/bin/bash

# NWSCAN Installer for Raspbian
# Version 1.0

set -e

echo "========================================"
echo "   NWSCAN v1.0 Installer"
echo "========================================"

# 0. SWAP Management (Optional but recommended for Pi)
echo "[*] Checking SWAP size..."
SWAP_FILE="/etc/dphys-swapfile"
DESIRED_SWAP=1024 # For general use, 1GB is usually enough, 2GB for compilation

# Install dphys-swapfile if missing
if ! command -v dphys-swapfile &> /dev/null; then
    echo "[*] Installing dphys-swapfile..."
    sudo apt update && sudo apt install -y dphys-swapfile
fi

if [ -f "$SWAP_FILE" ]; then
    CURRENT_SWAP=$(grep "CONF_SWAPSIZE=" $SWAP_FILE | cut -d'=' -f2)
    if [ "$CURRENT_SWAP" -lt "$DESIRED_SWAP" ]; then
        echo "[!] Current SWAP ($CURRENT_SWAP MB) is small. Increasing to $DESIRED_SWAP MB..."
        sudo sed -i "s/CONF_SWAPSIZE=.*/CONF_SWAPSIZE=$DESIRED_SWAP/" $SWAP_FILE
        sudo /etc/init.d/dphys-swapfile restart
        echo "[+] SWAP increased successfully."
    else
        echo "[+] SWAP size is sufficient ($CURRENT_SWAP MB)."
    fi
fi

# 1. System Update & Dependencies
echo "[*] Updating system packages..."
sudo apt update

echo "[*] Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv \
    lldpd tcpdump ethtool curl nmap dnsutils \
    python3-tk python3-requests python3-urllib3 python3-paramiko python3-rpi.gpio || true

# 2. Setup Directory
# Use /opt/nwscan for a more robust installation that doesn't depend on the username
INSTALL_DIR="/opt/nwscan"
CURRENT_DIR=$(pwd)

echo "[*] Installation directory: $INSTALL_DIR"

if [ "$CURRENT_DIR" == "$INSTALL_DIR" ]; then
    echo "[!] Current directory is the same as installation directory. Skipping copy."
else
    if [ ! -d "$INSTALL_DIR" ]; then
        sudo mkdir -p "$INSTALL_DIR"
        echo "    Created directory."
    fi

    # Copy files from current directory
    echo "[*] Copying files to $INSTALL_DIR..."
    sudo cp nwscan.py "$INSTALL_DIR/"
    sudo cp nwscan_gui.py "$INSTALL_DIR/"
    sudo cp requirements.txt "$INSTALL_DIR/" 2>/dev/null || true
    if [ -f "nwscan_config.json" ]; then
        sudo cp nwscan_config.json "$INSTALL_DIR/"
    fi
fi

# Create SFTP data directory
SFTP_DIR="$INSTALL_DIR/sftp_files"
if [ ! -d "$SFTP_DIR" ]; then
    sudo mkdir -p "$SFTP_DIR"
    sudo chmod 777 "$SFTP_DIR"
    echo "    Created SFTP data directory (sftp_files)."
fi

# 3. Python Dependencies (Verification & Fallback)
echo "[*] Verifying Python dependencies..."

# Detect if --break-system-packages is needed (for Debian 12+)
PIP_BREAK=""
if pip3 help install | grep -q "break-system-packages"; then
    PIP_BREAK="--break-system-packages"
fi

# Function to check and install missing python package
check_and_install() {
    package=$1
    pip_name=$2
    if ! python3 -c "import $package" &> /dev/null; then
        echo "[!] $package not found, trying to install $pip_name via pip3..."
        sudo pip3 install "$pip_name" $PIP_BREAK || echo "[ERROR] Failed to install $pip_name"
    else
        echo "[+] $package is already installed."
    fi
}

check_and_install "paramiko" "paramiko"
check_and_install "requests" "requests"
check_and_install "urllib3" "urllib3"
check_and_install "tkinter" "python3-tk" # Note: tkinter is a bit special, usually apt is better

# Install additional requirements from requirements.txt if any
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    echo "[*] Installing additional requirements from requirements.txt..."
    sudo pip3 install -r "$INSTALL_DIR/requirements.txt" $PIP_BREAK || true
fi

# 4. Configure Services
echo "[*] Configuring services..."

# Enable LLDPd
sudo systemctl enable lldpd
sudo systemctl start lldpd

# Create Systemd Service for NWSCAN (Background Monitor & Telegram Bot)
SERVICE_FILE="/etc/systemd/system/nwscan.service"
echo "[*] Creating systemd service: $SERVICE_FILE"

sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=NWSCAN Network Monitor (Background)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/nwscan.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create Systemd Service for GUI (Auto-starts on Display)
GUI_SERVICE_FILE="/etc/systemd/system/nwscan-gui.service"
echo "[*] Creating GUI service: $GUI_SERVICE_FILE"

sudo tee "$GUI_SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=NWSCAN GUI Interface
After=graphical.target
Wants=graphical.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=DISPLAY=:0
Environment=XAUTHORITY=/home/$(logname)/.Xauthority
ExecStartPre=/bin/sleep 5
# Start the GUI, it will automatically handle the lock
ExecStart=/usr/bin/python3 $INSTALL_DIR/nwscan_gui.py
Restart=always
RestartSec=10

[Install]
WantedBy=graphical.target
EOF

# Create Desktop Autostart for GUI (Traditional method)
AUTOSTART_DIR="/etc/xdg/autostart"
if [ -d "$AUTOSTART_DIR" ]; then
    echo "[*] Creating Desktop autostart for GUI..."
    sudo tee "$AUTOSTART_DIR/nwscan-gui.desktop" > /dev/null <<EOF
[Desktop Entry]
Type=Application
Name=NWSCAN GUI
Comment=Network Status Monitor GUI
Exec=sudo python3 $INSTALL_DIR/nwscan_gui.py
Terminal=false
Categories=Network;Utility;
X-GNOME-Autostart-enabled=true
EOF
fi

# Create Desktop Shortcut
DESKTOP_DIR="/home/$(logname)/Desktop"
if [ -d "$DESKTOP_DIR" ]; then
    echo "[*] Creating Desktop shortcut..."
    sudo tee "$DESKTOP_DIR/nwscan-gui.desktop" > /dev/null <<EOF
[Desktop Entry]
Type=Application
Name=NWSCAN GUI
Comment=Network Status Monitor GUI
Exec=sudo python3 $INSTALL_DIR/nwscan_gui.py
Icon=network-transmit-receive
Terminal=false
Categories=Network;Utility;
EOF
    sudo chown $(logname):$(logname) "$DESKTOP_DIR/nwscan-gui.desktop"
    sudo chmod +x "$DESKTOP_DIR/nwscan-gui.desktop"
fi

# Reload and Enable
sudo systemctl daemon-reload
sudo systemctl enable nwscan
sudo systemctl start nwscan

# Enable and Start GUI service
sudo systemctl enable nwscan-gui
sudo systemctl start nwscan-gui

# 5. Fix permissions for mandatory root execution
echo "[*] Setting permissions..."
sudo chown root:root "$INSTALL_DIR/nwscan.py" "$INSTALL_DIR/nwscan_gui.py"
sudo chmod +x "$INSTALL_DIR/nwscan.py" "$INSTALL_DIR/nwscan_gui.py"

echo "========================================"
echo "   Installation Complete!"
echo "========================================"
echo "Service is now running. Check status with:"
echo "  sudo systemctl status nwscan"
echo ""
echo "To run the GUI manually, use:"
echo "  sudo python3 $INSTALL_DIR/nwscan_gui.py"
echo "========================================"
