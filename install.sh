#!/bin/bash

# NWSCAN Installer for Raspbian
# Version 1.0

set -e

echo "========================================"
echo "   NWSCAN v1.0 Installer"
echo "========================================"

# 1. System Update & Dependencies
echo "[*] Updating system packages..."
sudo apt update

echo "[*] Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv \
    lldpd tcpdump ethtool curl nmap dnsutils \
    python3-tk

# 2. Setup Directory
INSTALL_DIR="/home/pi/nwscan"
echo "[*] Installation directory: $INSTALL_DIR"

if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    echo "    Created directory."
fi

# Copy files (assuming running from source directory)
echo "[*] Copying files..."
cp nwscan.py "$INSTALL_DIR/"
cp nwscan_gui.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/" 2>/dev/null || true
if [ -f "nwscan_config.json" ]; then
    cp nwscan_config.json "$INSTALL_DIR/"
fi

# 3. Python Dependencies
echo "[*] Installing Python dependencies..."
# Try to install system-wide packages for simplicity on Pi, or use pip
# Using --break-system-packages on newer Debian/Raspbian if needed, or prefer apt
sudo apt install -y python3-requests python3-urllib3 python3-rpi.gpio

# Fallback to pip if RPi.GPIO is missing (e.g. non-Pi environment testing)
# pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true

# 4. Configure Services
echo "[*] Configuring services..."

# Enable LLDPd
sudo systemctl enable lldpd
sudo systemctl start lldpd

# Create Systemd Service for NWSCAN
SERVICE_FILE="/etc/systemd/system/nwscan.service"
echo "[*] Creating systemd service: $SERVICE_FILE"

sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=NWSCAN Network Monitor
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

# Reload and Enable
sudo systemctl daemon-reload
sudo systemctl enable nwscan

echo "========================================"
echo "   Installation Complete!"
echo "========================================"
echo "To start the service now, run:"
echo "  sudo systemctl start nwscan"
echo ""
echo "Check status with:"
echo "  sudo systemctl status nwscan"
echo "========================================"
