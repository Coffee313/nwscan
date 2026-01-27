#!/bin/bash

# NWSCAN Uninstaller for Raspbian
# Version 1.0

echo "========================================"
echo "   NWSCAN v1.0 Uninstaller"
echo "========================================"

# 1. Stop and Disable Service
SERVICE_NAME="nwscan"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ -f "$SERVICE_FILE" ]; then
    echo "[*] Stopping and disabling service: $SERVICE_NAME"
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    sudo rm "$SERVICE_FILE"
    sudo systemctl daemon-reload
    echo "    Service removed."
else
    echo "[!] Service file not found, skipping."
fi

# 2. Identify Installation Directory
# We check the default location, but also try to find where it might be
INSTALL_DIR="/home/pi/nwscan"
# Try to find from service file if it existed (though we just deleted it, we should have checked before)
# Since we just deleted it, let's just use the default and check if it exists

if [ -d "$INSTALL_DIR" ]; then
    echo "[*] Found installation directory: $INSTALL_DIR"
    read -p "Do you want to remove the installation directory and all files? (y/n): " confirm
    if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
        sudo rm -rf "$INSTALL_DIR"
        echo "    Directory removed."
    else
        echo "    Directory preserved."
    fi
else
    echo "[!] Installation directory $INSTALL_DIR not found."
fi

# 3. Optional: Remove system dependencies (not recommended as they might be used by other apps)
# echo "[*] Note: System dependencies (lldpd, tcpdump, etc.) were NOT removed."

echo "========================================"
echo "   Uninstallation Complete!"
echo "========================================"
