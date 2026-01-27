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

# 1.1 Remove Desktop entries
echo "[*] Removing Desktop entries..."
sudo rm -f "/etc/xdg/autostart/nwscan-gui.desktop" 2>/dev/null || true
# Try to remove from all user desktops
for user_dir in /home/*; do
    if [ -d "$user_dir/Desktop" ]; then
        sudo rm -f "$user_dir/Desktop/nwscan-gui.desktop" 2>/dev/null || true
    fi
done

# 2. Identify Installation Directory
# We check the default locations
INSTALL_DIRS=("/opt/nwscan" "/home/pi/nwscan")

for INSTALL_DIR in "${INSTALL_DIRS[@]}"; do
    if [ -d "$INSTALL_DIR" ]; then
        echo "[*] Found installation directory: $INSTALL_DIR"
        read -p "Do you want to remove the installation directory $INSTALL_DIR and all files? (y/n): " confirm
        if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
            sudo rm -rf "$INSTALL_DIR"
            echo "    Directory $INSTALL_DIR removed."
        else
            echo "    Directory $INSTALL_DIR preserved."
        fi
    fi
done

# 3. Optional: Remove system dependencies (not recommended as they might be used by other apps)
# echo "[*] Note: System dependencies (lldpd, tcpdump, etc.) were NOT removed."

echo "========================================"
echo "   Uninstallation Complete!"
echo "========================================"
