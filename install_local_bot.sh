#!/bin/bash

# Script to install Local Telegram Bot API Server on Raspberry Pi
# Optimized for low-resource devices (Pi 3/4)

set -e

echo "===================================================="
echo "   Telegram Bot API Server Installer for RPi"
echo "===================================================="

# 1. SWAP Management (Crucial for TDLib compilation)
echo "[*] Checking SWAP size..."
SWAP_FILE="/etc/dphys-swapfile"
DESIRED_SWAP=2048

# Install dphys-swapfile if missing
if ! command -v dphys-swapfile &> /dev/null; then
    echo "[*] Installing dphys-swapfile..."
    sudo apt update && sudo apt install -y dphys-swapfile
fi

if [ -f "$SWAP_FILE" ]; then
    CURRENT_SWAP=$(grep "CONF_SWAPSIZE=" $SWAP_FILE | cut -d'=' -f2)
    if [ "$CURRENT_SWAP" -lt "$DESIRED_SWAP" ]; then
        echo "[!] Current SWAP ($CURRENT_SWAP MB) is too small for compilation."
        echo "[*] Increasing SWAP to $DESIRED_SWAP MB..."
        sudo sed -i "s/CONF_SWAPSIZE=.*/CONF_SWAPSIZE=$DESIRED_SWAP/" $SWAP_FILE
        sudo /etc/init.d/dphys-swapfile restart
        echo "[+] SWAP increased successfully."
    else
        echo "[+] SWAP size is sufficient ($CURRENT_SWAP MB)."
    fi
else
    echo "[!] $SWAP_FILE not found. Please ensure dphys-swapfile is installed if you run out of memory."
fi

# 2. Install Dependencies
echo "[*] Updating system and installing dependencies..."
sudo apt update
sudo apt install -y make cmake g++ gperf libssl-dev zlib1g-dev php-cli git

# 3. Clone and Build Telegram Bot API
INSTALL_DIR="/home/pi/tg_bot_api"
if [ ! -d "$INSTALL_DIR" ]; then
    echo "[*] Cloning telegram-bot-api repository..."
    git clone --recursive https://github.com/tdlib/telegram-bot-api.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
mkdir -p build
cd build

echo "[*] Configuring build with CMake..."
cmake -DCMAKE_BUILD_TYPE=Release ..

echo "[*] Starting compilation (this will take A LONG TIME)..."
echo "[!] Using -j1 to prevent Raspberry Pi from overheating or rebooting."
# Using -j1 is critical for stability on Pi during TDLib build
make -j1

# 4. Create Systemd Service
SERVICE_FILE="/etc/systemd/system/telegram-bot-api.service"
echo "[*] Creating systemd service: $SERVICE_FILE"

# Note: You need to provide API_ID and API_HASH for the server to work properly
# but the server can start without them for local testing.
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Telegram Bot API Server
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=$INSTALL_DIR/build
ExecStart=$INSTALL_DIR/build/telegram-bot-api --local --http-port 8081
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 5. Finalize
sudo systemctl daemon-reload
sudo systemctl enable telegram-bot-api

echo "===================================================="
echo "   Installation Complete!"
echo "===================================================="
echo "The Telegram Bot API server is installed and will start on boot."
echo "To start it now, run: sudo systemctl start telegram-bot-api"
echo "To use it with NWSCAN, set TELEGRAM_API_BASE_URL to http://localhost:8081"
echo "===================================================="
