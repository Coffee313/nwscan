# 0.1 Disable Low Voltage Warning (Raspberry Pi specific)
echo "[*] Disabling Low Voltage Warning in /boot/config.txt..."
CONFIG_FILE="/boot/config.txt"
if [ ! -f "$CONFIG_FILE" ]; then
    CONFIG_FILE="/boot/firmware/config.txt"
fi

if [ -f "$CONFIG_FILE" ]; then
    if ! grep -q "avoid_warnings=1" "$CONFIG_FILE"; then
        echo "    Adding avoid_warnings=1 to $CONFIG_FILE"
        echo "avoid_warnings=1" | sudo tee -a "$CONFIG_FILE" > /dev/null
        echo "[SUCCESS] Parameter added. Please REBOOT your Pi."
    else
        echo "    avoid_warnings=1 already present in $CONFIG_FILE"
        echo "[INFO] Already present, but if banner persists, check power supply."
    fi
else
    echo "[!] Could not find config.txt to disable warnings."
fi
