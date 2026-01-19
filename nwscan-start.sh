#!/bin/bash
# Wrapper script for safe NWSCAN startup

# Wait for network to be ready
sleep 5

# Clear screen
echo -e "\033[2J\033[H"

# Start NWSCAN with proper terminal handling
exec /usr/bin/python3 /usr/local/bin/nwscan_gui.py
