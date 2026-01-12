#!/usr/bin/env python3
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Starting NWScan GUI...")
    
    # Test imports
    print("Testing imports...")
    import nwscan
    print("✓ nwscan imported successfully")
    
    import tkinter as tk
    print("✓ tkinter imported successfully")
    
    from nwscan_gui import NWScanGUI
    print("✓ NWScanGUI imported successfully")
    
    print("Creating GUI instance...")
    app = NWScanGUI()
    print("✓ GUI instance created")
    
    print("Starting main loop...")
    app.mainloop()
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)