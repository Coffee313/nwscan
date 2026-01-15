import RPi.GPIO as GPIO
import time

PIN = 26

def callback(channel):
    print(f"Button pressed on channel {channel}!")

try:
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    # Check initial state
    initial_state = GPIO.input(PIN)
    print(f"Initial state of GPIO {PIN}: {initial_state} (Should be 1/True if not pressed)")
    
    # Add event detection
    try:
        GPIO.add_event_detect(PIN, GPIO.FALLING, callback=callback, bouncetime=200)
        print("Interrupt mode active.")
    except Exception as e:
        print(f"Interrupt mode failed ({e}). Switching to POLLING mode.")
        print("Polling active...")
        last_state = 1
        while True:
            current_state = GPIO.input(PIN)
            if last_state == 1 and current_state == 0:
                print(f"Button pressed (Polling)!")
                time.sleep(0.5) # Debounce
            last_state = current_state
            time.sleep(0.1)

    print(f"Monitoring GPIO {PIN}. Press Ctrl+C to exit.")
    print("Try connecting GPIO 26 to GND now...")
    
    while True:
        # Just keep main thread alive if interrupt works
        time.sleep(1)

except KeyboardInterrupt:
    print("\nExiting...")
except Exception as e:
    print(f"Error: {e}")
finally:
    GPIO.cleanup()
