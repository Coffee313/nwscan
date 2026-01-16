import requests
import json
import sys

def force_logout(token, local_url=None):
    """
    Forces the bot to log out from the current server (local or cloud).
    Useful when switching between local Telegram Bot API server and the public one.
    """
    print(f"[*] Attempting to log out bot...")
    
    # 1. Try to log out from Local Server (if provided or default)
    if local_url:
        try:
            print(f"[*] Trying local server: {local_url}")
            # Ensure URL doesn't end with slash
            local_url = local_url.rstrip('/')
            if not local_url.startswith('http'):
                local_url = 'http://' + local_url
                
            url = f"{local_url}/bot{token}/logOut"
            r = requests.get(url, timeout=5)
            print(f"    Response: {r.status_code} - {r.text}")
            if r.status_code == 200 and r.json().get('ok'):
                print("    SUCCESS: Logged out from local server.")
        except Exception as e:
            print(f"    Failed to connect to local server: {e}")

    # 2. Try to log out from Cloud Server (official)
    try:
        print(f"[*] Trying official cloud server...")
        url = f"https://api.telegram.org/bot{token}/logOut"
        r = requests.get(url, timeout=10)
        print(f"    Response: {r.status_code} - {r.text}")
        if r.status_code == 200 and r.json().get('ok'):
             print("    SUCCESS: Logged out from cloud server.")
    except Exception as e:
        print(f"    Failed to connect to cloud server: {e}")

    # 3. Check status
    print(f"[*] Checking bot status on Cloud Server...")
    try:
        url = f"https://api.telegram.org/bot{token}/getMe"
        r = requests.get(url, timeout=10)
        print(f"    Response: {r.status_code} - {r.text}")
        if r.status_code == 200 and r.json().get('ok'):
            print("    ✅ Bot is active on Cloud Server!")
        else:
            print("    ⚠️ Bot is NOT active on Cloud Server yet.")
    except Exception as e:
        print(f"    Error checking status: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 telegram_logout.py <BOT_TOKEN> [LOCAL_API_URL]")
        print("Example: python3 telegram_logout.py 123456:ABC-DEF http://localhost:8081")
        # Try to load from config if available
        try:
            with open('nwscan_config.json', 'r') as f:
                cfg = json.load(f)
                token = cfg.get('telegram_token') or cfg.get('TELEGRAM_BOT_TOKEN')
                local_url = cfg.get('telegram_api_url', 'http://localhost:8081')
                if token:
                    print(f"\nFound token in config: {token[:5]}...")
                    force_logout(token, local_url)
                    sys.exit(0)
        except:
            pass
        sys.exit(1)
    
    token = sys.argv[1]
    local_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8081"
    
    force_logout(token, local_url)
