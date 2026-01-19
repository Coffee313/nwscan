# Setting Up Local Telegram Bot API Server on Raspberry Pi

To bypass the 20MB download limit and 50MB upload limit (increasing them to 2000MB), you need to run a local Telegram Bot API server.

## Prerequisites

1.  **Get API ID and API Hash:**
    *   Go to [https://my.telegram.org](https://my.telegram.org).
    *   Log in with your phone number.
    *   Click on **API development tools**.
    *   Create a new application (URL can be `http://localhost`).
    *   Copy **App api_id** and **App api_hash**.

---

## Method 1: Using Docker (Recommended if supported)

Try this first. It is the fastest method.

1.  **Install Docker:**
    ```bash
    curl -sSL https://get.docker.com | sh
    sudo usermod -aG docker pi
    # Log out and log back in for changes to take effect
    ```

2.  **Run the container:**
    Replace `<YOUR_API_ID>` and `<YOUR_API_HASH>` with your values.

    ```bash
    docker run -d \
      --name=telegram-bot-api \
      --restart=always \
      -p 8081:8081 \
      -v /var/lib/telegram-bot-api:/var/lib/telegram-bot-api \
      lukaszraczylo/telegram-bot-api:latest \
      --api-id=<YOUR_API_ID> \
      --api-hash=<YOUR_API_HASH> \
      --local
    ```
    *(Note: We use `lukaszraczylo/telegram-bot-api` as it often has better ARM support than the official image).*

3.  **Check logs:**
    ```bash
    docker logs telegram-bot-api
    ```
    If it says the server is running on port 8081, you are done! Proceed to "Configuring NWScan".

---

## Method 2: Manual Build (Reliable for Raspberry Pi)

If Docker fails or the container exits immediately, build the server from source. This takes about 15 minutes.

### 1. Install Dependencies
```bash
sudo apt-get update
sudo apt-get install -y make git zlib1g-dev libssl-dev gperf cmake clang libc++-dev libc++abi-dev
```

### 2. Clone Repository
```bash
cd ~
git clone --recursive https://github.com/tdlib/telegram-bot-api.git
cd telegram-bot-api
```

### 3. Build
```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=.. ..
cmake --build . --target install
```

### 4. Create Systemd Service (Auto-start)
Create a service file to run the server in the background.

1.  Create the file:
    ```bash
    sudo nano /etc/systemd/system/telegram-bot-api.service
    ```

2.  Paste the following content (Replace `<YOUR_API_ID>` and `<YOUR_API_HASH>`):
    ```ini
    [Unit]
    Description=Telegram Bot API Server
    After=network.target

    [Service]
    User=pi
    WorkingDirectory=/home/pi/telegram-bot-api/bin
    # Check that the path to the binary matches your installation
    ExecStart=/home/pi/telegram-bot-api/bin/telegram-bot-api --api-id=<YOUR_API_ID> --api-hash=<YOUR_API_HASH> --http-port=8081 --local
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```

3.  Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

4.  Start the service:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable telegram-bot-api
    sudo systemctl start telegram-bot-api
    ```

5.  Check status:
    ```bash
    sudo systemctl status telegram-bot-api
    ```

---

## Configuring NWScan

Once the local server is running (usually on port 8081):

1.  Open your bot in Telegram.
2.  Send the command:
    ```text
    /set_telegram_api http://localhost:8081
    ```
    *(If NWScan is running on the same Pi as the API server).*

3.  **Important:** The first time you make a request to the local server, the bot will automatically "log out" from the public cloud API and move to your local server.

Now you can upload files up to **2000 MB** using `/sftp_upload`.
