#!/bin/bash

# ==========================================================================
# Установка локального Telegram Bot API сервера для NWSCAN
# Позволяет отправлять файлы до 2000 МБ
# ==========================================================================

# Конфигурация
API_ID="35296335"
API_HASH="869f46658f3cba447e345a169d759516"
PORT="8081"
USER=$(whoami)

echo "--- 1. Обновление системы и установка зависимостей ---"
sudo apt update
sudo apt install make cmake g++ fts-dev libssl-dev zlib1g-dev git -y

echo "--- 2. Клонирование и сборка telegram-bot-api (это займет время) ---"
cd ~
if [ -d "telegram-bot-api" ]; then
    echo "Папка telegram-bot-api уже существует, пропускаю клонирование..."
else
    git clone --recursive https://github.com/tdlib/telegram-bot-api.git
fi

cd telegram-bot-api
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --target install -j$(nproc)

echo "--- 3. Создание Systemd сервиса ---"
SERVICE_FILE="/etc/systemd/system/telegram-bot-api.service"

sudo bash -c "cat <<EOF > $SERVICE_FILE
[Unit]
Description=Telegram Bot API Server
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=/usr/local/bin/telegram-bot-api --api-id=$API_ID --api-hash=$API_HASH --local --http-port=$PORT
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF"

echo "--- 4. Запуск сервиса ---"
sudo systemctl daemon-reload
sudo systemctl enable telegram-bot-api
sudo systemctl restart telegram-bot-api

echo ""
echo "=========================================================================="
echo "УСТАНОВКА ЗАВЕРШЕНА!"
echo "=========================================================================="
echo "Сервер запущен на порту: $PORT"
echo "Теперь вам нужно изменить в nwscan.py все ссылки:"
echo "С: https://api.telegram.org"
echo "НА: http://localhost:$PORT"
echo "=========================================================================="
