# NWSCAN — монитор сети для Raspberry Pi v1.0 (Stable)

NWSCAN — легкий монитор сети, который:
- отслеживает наличие IP и доступность интернета;
- показывает активные интерфейсы с подробной сетевой информацией;
- получает соседей по LLDP/CDP (коммутаторы/устройства);
- отправляет уведомления в Telegram;
- управляет светодиодом на GPIO для индикации состояния сети.

## Возможности
- LED-индикация: стабильное мигание при отсутствии интернета, постоянное свечение при наличии.
- Подробные данные интерфейсов: IP, маска, сеть, диапазоны хостов, счетчики трафика.
- LLDP/CDP/ethtool: обнаружение соседей, базовая информация устройств и SFP-модулей.
- Telegram: сводный статус, уведомления об изменениях, отчеты о даунтайме.
- GUI (tkinter): вкладки Status/Neighbors/Nmap/Settings/Logs, простые сетевые сканы (nmap/локальные).

## Требования
- Raspberry Pi OS (или другой Debian-based Linux).
- Пакеты: `python3`, `python3-requests`, `python3-urllib3`, `python3-rpi.gpio`, `lldpd`, `tcpdump`, `ethtool`, `curl`, `nmap` (по желанию).
- Запуск монитора — от root (доступ к LLDP/CDP, tcpdump, статистике интерфейсов).

```bash
sudo apt update
sudo apt install -y python3 python3-requests python3-urllib3 python3-rpi.gpio \
  lldpd tcpdump ethtool curl nmap
sudo systemctl enable lldpd
sudo systemctl start lldpd
```

## Подключение светодиода
- Используется `LED_PIN=18` (нумерация BCM; физический пин 12).
- Подключение:
  - Анод светодиода → через резистор 220–1000 Ω → к GPIO18 (физ. пин 12).
  - Катод → GND (например, физ. пин 6).
- Состояния:
  - Нет IP: LED выключен.
  - Есть IP, нет интернета: LED мигает (интервал 0.15 c).
  - Есть интернет: LED постоянно включен.

## Установка
1. Скопируйте проект на устройство, например:
   ```bash
   mkdir -p /home/pi/nwscan
   # поместите файлы nwscan.py и nwscan_gui.py в /home/pi/nwscan/
   ```
2. Настройте Telegram:
   - В GUI (Settings → Telegram) введите Bot Token (получить у @BotFather), добавьте chat ID, включите Telegram, настройте интервалы.
   - При необходимости можно задать токен вручную в `nwscan_config.json` в поле `telegram_token`.
3. Запуск вручную:
   - Консольный монитор:
     ```bash
     cd /home/pi/nwscan
     sudo python3 nwscan.py
     ```
   - GUI (при наличии рабочего десктопа):
     ```bash
     cd /home/pi/nwscan
     python3 nwscan_gui.py
     ```

## Автозапуск через systemd
Создайте unit-файл:
```ini
sudo tee /etc/systemd/system/nwscan.service >/dev/null <<'EOF'
[Unit]
Description=NWSCAN Network Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/pi/nwscan
ExecStart=/usr/bin/python3 /home/pi/nwscan/nwscan.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
```
Активируйте:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nwscan
sudo systemctl start nwscan
sudo systemctl status nwscan
```

## Управление через Telegram
Бот поддерживает полноценное удаленное управление всеми функциями монитора:
- `/status` — текущее состояние сети (интерфейсы, IP, шлюз, интернет).
- `/settings`, `/get_settings` — просмотр текущих настроек (интервалы, воркеры nmap, флаги мониторинга).
- `/set <ключ> <значение>` — изменение настроек на лету (синхронизируется с GUI и JSON).
- `/restart` — удаленная перезагрузка сервиса.
- `/shutdown_os` — мягкое выключение операционной системы.
- `/chat_add <id>` / `/chat_remove <id>` — управление списком разрешенных чатов.

### Работа с Nmap и инструментами через бота
- `/scan_discover <цель>` — быстрый поиск живых хостов в сети.
- `/scan_quick <цель> [TCP|UDP|BOTH]` — быстрое сканирование портов.
- `/scan_custom <цель> <порты> [TCP|UDP|BOTH]` — сканирование указанных портов.
- `/scan_stop` — принудительная остановка текущего сканирования.
- `/dump [min]` — сбор полного дампа трафика (tcpdump) на указанное время (по умолчанию 1 мин) с отправкой .pcap файла в Telegram.
- `/dump_custom <PROTO> <SRC_IP> <DST_IP> <SRC_PORT> <DST_PORT> [min]` — сбор дампа с гибкой фильтрацией.
  - `PROTO`: TCP, UDP, BOTH.
  - IP/PORT: конкретное значение или `any`.
- `/dump_stop` — немедленная остановка сбора дампа и отправка результата.
- `/nslookup <host>` — выполнение DNS запроса (dig/nslookup) для домена или IP.

### Примеры команд `/set`:
- `/set debug_enabled true` — включение режима отладки.
- `/set check_interval 5` — проверка сети каждые 5 секунд.
- `/set nmap_workers 16` — установка 16 потоков для nmap.
- `/set monitor_eth0 off` — отключение мониторинга интерфейса eth0.

## Настройки
- GUI и Telegram-бот сохраняют настройки в `nwscan_config.json`.
- `telegram_notify_on_change` — если включено (true), бот отправляет статус только при изменении состояния сети (поднялся/упал интерфейс, сменился IP).
- `auto_scan_on_network_up` — автоматический запуск сканирования сети при появлении линка на шлюзе.
  - Требуется работающий сервис `lldpd` (`sudo systemctl enable/start lldpd`).
  - CDP использует `tcpdump`, требует root.
- Внешний IP берется через `curl` (`ifconfig.me`, `api.ipify.org`), убедитесь, что `curl` установлен.

## Nmap и сканирование
- Вкладка Nmap:
  - Если установлен `nmap`, используется CLI (быстрее, более точные результаты).
  - Если нет, выполняются локальные проверки TCP/UDP через сокеты.
  - Поддерживаются параллельные батчи и прогрессбар.

## Отчеты о даунтайме
- Логи пишутся в `/var/log/nwscan_downtime.log`.
- Файл создается автоматически; при интенсивном использовании рекомендуем настроить `logrotate`.

## Устранение неполадок
- Телеграм не работает при старте:
   - Убедитесь в наличии сети: `After=network-online.target`, включите `systemd-networkd-wait-online` или эквивалент.
   - Проверьте корректность токена и chat-ID (через GUI или `nwscan_config.json`).
   - В коде включена авто-переинициализация Telegram после появления интернета.
- LLDP/CDP:
  - Проверьте, что `lldpd` активен: `sudo systemctl status lldpd`.
  - Убедитесь, что монитор запускается от root.
- LED:
  - Проверьте правильную BCM-нумерацию пина 18 и GND.
  - Убедитесь, что установлен `RPi.GPIO`.

## Примечания безопасности
- Не публикуйте токен Telegram в открытом репозитории. Храните его локально и ограничивайте доступ.
- Токен хранится в `nwscan_config.json`; при использовании Linux можно ограничить права на файл: `chmod 600 nwscan_config.json`.
- Для продакшен окружений рекомендуется включить проверку SSL в запросах к Telegram.
