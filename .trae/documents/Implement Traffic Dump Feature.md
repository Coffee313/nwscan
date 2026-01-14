I will implement the traffic dump feature as requested.

### Plan

1.  **Add `send_telegram_document` method to `NetworkMonitor` class in `nwscan.py`**:
    *   This method will use `requests.post` with `files` parameter to upload the file to Telegram's `sendDocument` API.
    *   It will include error handling similar to existing message sending methods.

2.  **Implement `cmd_dump` and background task**:
    *   Add `cmd_dump(self, chat_id, minutes)` to handle the command parsing and feedback.
    *   Create a background thread function (e.g., `_run_dump_task`) that:
        *   Checks for `tcpdump` availability.
        *   Generates a filename with timestamp (e.g., `tcpdump_20231027_100000.pcap`).
        *   Runs `tcpdump -i any -w <file>` using `subprocess.Popen`.
        *   Waits for the specified duration using `time.sleep()`.
        *   Terminates the process gracefully.
        *   Sends the file to the user via Telegram.
        *   Deletes the file from the disk.

3.  **Register command in `handle_telegram_command`**:
    *   Add support for `/dump <minutes>` command (defaulting to 1 minute if not specified).

### Implementation Details
*   **Command**: `/dump [minutes]` (e.g., `/dump 5` for 5 minutes).
*   **Tool**: `tcpdump` capturing on all interfaces (`-i any`) without filters.
*   **Cleanup**: The capture file will be automatically deleted after attempting to send it.
*   **Concurrency**: The dump will run in a separate thread so the bot remains responsive to other commands.
