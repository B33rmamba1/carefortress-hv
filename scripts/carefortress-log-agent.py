#!/usr/bin/env python3
"""
CareFortress Guest Log Agent
Writes structured JSON log entries to virtio-serial port.
Runs as a systemd service on each guest VM.
"""

import json
import time
import socket
import os
import sys
import subprocess
from datetime import datetime, timezone

SERIAL_PORT = f"/dev/virtio-ports/log.{socket.gethostname()}"
FLUSH_INTERVAL = 5  # seconds between heartbeat entries

def write_entry(port, event_type, message, extra=None):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "type": event_type,
        "msg": message,
    }
    if extra:
        entry.update(extra)
    try:
        line = json.dumps(entry) + "\n"
        port.write(line.encode())
        port.flush()
    except Exception as e:
        sys.stderr.write(f"write_entry error: {e}\n")

def get_logged_in_users():
    """Read logged-in users directly from /var/run/utmp -- no subprocess, no AppArmor noise."""
    try:
        import struct
        UTMP_STRUCT = "hi32s4s32s256s4i20s"
        UTMP_SIZE = struct.calcsize(UTMP_STRUCT)
        USER_PROCESS = 7
        users = []
        with open("/var/run/utmp", "rb") as f:
            while True:
                data = f.read(UTMP_SIZE)
                if len(data) < UTMP_SIZE:
                    break
                fields = struct.unpack(UTMP_STRUCT, data)
                ut_type = fields[0]
                ut_user = fields[4].decode("utf-8", errors="ignore").rstrip("\x00").strip()
                if ut_type == USER_PROCESS and ut_user:
                    users.append(ut_user)
        return ", ".join(users) if users else "none"
    except Exception:
        return "none"

def get_load():
    try:
        with open("/proc/loadavg") as f:
            return f.read().split()[:3]
    except Exception:
        return ["?", "?", "?"]

def main():
    # Wait for the serial port to be available
    for _ in range(30):
        if os.path.exists(SERIAL_PORT):
            break
        time.sleep(1)

    if not os.path.exists(SERIAL_PORT):
        sys.stderr.write(f"Serial port {SERIAL_PORT} not found after 30s\n")
        sys.exit(1)

    with open(SERIAL_PORT, "wb", buffering=0) as port:
        write_entry(port, "START", "CareFortress log agent started")

        last_users = ""
        while True:
            try:
                # Heartbeat with load average
                load = get_load()
                write_entry(port, "HEARTBEAT", "periodic check", {
                    "load_1m": load[0],
                    "load_5m": load[1],
                    "load_15m": load[2],
                })

                # Detect login/logout changes
                users = get_logged_in_users()
                if users != last_users:
                    write_entry(port, "AUTH", "user session change", {
                        "sessions": users
                    })
                    last_users = users

                time.sleep(FLUSH_INTERVAL)

            except Exception as e:
                sys.stderr.write(f"agent loop error: {e}\n")
                time.sleep(FLUSH_INTERVAL)

if __name__ == "__main__":
    main()
