#!/usr/bin/env python3
"""
CareFortress Agent Watchdog
Monitors the log agent PID. If the agent dies, writes AGENT_KILLED
to the virtio-serial port and restarts the agent.
Runs as a separate process so a kill -9 on the agent cannot silence it.
"""
import json
import time
import socket
import os
import sys
import hmac
import hashlib
import subprocess
from datetime import datetime, timezone

SERIAL_PORT = f"/dev/virtio-ports/log.{socket.gethostname()}"
HMAC_KEY_FILE = "/etc/carefortress-agent.key"
AGENT_PATH = "/usr/local/bin/carefortress-log-agent.py"
CHECK_INTERVAL = 5
RESTART_DELAY = 2


def load_hmac_key():
    try:
        with open(HMAC_KEY_FILE, 'r') as f:
            return f.read().strip().encode()
    except Exception as e:
        sys.stderr.write(f"FATAL: cannot load HMAC key: {e}\n")
        sys.exit(1)


def sign_and_write(port, key, event_type, message):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "type": event_type,
        "msg": message,
        "agent_seq": -1,
    }
    payload_str = json.dumps(entry, sort_keys=True)
    entry["agent_hmac"] = hmac.new(key, payload_str.encode(), hashlib.sha256).hexdigest()
    try:
        port.write((json.dumps(entry) + "\n").encode())
        port.flush()
    except Exception as e:
        sys.stderr.write(f"watchdog write error: {e}\n")


def find_agent_pid():
    try:
        result = subprocess.run(
            ["pgrep", "-f", "carefortress-log-agent.py"],
            capture_output=True, text=True
        )
        pids = result.stdout.strip().split("\n")
        pids = [p for p in pids if p and int(p) != os.getpid()]
        return int(pids[0]) if pids else None
    except Exception:
        return None


def restart_agent():
    try:
        subprocess.Popen(
            ["python3", AGENT_PATH],
            stdout=open("/tmp/agent.log", "a"),
            stderr=subprocess.STDOUT
        )
        return True
    except Exception as e:
        sys.stderr.write(f"watchdog restart failed: {e}\n")
        return False


def main():
    key = load_hmac_key()

    for _ in range(30):
        if os.path.exists(SERIAL_PORT):
            break
        time.sleep(1)
    if not os.path.exists(SERIAL_PORT):
        sys.stderr.write(f"Serial port {SERIAL_PORT} not found after 30s\n")
        sys.exit(1)

    last_pid = find_agent_pid()
    if last_pid:
        sys.stderr.write(f"watchdog: monitoring agent PID {last_pid}\n")

    while True:
        time.sleep(CHECK_INTERVAL)
        current_pid = find_agent_pid()

        if last_pid and not current_pid:
            sys.stderr.write(f"watchdog: agent PID {last_pid} disappeared\n")
            try:
                with open(SERIAL_PORT, "wb", buffering=0) as port:
                    sign_and_write(port, key, "AGENT_KILLED",
                        f"watchdog detected agent death (PID {last_pid})")
            except Exception as e:
                sys.stderr.write(f"watchdog: failed to write AGENT_KILLED: {e}\n")

            time.sleep(RESTART_DELAY)
            if restart_agent():
                time.sleep(3)
                new_pid = find_agent_pid()
                sys.stderr.write(f"watchdog: agent restarted as PID {new_pid}\n")
                last_pid = new_pid
            else:
                last_pid = None
        elif current_pid != last_pid:
            last_pid = current_pid
            if last_pid:
                sys.stderr.write(f"watchdog: now monitoring agent PID {last_pid}\n")


if __name__ == "__main__":
    main()
