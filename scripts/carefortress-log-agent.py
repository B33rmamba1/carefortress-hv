#!/usr/bin/env python3
"""
CareFortress Guest Log Agent v2
Writes HMAC-SHA256 signed structured JSON log entries to virtio-serial port.
Includes sequence number tracking for replay/injection detection.
Runs on each guest VM.
"""
import json
import time
import socket
import os
import sys
import hmac
import hashlib
from datetime import datetime, timezone

SERIAL_PORT = f"/dev/virtio-ports/log.{socket.gethostname()}"
HMAC_KEY_FILE = "/etc/carefortress-agent.key"
SEQ_FILE = "/var/lib/carefortress/seq"
FLUSH_INTERVAL = 5


def load_hmac_key():
    try:
        with open(HMAC_KEY_FILE, 'r') as f:
            return f.read().strip().encode()
    except Exception as e:
        sys.stderr.write(f"FATAL: cannot load HMAC key: {e}\n")
        sys.exit(1)


def load_seq():
    try:
        with open(SEQ_FILE, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0
    except Exception as e:
        sys.stderr.write(f"WARNING: cannot load sequence number: {e} -- starting at 0\n")
        return 0


def save_seq(seq):
    try:
        os.makedirs(os.path.dirname(SEQ_FILE), exist_ok=True)
        with open(SEQ_FILE, 'w') as f:
            f.write(str(seq))
    except Exception as e:
        sys.stderr.write(f"WARNING: cannot save sequence number: {e}\n")


def sign_entry(payload, key):
    payload_str = json.dumps(payload, sort_keys=True)
    sig = hmac.new(key, payload_str.encode(), hashlib.sha256).hexdigest()
    payload["agent_hmac"] = sig
    return payload


def write_entry(port, key, seq_ref, event_type, message, extra=None):
    seq_ref[0] += 1
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "type": event_type,
        "msg": message,
        "agent_seq": seq_ref[0],
    }
    if extra:
        entry.update(extra)
    entry = sign_entry(entry, key)
    save_seq(seq_ref[0])
    try:
        line = json.dumps(entry) + "\n"
        port.write(line.encode())
        port.flush()
    except Exception as e:
        sys.stderr.write(f"write_entry error: {e}\n")


def get_logged_in_users():
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
    key = load_hmac_key()
    seq_ref = [load_seq()]

    for _ in range(30):
        if os.path.exists(SERIAL_PORT):
            break
        time.sleep(1)
    if not os.path.exists(SERIAL_PORT):
        sys.stderr.write(f"Serial port {SERIAL_PORT} not found after 30s\n")
        sys.exit(1)

    agent_hash = hashlib.sha256(open(__file__, "rb").read()).hexdigest()

    with open(SERIAL_PORT, "wb", buffering=0) as port:
        write_entry(port, key, seq_ref, "START",
                    "CareFortress log agent v2 started (HMAC-signed)")
        last_users = ""
        while True:
            try:
                load = get_load()
                write_entry(port, key, seq_ref, "HEARTBEAT", "periodic check", {
                    "load_1m": load[0],
                    "load_5m": load[1],
                    "load_15m": load[2],
                    "agent_hash": agent_hash,
                })
                users = get_logged_in_users()
                if users != last_users:
                    write_entry(port, key, seq_ref, "AUTH", "user session change", {
                        "sessions": users
                    })
                    last_users = users
                time.sleep(FLUSH_INTERVAL)
            except Exception as e:
                sys.stderr.write(f"agent loop error: {e}\n")
                time.sleep(FLUSH_INTERVAL)


if __name__ == "__main__":
    main()
