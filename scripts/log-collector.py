#!/usr/bin/env python3
"""
CareFortress Host Log Collector
Reads virtio-serial Unix sockets from all guest VMs.
Writes SHA-256 chained entries to an append-only log file.
"""

import json
import hashlib
import os
import socket
import threading
import time
from datetime import datetime, timezone

LOG_DIR = os.path.expanduser("~/carefortress-hv/logs")
CHAIN_LOG = os.path.join(LOG_DIR, "audit-chain.log")
AUDIT_VM_USER = "ubuntu"
AUDIT_VM_IP = "10.10.3.74"
AUDIT_VM_KEY = os.path.expanduser("~/.ssh/id_ed25519")
SCP_INTERVAL = 300

SERIAL_SOCKETS = {
    "medical-vm": "/run/libvirt/qemu/channel/medical-vm-log",
    "mgmt-vm":    "/run/libvirt/qemu/channel/mgmt-vm-log",
    "audit-vm":   "/run/libvirt/qemu/channel/audit-vm-log",
}

write_lock = threading.Lock()
last_hash = "0" * 64  # in-memory hash cache — updated inside write_lock

def get_last_hash():
    """Must be called inside write_lock."""
    try:
        with open(CHAIN_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return "0" * 64
            pos = size - 2
            while pos > 0:
                f.seek(pos)
                if f.read(1) == b"\n":
                    line = f.readline().decode().strip()
                    if line:
                        return json.loads(line).get("chain_hash", "0" * 64)
                pos -= 1
        return "0" * 64
    except Exception:
        return "0" * 64


def write_chained_entry(raw_line, source_vm):
    global last_hash
    try:
        payload = json.loads(raw_line.strip())
    except json.JSONDecodeError:
        payload = {"raw": raw_line.strip()}

    with write_lock:
        prev_hash = last_hash
        entry = {
            "collected_ts": datetime.now(timezone.utc).isoformat(),
            "source_vm": source_vm,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        entry_json = json.dumps(entry, sort_keys=True)
        entry["chain_hash"] = hashlib.sha256(
            (prev_hash + entry_json).encode()
        ).hexdigest()

        with open(CHAIN_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()

        last_hash = entry["chain_hash"]

def write_genesis():
    global last_hash
    prev_hash = "0" * 64
    entry = {
        "collected_ts": datetime.now(timezone.utc).isoformat(),
        "source_vm": "collector",
        "payload": {"type": "GENESIS", "msg": "CareFortress collector started"},
        "prev_hash": prev_hash,
    }
    entry_json = json.dumps(entry, sort_keys=True)
    entry["chain_hash"] = hashlib.sha256(
        (prev_hash + entry_json).encode()
    ).hexdigest()
    with open(CHAIN_LOG, "w") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
    last_hash = entry["chain_hash"]
    print(f"[collector] Genesis block written — hash: {last_hash[:16]}...")


def read_socket(vm_name, socket_path, ready_event=None):
    print(f"[collector] Starting reader for {vm_name}")
    while True:
        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(socket_path)
            print(f"[collector] Connected to {vm_name}")
            if ready_event:
                ready_event.set()
                ready_event = None
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    print(f"[collector] {vm_name} disconnected, reconnecting...")
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        write_chained_entry(line.decode(errors="replace"), vm_name)
        except Exception as e:
            time.sleep(5)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            if ready_event:
                ready_event.set()


def scp_to_audit_vm():
    import subprocess
    while True:
        time.sleep(SCP_INTERVAL)
        try:
            result = subprocess.run([
                "scp", "-i", AUDIT_VM_KEY, "-o", "StrictHostKeyChecking=no",
                CHAIN_LOG, f"{AUDIT_VM_USER}@{AUDIT_VM_IP}:~/audit-chain.log"
            ], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[collector] Chain log copied to audit-vm")
            else:
                print(f"[collector] SCP failed: {result.stderr.strip()}")
        except Exception as e:
            print(f"[collector] SCP error: {e}")


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    print(f"[collector] Starting — chain log: {CHAIN_LOG}")

    # Write genesis block BEFORE any threads start
    write_genesis()

    # Start reader threads sequentially, waiting for each to connect
    for vm_name, socket_path in SERIAL_SOCKETS.items():
        ready = threading.Event()
        t = threading.Thread(
            target=read_socket,
            args=(vm_name, socket_path, ready),
            daemon=True,
            name=f"reader-{vm_name}"
        )
        t.start()
        ready.wait(timeout=10)

    threading.Thread(target=scp_to_audit_vm, daemon=True, name="scp").start()
    print(f"[collector] All readers started. Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[collector] Shutting down.")


if __name__ == "__main__":
    main()
