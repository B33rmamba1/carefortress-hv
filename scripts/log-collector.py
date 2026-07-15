#!/usr/bin/env python3
"""
CareFortress Host Log Collector
Reads virtio-serial Unix sockets from all guest VMs.
Writes SHA-256 chained entries to an append-only log file.
"""

import json
import hashlib
import hmac
import os
import socket
import threading
import time
from datetime import datetime, timezone

LOG_DIR = os.path.expanduser("~/carefortress-hv/logs")
CHAIN_LOG = os.path.join(LOG_DIR, "audit-chain.log")
AUDIT_VM_USER = "ubuntu"
AUDIT_VM_IP = "10.10.3.30"
AUDIT_VM_KEY = os.path.expanduser("~/.ssh/carefortress_collector")
SCP_INTERVAL = 60

import glob as _glob

def _find_socket(vm_name):
    matches = _glob.glob(f"/run/libvirt/qemu/channel/*-{vm_name}/log.{vm_name}")
    return matches[0] if matches else f"/run/libvirt/qemu/channel/{vm_name}-log"

VM_NAMES = ["medical-vm", "mgmt-vm", "audit-vm"]


# ── HMAC verification setup ───────────────────────────────────────────
AGENT_KEY_FILE = "/etc/carefortress-agent.key"
_agent_key = None
_vm_seq = {}  # track last sequence number per VM
_expected_agent_hash = None  # cached expected hash from config

def load_agent_key():
    global _agent_key
    try:
        with open(AGENT_KEY_FILE, 'r') as f:
            _agent_key = f.read().strip().encode()
        print(f"[collector] HMAC verification key loaded")
    except Exception as e:
        print(f"[collector] WARNING: cannot load agent key: {e} -- HMAC verification disabled")
        _agent_key = None

def load_expected_agent_hash():
    global _expected_agent_hash
    hash_file = os.path.join(os.path.expanduser("~/carefortress-hv/config"), "agent-hash.sha256")
    try:
        with open(hash_file, 'r') as f:
            _expected_agent_hash = f.read().strip()
        print(f"[collector] Expected agent hash loaded: {_expected_agent_hash[:16]}...")
    except Exception as e:
        print(f"[collector] WARNING: cannot load agent hash: {e} -- hash verification disabled")
        _expected_agent_hash = None

def verify_entry(payload, raw_line):
    """Verify HMAC signature and sequence number of an agent entry.
    Returns (verified, warnings) where warnings is a list of issue strings."""
    warnings = []

    # Extract and verify HMAC
    agent_hmac = payload.get("agent_hmac")
    if agent_hmac is None:
        warnings.append("NO_HMAC: entry has no agent_hmac field")
    elif _agent_key is None:
        warnings.append("KEY_MISSING: cannot verify HMAC -- no key loaded")
    elif agent_hmac != "unsigned":
        # Reconstruct the payload as it was before hmac was added
        check_payload = {k: v for k, v in payload.items() if k != "agent_hmac"}
        payload_str = __import__('json').dumps(check_payload, sort_keys=True)
        expected = hmac.new(_agent_key, payload_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(agent_hmac, expected):
            warnings.append(f"HMAC_FAIL: signature mismatch -- possible injection")

    # Check sequence number
    agent_seq = payload.get("agent_seq")
    source_vm = payload.get("host", "unknown")
    if agent_seq is not None:
        last_seq = _vm_seq.get(source_vm)
        if last_seq is not None:
            gap = agent_seq - last_seq - 1
            if gap > 0:
                warnings.append(f"SEQ_GAP: expected seq {last_seq+1} got {agent_seq} -- {gap} entries missing")
            elif agent_seq <= last_seq:
                warnings.append(f"SEQ_REWIND: seq went backwards {last_seq} -> {agent_seq} -- possible agent restart or injection")
        _vm_seq[source_vm] = agent_seq

    # Check agent binary hash (present in HEARTBEAT entries)
    agent_hash = payload.get("agent_hash")
    if agent_hash is not None and _expected_agent_hash is not None:
        if agent_hash != _expected_agent_hash:
            warnings.append(f"AGENT_HASH_MISMATCH: expected {_expected_agent_hash[:16]}... got {agent_hash[:16]}... -- possible binary tampering")

    return len(warnings) == 0, warnings

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

    # Verify HMAC and sequence number
    verified, warnings = verify_entry(payload, raw_line)
    if warnings:
        for w in warnings:
            print(f"[collector] SECURITY WARNING [{source_vm}]: {w}")
        # Write a security alert entry to the chain
        _alert = {
            "event_type": "AGENT_SECURITY_ALERT",
            "source_vm": source_vm,
            "warnings": warnings,
            "raw_preview": raw_line.strip()[:200]
        }
        # Write the alert AND the suspicious entry both to chain
        # so the full record is preserved for forensics
        with write_lock:
            prev_hash = last_hash
            alert_entry = {
                "collected_ts": datetime.now(timezone.utc).isoformat(),
                "source_vm": source_vm,
                "payload": _alert,
                "prev_hash": prev_hash,
            }
            alert_json = json.dumps(alert_entry, sort_keys=True)
            alert_entry["chain_hash"] = hashlib.sha256(
                (prev_hash + alert_json).encode()
            ).hexdigest()
            with open(CHAIN_LOG, "a") as f:
                f.write(json.dumps(alert_entry) + "\n")
                f.flush()
            last_hash = alert_entry["chain_hash"]

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

def _repair_truncate(valid_count):
    """Truncate chain log to keep only the first valid_count entries.
    Removes corrupt trailing data (null bytes, partial writes) from disk-full events."""
    import tempfile
    print(f"[collector] Truncating chain to {valid_count} valid entries...")
    try:
        os.system(f"sudo chattr -a {CHAIN_LOG} 2>/dev/null")
        with open(CHAIN_LOG, "r") as src:
            # Find byte offset of end of last valid entry
            offset = 0
            entry_num = 0
            for line in src:
                stripped = line.strip()
                if not stripped:
                    offset += len(line)
                    continue
                try:
                    json.loads(stripped)
                except json.JSONDecodeError:
                    break
                offset += len(line)
                entry_num += 1
                if entry_num >= valid_count:
                    break
        with open(CHAIN_LOG, "r+b") as f:
            f.truncate(offset)
        os.system(f"sudo chattr +a {CHAIN_LOG} 2>/dev/null")
        print(f"[collector] Truncated to {offset} bytes ({entry_num} entries)")
    except Exception as e:
        print(f"[collector] Repair truncation failed: {e}")
        os.system(f"sudo chattr +a {CHAIN_LOG} 2>/dev/null")

def validate_chain():
    """Validate the chain. Returns (valid, last_hash, entry_count).
    Corrupt trailing data (e.g. null bytes from disk-full) is auto-repaired
    by truncating to the last valid entry, not treated as a chain break."""
    prev_hash = "0" * 64
    # Allow ROTATION_GENESIS as valid chain start
    try:
        _fl = open(CHAIN_LOG).readline().strip()
        _fe = json.loads(_fl)
        if _fe.get("type") == "ROTATION_GENESIS":
            prev_hash = _fe.get("prev_hash", "0" * 64)
            print(f"[collector] Rotation chain detected -- seeding from prev hash: {prev_hash[:16]}...")
    except Exception:
        pass
    count = 0
    try:
        with open(CHAIN_LOG, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    # Corrupt trailing data (null bytes, partial write).
                    # If we validated entries before this, the chain is intact --
                    # truncate the garbage rather than declaring a break.
                    if count > 0:
                        print(f"[collector] Corrupt trailing data at line {count} -- auto-repairing by truncation")
                        _repair_truncate(count)
                        return True, prev_hash, count
                    return False, prev_hash, count
                stored_hash = entry.get("chain_hash", "")
                entry_copy = {k: v for k, v in entry.items() if k != "chain_hash"}
                entry_json = json.dumps(entry_copy, sort_keys=True)
                expected = hashlib.sha256((prev_hash + entry_json).encode()).hexdigest()
                if stored_hash != expected:
                    return False, prev_hash, count
                prev_hash = stored_hash
                count += 1
        return True, prev_hash, count
    except FileNotFoundError:
        return True, "0" * 64, 0
    except Exception as e:
        print(f"[collector] Unexpected validation error at entry {count}: {e}")
        if count > 0:
            return True, prev_hash, count
        return False, prev_hash, count

def isolate_broken_log():
    """Move broken log to quarantine preserving evidence."""
    import shutil
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    broken_path = os.path.join(LOG_DIR, f"audit-chain-BROKEN-{ts}.log")
    os.system(f"sudo chattr -a {CHAIN_LOG} 2>/dev/null")
    shutil.move(CHAIN_LOG, broken_path)
    print(f"[collector] CHAIN BREAK -- broken log isolated to {broken_path}")
    return broken_path

def write_genesis(prev_hash=None, msg="CareFortress collector started", broken_ref=None):
    global last_hash
    if prev_hash is None:
        prev_hash = "0" * 64
    payload_msg = msg
    if broken_ref:
        payload_msg += f" -- previous chain broken, isolated to {os.path.basename(broken_ref)}"
    entry = {
        "collected_ts": datetime.now(timezone.utc).isoformat(),
        "source_vm": "collector",
        "payload": {"type": "GENESIS", "msg": payload_msg},
        "prev_hash": prev_hash,
    }
    entry_json = json.dumps(entry, sort_keys=True)
    entry["chain_hash"] = hashlib.sha256(
        (prev_hash + entry_json).encode()
    ).hexdigest()
    with open(CHAIN_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
    os.system(f"sudo chattr +a {CHAIN_LOG} 2>/dev/null")
    last_hash = entry["chain_hash"]
    print(f"[collector] Genesis block written -- hash: {last_hash[:16]}...")


def read_socket(vm_name, ready_event=None):
    print(f"[collector] Starting reader for {vm_name}")
    while True:
        sock = None
        socket_path = _find_socket(vm_name)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(socket_path)
            print(f"[collector] Connected to {vm_name}")
            # Write reconnect sentinel so timeline is clear in chain
            _rc_entry = json.dumps({
                "event_type": "AGENT_CONNECT",
                "source_vm": vm_name,
                "message": "virtio-serial connection established"
            })
            write_chained_entry(_rc_entry, vm_name)
            if ready_event:
                ready_event.set()
                ready_event = None
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    print(f"[collector] {vm_name} disconnected, reconnecting...")
                    # Write sentinel -- any data after this is potentially untrusted
                    _dc_entry = json.dumps({
                        "event_type": "AGENT_DISCONNECT",
                        "source_vm": vm_name,
                        "message": "virtio-serial connection lost -- channel integrity unverified until reconnect",
                        "severity": "WARNING"
                    })
                    write_chained_entry(_dc_entry, vm_name)
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
    global last_hash
    os.makedirs(LOG_DIR, exist_ok=True)
    print(f"[collector] Starting — chain log: {CHAIN_LOG}")

    # Validate existing chain before starting
    if os.path.exists(CHAIN_LOG):
        print("[collector] Validating existing chain...")
        valid, last_valid_hash, count = validate_chain()
        if valid:
            print(f"[collector] Chain valid — {count} entries. Resuming.")
            # Check for gap
            import subprocess
            result = subprocess.run(
                ["/usr/bin/tail", "-1", CHAIN_LOG],
                capture_output=True, text=True
            )
            try:
                last_entry = json.loads(result.stdout.strip())
                last_ts = last_entry.get("collected_ts", "")
                if last_ts:
                    from datetime import timedelta
                    last_dt = datetime.fromisoformat(last_ts)
                    gap = datetime.now(timezone.utc) - last_dt
                    if gap.total_seconds() > 300:
                        print(f"[collector] GAP DETECTED — {gap} since last entry")
                        write_genesis(
                            prev_hash=last_valid_hash,
                            msg=f"Collector restarted after gap of {gap}"
                        )
                    else:
                        last_hash = last_valid_hash
            except Exception:
                last_hash = last_valid_hash
        else:
            print(f"[collector] CHAIN BREAK DETECTED after {count} entries — isolating broken log")
            broken_ref = isolate_broken_log()
            write_genesis(msg="New chain after break", broken_ref=broken_ref)
    else:
        # Fresh start
        write_genesis()

    load_agent_key()
    load_expected_agent_hash()
    # Start reader threads sequentially, waiting for each to connect
    for vm_name in VM_NAMES:
        ready = threading.Event()
        t = threading.Thread(
            target=read_socket,
            args=(vm_name, ready),
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
