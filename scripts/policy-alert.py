#!/usr/bin/env python3
import subprocess
import re
from datetime import datetime, timezone

WATCHED_BRIDGES = ["virbr1", "virbr2", "virbr3"]

def parse_ufw_block(line):
    fields = {}
    for key in ["IN", "OUT", "SRC", "DST", "PROTO", "SPT", "DPT"]:
        m = re.search(key + r"=(\S+)", line)
        if m:
            fields[key] = m.group(1)
    return fields

def is_carefortress_block(fields):
    return any(b in fields.get("IN", "") or b in fields.get("OUT", "")
               for b in WATCHED_BRIDGES)

def alert(fields):
    ts = datetime.now(timezone.utc).isoformat()
    src = fields.get("SRC", "unknown")
    dst = fields.get("DST", "unknown")
    proto = fields.get("PROTO", "unknown")
    dpt = fields.get("DPT", "")
    iface_in = fields.get("IN", "")
    iface_out = fields.get("OUT", "")
    port_str = " -> port " + dpt if dpt else ""
    print("")
    print("=" * 60)
    print("[CAREFORTRESS ALERT] Policy Violation Detected")
    print("  Time:      " + ts)
    print("  Source:    " + src)
    print("  Dest:      " + dst + port_str)
    print("  Protocol:  " + proto)
    print("  Interface: IN=" + iface_in + " OUT=" + iface_out)
    print("=" * 60)
    print("")

def main():
    print("[policy-alert] CareFortress Policy Violation Monitor started")
    print("[policy-alert] Watching bridges: " + ", ".join(WATCHED_BRIDGES))
    print("[policy-alert] Monitoring journalctl for UFW BLOCK events...")
    proc = subprocess.Popen(
        ["journalctl", "-f", "--no-pager", "-o", "short-unix"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    seen = set()
    try:
        for line in proc.stdout:
            if "[UFW BLOCK]" not in line:
                continue
            idx = line.find("[UFW BLOCK]"); sig = line[idx:].strip() if idx >= 0 else line.strip()
            if sig in seen:
                continue
            seen.add(sig)
            if len(seen) > 1000:
                seen.clear()
            fields = parse_ufw_block(line)
            if not fields.get("SRC"):
                continue
            if is_carefortress_block(fields):
                alert(fields)
            else:
                print("[policy-alert] Non-bridge UFW BLOCK: SRC=" + fields.get("SRC","") + " DST=" + fields.get("DST",""))
    except KeyboardInterrupt:
        print("")
        print("[policy-alert] Monitor stopped.")
        proc.terminate()

if __name__ == "__main__":
    main()
