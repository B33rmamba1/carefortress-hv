#!/usr/bin/env python3
"""
CareFortress Chain Validator
Walks the audit-chain.log and verifies every SHA-256 hash.
Alerts if the chain is broken at any point.
"""

import json
import hashlib
import os
import sys

CHAIN_LOG = os.path.expanduser("~/carefortress-hv/logs/audit-chain.log")

def validate_chain(log_path):
    if not os.path.exists(log_path):
        print(f"[validator] ERROR: Log file not found: {log_path}")
        sys.exit(1)

    prev_hash = "0" * 64
    # Allow ROTATION_GENESIS as valid chain start with non-zero prev_hash
    _first_line = open(log_path).readline().strip()
    try:
        _first_entry = json.loads(_first_line)
        if _first_entry.get("type") == "ROTATION_GENESIS":
            prev_hash = _first_entry.get("prev_hash", "0" * 64)
            print(f"[validator] Rotation chain -- seeding from prev hash: {prev_hash[:16]}...")
    except Exception:
        pass
    total = 0
    errors = 0

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[validator] LINE {line_num}: PARSE ERROR — {e}")
                errors += 1
                continue

            stored_prev = entry.get("prev_hash", "")
            stored_hash = entry.get("chain_hash", "")

            # Check prev_hash matches what we computed
            if stored_prev != prev_hash:
                print(f"[validator] LINE {line_num}: CHAIN BREAK — "
                      f"expected prev_hash {prev_hash[:16]}... "
                      f"got {stored_prev[:16]}...")
                errors += 1

            # Recompute chain_hash
            check_entry = {k: v for k, v in entry.items()
                          if k != "chain_hash"}
            entry_json = json.dumps(check_entry, sort_keys=True)
            expected_hash = hashlib.sha256(
                (stored_prev + entry_json).encode()
            ).hexdigest()

            if expected_hash != stored_hash:
                print(f"[validator] LINE {line_num}: HASH MISMATCH — "
                      f"expected {expected_hash[:16]}... "
                      f"got {stored_hash[:16]}...")
                errors += 1
            else:
                total += 1

            prev_hash = stored_hash

    print(f"\n[validator] Results: {total} entries valid, {errors} errors")
    if errors == 0:
        print(f"[validator] ✅ Chain integrity VERIFIED — all {total} entries intact")
        return True
    else:
        print(f"[validator] ❌ Chain integrity FAILED — {errors} violations detected")
        return False

if __name__ == "__main__":
    log = sys.argv[1] if len(sys.argv) > 1 else CHAIN_LOG
    print(f"[validator] Validating chain: {log}")
    ok = validate_chain(log)
    sys.exit(0 if ok else 1)
