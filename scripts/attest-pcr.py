#!/usr/bin/env python3
"""
CareFortress PCR Attestation Script
Reads current TPM PCR values and compares against the stored baseline.
Alerts on any deviation from known-good state.
"""

import subprocess
import sys
import os
from datetime import datetime, timezone

BASELINE_FILE = os.path.expanduser("~/carefortress-hv/docs/tpm/pcr-baseline.txt")
PCR_BANK = "sha256"


def read_pcrs():
    """Read current PCR values from TPM."""
    result = subprocess.run(
        ["tpm2_pcrread", PCR_BANK],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[attest] ERROR: tpm2_pcrread failed: {result.stderr.strip()}")
        sys.exit(1)
    return parse_pcr_output(result.stdout)


def parse_pcr_output(text):
    """Parse tpm2_pcrread output into a dict of {pcr_index: hash}."""
    pcrs = {}
    for line in text.splitlines():
        line = line.strip()
        if ':' in line and line[0].isdigit():
            parts = line.split(':', 1)
            idx = int(parts[0].strip())
            val = parts[1].strip()
            pcrs[idx] = val.upper()
    return pcrs


def load_baseline():
    """Load the stored PCR baseline."""
    if not os.path.exists(BASELINE_FILE):
        print(f"[attest] ERROR: Baseline file not found: {BASELINE_FILE}")
        print(f"[attest] Run: tpm2_pcrread sha256 > {BASELINE_FILE}")
        sys.exit(1)
    with open(BASELINE_FILE) as f:
        return parse_pcr_output(f.read())


def attest():
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[attest] CareFortress PCR Attestation — {ts}")
    print(f"[attest] Baseline: {BASELINE_FILE}")
    print(f"[attest] Bank: {PCR_BANK}")
    print()

    baseline = load_baseline()
    current = read_pcrs()

    # PCRs 17-22 are always 0xFF...FF on this platform — skip them
    SKIP_PCRS = {17, 18, 19, 20, 21, 22}

    deviations = []
    matches = 0

    all_pcrs = sorted(set(baseline.keys()) | set(current.keys()))
    for idx in all_pcrs:
        if idx in SKIP_PCRS:
            continue
        b_val = baseline.get(idx, "MISSING")
        c_val = current.get(idx, "MISSING")
        if b_val == c_val:
            matches += 1
        else:
            deviations.append((idx, b_val, c_val))

    print(f"[attest] PCRs checked: {matches + len(deviations)}  |  "
          f"Matches: {matches}  |  Deviations: {len(deviations)}")
    print()

    if not deviations:
        print(f"[attest] ✅ ATTESTATION PASSED — system state matches baseline")
        return True
    else:
        print(f"[attest] ❌ ATTESTATION FAILED — {len(deviations)} PCR deviation(s) detected")
        print()
        for idx, baseline_val, current_val in deviations:
            print(f"  PCR {idx:2d}:")
            print(f"    Baseline: {baseline_val}")
            print(f"    Current:  {current_val}")
        return False


if __name__ == "__main__":
    ok = attest()
    sys.exit(0 if ok else 1)
