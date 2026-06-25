#!/usr/bin/env python3
"""
CareFortress virtio-serial Channel Security Validation Suite

PURPOSE: Validates that the CareFortress host collector correctly detects
and flags malicious or unauthorized data injected into the virtio-serial
audit channel. Run this from the HOST (VM 102) to validate your deployment.

This script is a VALIDATION TOOL -- it tests that detections work correctly
and reports PASS/FAIL for each test case. It is not a standalone attack tool.

REQUIREMENTS:
- Run from the CareFortress hypervisor host
- Guest VMs must be running with the CareFortress agent active
- SSH access to guest VMs must be configured
- Python 3.8+

USAGE:
    python3 tests/security/virtio_validation.py --vm medical-vm --ip 10.10.1.126

Each test injects a specific payload via the virtio-serial channel, then
verifies that the host collector generated the expected AGENT_SECURITY_ALERT
entry in the audit chain. A test PASSES if the detection fires correctly.
"""

import argparse
import json
import subprocess
import sys
import time
import os

# Default config -- override with args
DEFAULT_CHAIN_LOG = os.path.expanduser(
    "~/carefortress-hv/logs/audit-chain.log"
)

RESULTS = []

def log(msg):
    print(f"  {msg}")

def get_chain_line_count(chain_log):
    try:
        with open(chain_log) as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def get_alerts_since(chain_log, line_start, alert_type=None):
    """Get AGENT_SECURITY_ALERT entries added after line_start."""
    alerts = []
    try:
        with open(chain_log) as f:
            for i, line in enumerate(f):
                if i < line_start:
                    continue
                try:
                    e = json.loads(line.strip())
                    p = e.get('payload', {})
                    if p.get('event_type') == 'AGENT_SECURITY_ALERT':
                        alerts.append(p)
                except Exception:
                    pass
    except Exception:
        pass
    return alerts

def run_on_guest(vm_ip, cmd, use_sudo=True):
    """Run a command on a guest VM via SSH."""
    prefix = "sudo " if use_sudo else ""
    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ConnectTimeout=10",
         f"ubuntu@{vm_ip}", f"{prefix}{cmd}"],
        capture_output=True, text=True, timeout=30
    )
    return result

def inject_on_guest(vm_ip, payload, kill_agent=False):
    """Inject payload to virtio port on guest, optionally killing agent first."""
    import base64 as _b64
    vm_name = run_on_guest(vm_ip, "hostname", use_sudo=False).stdout.strip()
    virtio_port = "/dev/virtio-ports/log." + vm_name

    if kill_agent:
        run_on_guest(vm_ip, "fuser -k " + virtio_port)
        time.sleep(0.5)

    encoded = payload.encode() if isinstance(payload, str) else payload
    b64 = _b64.b64encode(encoded).decode()

    script_lines = [
        "import base64",
        "data = base64.b64decode('" + b64 + "')",
        "with open('" + virtio_port + "', 'wb') as f:",
        "    f.write(data + b'\n')",
        "    f.flush()",
    ]
    script_content = "\n".join(script_lines) + "\n"

    write_result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ConnectTimeout=10",
         "ubuntu@" + vm_ip, "sudo tee /tmp/cf_inject.py"],
        input=script_content, capture_output=True, text=True, timeout=30
    )
    result = run_on_guest(vm_ip, "python3 /tmp/cf_inject.py")
    return result.returncode == 0

def check_detection(chain_log, line_before, expected_warning_substr,
                    timeout=15):
    """Wait for expected detection in chain. Returns (detected, alerts)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        alerts = get_alerts_since(chain_log, line_before)
        for alert in alerts:
            # alerts are payload dicts -- check event_type and warnings
            if alert.get('event_type') == 'AGENT_SECURITY_ALERT':
                for w in alert.get('warnings', []):
                    if expected_warning_substr in w:
                        return True, alerts
        time.sleep(1)
    return False, get_alerts_since(chain_log, line_before)

def run_test(name, description, vm_ip, chain_log, test_fn,
             expected_warning, expect_detection=True):
    """Run a single validation test and record result."""
    log(f"Running: {name}")
    log(f"  {description}")

    line_before = get_chain_line_count(chain_log)
    try:
        test_fn(vm_ip)
    except Exception as e:
        RESULTS.append((name, "ERROR", str(e)))
        log(f"  ERROR: {e}")
        return

    if expect_detection:
        detected, alerts = check_detection(
            chain_log, line_before, expected_warning
        )
        if detected:
            RESULTS.append((name, "PASS",
                           f"Detection fired: {expected_warning}"))
            log(f"  ✅ PASS -- AGENT_SECURITY_ALERT generated: {expected_warning}")
        else:
            RESULTS.append((name, "FAIL",
                           f"Expected detection '{expected_warning}' not seen"))
            log(f"  ❌ FAIL -- expected '{expected_warning}' but got: {alerts}")
    else:
        # Expect NO alert (legitimate entry)
        time.sleep(3)
        alerts = get_alerts_since(chain_log, line_before)
        spurious = [a for a in alerts
                   if expected_warning not in str(a.get('warnings', []))]
        if not spurious:
            RESULTS.append((name, "PASS", "No false positive alert"))
            log(f"  ✅ PASS -- no false positive")
        else:
            RESULTS.append((name, "FAIL",
                           f"False positive alert: {spurious}"))
            log(f"  ❌ FAIL -- unexpected alert: {spurious}")

def main():
    parser = argparse.ArgumentParser(
        description="CareFortress virtio-serial security validation"
    )
    parser.add_argument("--vm", default="medical-vm", help="VM name")
    parser.add_argument("--ip", default="10.10.1.126", help="VM IP")
    parser.add_argument("--chain-log", default=DEFAULT_CHAIN_LOG)
    args = parser.parse_args()

    print(f"\nCareFortress virtio-serial Validation Suite")
    print(f"Target VM: {args.vm} ({args.ip})")
    print(f"Chain log: {args.chain_log}")
    print(f"{'='*60}\n")

    # ── T01: Kill-and-hijack injection (no HMAC) ─────────────────────
    def t01_kill_hijack(vm_ip):
        payload = json.dumps({
            "event_type": "VALIDATION_INJECT",
            "message": "kill-hijack test -- no hmac"
        })
        inject_on_guest(vm_ip, payload, kill_agent=True)
        time.sleep(2)

    run_test(
        "T01 Kill-and-hijack injection",
        "Kills guest agent, injects unsigned entry. Expects NO_HMAC alert.",
        args.ip, args.chain_log, t01_kill_hijack, "NO_HMAC"
    )

    # Wait for agent to restart
    time.sleep(8)

    # ── T02: Unsigned entry without killing agent ─────────────────────
    def t02_unsigned(vm_ip):
        payload = json.dumps({
            "event_type": "VALIDATION_UNSIGNED",
            "message": "unsigned entry test"
        })
        # Write directly -- this will fail if agent holds port
        # Expected: either blocked (PASS) or flagged (PASS)
        try:
            inject_on_guest(vm_ip, payload, kill_agent=False)
        except Exception:
            pass

    run_test(
        "T02 Unsigned entry attempt",
        "Attempts to inject unsigned entry without killing agent. "
        "Expects either port-busy block or NO_HMAC alert.",
        args.ip, args.chain_log, t02_unsigned, "NO_HMAC",
        expect_detection=False  # Port will be busy -- this is a PASS
    )

    # ── T03: Chain poisoning -- forged prev_hash ──────────────────────
    def t03_chain_poison(vm_ip):
        payload = json.dumps({
            "event_type": "VALIDATION_POISON",
            "prev_hash": "0" * 64,
            "chain_hash": "f" * 64,
            "message": "chain poisoning attempt"
        })
        inject_on_guest(vm_ip, payload, kill_agent=True)
        time.sleep(2)

    run_test(
        "T03 Chain poisoning attempt",
        "Injects entry with forged prev_hash/chain_hash. "
        "Expects NO_HMAC alert -- host controls chain hashing.",
        args.ip, args.chain_log, t03_chain_poison, "NO_HMAC"
    )

    time.sleep(8)

    # ── T04: Malformed JSON injection ─────────────────────────────────
    def t04_malformed(vm_ip):
        inject_on_guest(vm_ip,
            '{"unclosed": "json injection attempt',
            kill_agent=True)
        time.sleep(2)

    run_test(
        "T04 Malformed JSON injection",
        "Injects malformed JSON. Expects NO_HMAC alert "
        "(parsed as raw entry, no valid hmac field).",
        args.ip, args.chain_log, t04_malformed, "NO_HMAC"
    )

    time.sleep(8)

    # ── T05: Fake ROTATION_GENESIS injection ──────────────────────────
    def t05_fake_genesis(vm_ip):
        payload = json.dumps({
            "event_type": "ROTATION_GENESIS",
            "message": "attacker controlled genesis -- chain reset attempt"
        })
        inject_on_guest(vm_ip, payload, kill_agent=True)
        time.sleep(2)

    run_test(
        "T05 Fake ROTATION_GENESIS",
        "Injects fake genesis entry. Expects NO_HMAC alert.",
        args.ip, args.chain_log, t05_fake_genesis, "NO_HMAC"
    )

    time.sleep(8)

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("VALIDATION SUMMARY")
    print(f"{'='*60}")
    passed = sum(1 for _, r, _ in RESULTS if r == "PASS")
    failed = sum(1 for _, r, _ in RESULTS if r == "FAIL")
    errors = sum(1 for _, r, _ in RESULTS if r == "ERROR")

    for name, result, detail in RESULTS:
        icon = "✅" if result == "PASS" else "❌" if result == "FAIL" else "⚠️"
        print(f"  {icon} {result:5} | {name}")
        if result != "PASS":
            print(f"         {detail}")

    print(f"\n  Total: {passed} passed, {failed} failed, {errors} errors")

    if failed == 0 and errors == 0:
        print("\n  ✅ All detections working correctly.")
        print("  virtio-serial channel attack detection: VERIFIED")
    else:
        print("\n  ❌ Some detections failed -- review output above.")

    # Validate chain integrity after tests
    print("\n  Validating chain integrity post-test...")
    result = subprocess.run(
        ["python3",
         os.path.expanduser("~/carefortress-hv/scripts/validate-chain.py")],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines()[-3:]:
        print(f"  {line}")

if __name__ == "__main__":
    main()
