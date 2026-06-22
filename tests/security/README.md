# CareFortress Security Validation Suite

This directory contains validation tools for verifying CareFortress
security controls are functioning correctly in your deployment.

## virtio_validation.py

Validates that the host collector correctly detects and flags unauthorized
data injection attempts on the virtio-serial audit channel.

**Usage:**
```bash
python3 tests/security/virtio_validation.py --vm medical-vm --ip <guest-ip>
```

**What it tests:**
- Kill-and-hijack injection detection (NO_HMAC alert)
- Unsigned entry detection
- Chain poisoning attempt detection
- Malformed JSON injection detection
- Fake ROTATION_GENESIS detection

Each test injects a specific payload and verifies the expected
AGENT_SECURITY_ALERT appears in the audit chain. Results are
reported as PASS/FAIL with chain integrity verification at the end.

## Full Attack Test Suite

A more comprehensive adversarial test suite covering additional attack
classes including oversized payloads, deep JSON recursion, binary data
injection, rapid flood attacks, and full kill-hijack scenarios with
timing analysis is available for security researchers and OEM evaluators.

For access to the full suite or to discuss security testing methodology,
contact the author via LinkedIn:

**https://linkedin.com/in/smithjamesd89**
