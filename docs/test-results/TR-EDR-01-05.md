# CareFortress EDR Test Results — TR-EDR-01 through TR-EDR-05

**Date:** 2026-07-02  
**Tester:** James Smith  
**Environment:** VM 102 (Ubuntu 26.04) → medical-vm (Ubuntu 24.04, Q35)  
**Chain entries at test start:** ~372,527

---

## TR-EDR-01: Kill Agent Only
**Status: PASS**  
- Agent PID 1831 killed with `kill -9`
- Watchdog detected death within 5s check interval
- `AGENT_KILLED` entry written to virtio-serial with valid HMAC (seq -1)
- Collector logged `AGENT_SECURITY_ALERT: SEQ_REWIND` on the -1 sentinel
- Agent restarted as new PID by watchdog
- Chain entry confirmed: collected_ts 2026-07-02T14:23:26

---

## TR-EDR-02: Kill Watchdog Only
**Status: PASS**  
- Watchdog PID 1828 killed with `kill -9`
- systemd `Restart=always` restarted watchdog within ~5s (new PID)
- Agent continued running uninterrupted — no gap in chain
- No AGENT_KILLED logged (correct — agent was alive)
- **Finding:** systemd is the outer resilience layer for the watchdog itself.
  Chain of custody: systemd → watchdog → agent

---

## TR-EDR-03: Kill Both Watchdog and Agent Simultaneously
**Status: PARTIAL PASS — Expected Limitation**  
- Both PIDs killed simultaneously with `kill -9 <watchdog> <agent>`
- No `AGENT_KILLED` entry written — watchdog had no time to detect and write before dying
- systemd restarted watchdog; watchdog started fresh agent
- Agent resumed from saved sequence number — no SEQ_GAP detected
- **Finding:** Simultaneous kill of both processes cannot produce an in-band
  AGENT_KILLED alert. The forensic indicator is a START entry with no preceding
  AGENT_KILLED — this anomaly pattern should be flagged by a SIEM rule.
- **Limitation documented:** Single-process watchdog cannot survive its own
  simultaneous kill. Mitigation: systemd as outer layer + SIEM anomaly detection.

---

## TR-EDR-04: Forged Entry Injection from Guest
**Status: PASS — Stronger Than Expected**  
- Attempted: `echo '<forged JSON>' | sudo tee /dev/virtio-ports/log.medical-vm`
- Result: `tee: /dev/virtio-ports/log.medical-vm: Device or resource busy`
- The agent holds the virtio-serial port exclusively at the OS level
- Forged entry never reached the collector — blocked before HMAC verification
- **Finding:** Exclusive port hold is the primary injection defense.
  HMAC verification is a secondary layer for cases where port access is obtained
  (e.g., agent stopped, race condition).

---

## TR-EDR-05: Sequence Number Replay
**Status: PASS — Blocked by Same Mechanism as TR-EDR-04**  
- Replay injection requires writing to the virtio-serial port
- Port is held exclusively by the running agent (same as TR-EDR-04)
- Direct replay injection not possible while agent is running
- **If agent is stopped:** collector's `verify_entry()` would detect SEQ_REWIND
  on any replayed sequence number lower than the last seen value
- SEQ_REWIND detection confirmed functional in TR-EDR-01 (seq -1 sentinel)

---

## Summary

| Test | Result | Detection Mechanism |
|------|--------|-------------------|
| TR-EDR-01 | PASS | Watchdog → AGENT_KILLED → SEQ_REWIND alert |
| TR-EDR-02 | PASS | systemd Restart=always, no chain gap |
| TR-EDR-03 | PARTIAL PASS | Documented limitation, START-without-KILLED anomaly |
| TR-EDR-04 | PASS | OS-level exclusive port hold |
| TR-EDR-05 | PASS | OS-level exclusive port hold + SEQ_REWIND (verified in TR-EDR-01) |

## Chain Integrity Post-Test
[validator] Validating chain: /home/b33rmamba/carefortress-hv/logs/audit-chain.log

[validator] Results: 383075 entries valid, 0 errors
[validator] ✅ Chain integrity VERIFIED — all 383075 entries intact

**Validator output appended above.**
