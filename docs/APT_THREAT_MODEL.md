# CareFortress APT & Ransomware Threat Model

**Date:** June 18, 2026
**Author:** James Smith
**Framework:** MITRE ATT&CK (Enterprise), kill-chain aligned
**Classification:** Defensive architectural threat model — public

---

## 1. Scope and Methodology

This is a defensive threat model. It reasons about adversary objectives and capabilities at the architectural level — mapped to MITRE ATT&CK tactics — in order to establish what the CareFortress architecture prevents, contains, mitigates, or leaves as residual risk. It contains no operational attack tooling, exploit code, or weaponization detail; it is intended to make the defense better and to be published alongside the project as evidence of design rigor.

The headline adversary is financially-motivated ransomware, the case most relevant to hospital patient safety. A broader advanced-persistent-threat (APT) profile is modeled alongside it because nation-state objectives (long-dwell exfiltration, pre-positioning) exercise different controls.

**Core design premise:** the protected medical devices are unpatchable certified systems. This model therefore *assumes the guest will eventually be compromised* and evaluates the architecture on what that compromise is worth — not on whether it can be prevented.

**Deployment note:** the development lab nests the CareFortress hypervisor under Proxmox. In production CareFortress is the bare-metal hypervisor at the facility edge; the Proxmox layer does not exist. Throughout this document, "the host" refers to the CareFortress hypervisor itself, which in production runs directly on dedicated hardware.

---

## 2. Threat Actors

### TA-1 — Financially-Motivated Ransomware (headline)
Archetype: Conti, LockBit, BlackCat/ALPHV. Fast, high-noise, double-extortion (encryption plus data-theft leverage). Healthcare is deliberately targeted because downtime translates directly into patient harm and therefore into willingness to pay. Standard behavior includes hunting and destroying backups before detonation.

### TA-2 — Advanced Persistent Threat (broader)
Archetype: long-dwell critical-infrastructure intrusion (Volt Typhoon-style). Slow, stealthy, living-off-the-land. Objectives are PHI exfiltration over months and/or pre-positioning for disruption at a chosen time. Defeats conventional defenses through patience and abuse of legitimate functionality rather than malware noise.

---

## 3. Protected Assets

1. Availability of medical devices for patient care
2. Integrity of clinical data emitted by devices (HL7 / DICOM)
3. Confidentiality of PHI
4. Integrity and non-repudiation of the audit record
5. The CareFortress hypervisor host (highest-value asset)

---

## 4. Thesis

CareFortress does not prevent a medical device from being compromised and does not claim to. The devices are unpatchable; any honest model assumes the guest falls. What the architecture changes is the consequence of that compromise.

**CareFortress converts ransomware against the medical device fleet from a fleet-wide, persistent, stealthy, catastrophic event into a single-device, recoverable, detected, contained one.**

That is the claim this document defends, phase by phase.

---

## 5. Kill Chain Analysis

### Initial Access / Execution (TA0001 / TA0002) — OUT OF SCOPE (by design)
The certified guest OS runs its certified, vulnerable software. The in-guest agent provides telemetry, not endpoint protection. CareFortress neither prevents initial access to the device nor execution within it. Containment begins the instant after compromise. Claiming otherwise would be dishonest; the architecture's value is everything downstream of this point.

### Persistence (TA0003) — CONTAINED
Persistence inside the guest (services, registry, implants) is achievable and not prevented. It is rendered inert by snapshot rollback to a known-good state, and boot-level tampering is detectable through TPM PCR drift where guest measured boot is configured. Persistence has no value against a system that can be restored to clean state on demand.

### Privilege Escalation (TA0004) — CRITICAL BOUNDARY
Escalation to SYSTEM/root inside the guest yields the attacker nothing — they remain sealed within the VM. The only escalation that matters is VM escape (QEMU/virtio class). This is the single decisive boundary in the architecture. QEMU runs under an AppArmor profile in enforce mode, scoped to minimum required resources, so that even a successful hypervisor escape lands in a confined, low-privilege process rather than as root on the host. Validated in Section 8, Test 3.

### Defense Evasion (TA0005) — PREVENTED
This is the architecture's strongest property against both actors. The audit record is collected *out* of the guest over a virtio-serial channel to the host, SHA-256 chained, and held append-only through kernel-enforced `chattr +a`. An attacker with complete ownership of the guest cannot reach, alter, or truncate the host-side chain: it resides across a hypervisor boundary they cannot cross, tampering is cryptographically detectable, and truncation is blocked at the VFS layer. Ransomware's routine log-clearing and APT log-blending both fail here. Validated in Section 8, Test 2.

### Discovery (TA0007) — PREVENTED
From a compromised guest the attacker is in a sealed room. Isolated bridges with deny-all default and no inter-VM routing mean the guest cannot enumerate sibling device VMs, the management VM, or the audit VM. Network reconnaissance returns nothing.

### Lateral Movement (TA0008) — PREVENTED (headline ransomware win)
This is the phase that turns a single infection into a fleet-wide hospital outbreak, and it is architecturally dead. Isolated networks and deny-all routing mean a compromised device VM cannot reach any sibling device. The only sanctioned outbound path is content-inspected protocol traffic to one designated upstream; worm propagation (SMB, RDP, the WannaCry/NotPetya mechanism) cannot be tunneled through an HL7 proxy that forwards only whitelisted message types. One ransomed device remains one ransomed device. Validated in Section 8, Test 1.

### Collection / Exfiltration (TA0009 / TA0010) — PARTIALLY MITIGATED (residual gap)
Direct network exfiltration is blocked by isolation. The residual gap, relevant to TA-2, is covert-channel exfiltration through permitted protocol fields: the HL7 proxy enforces message-type structure and the DICOM proxy enforces SOP class, but neither performs deep semantic payload inspection. A patient adversary could in principle encode data within otherwise-legitimate observation values or image data. Content-aware proxying substantially raises the cost of exfiltration but does not eliminate this class of channel. This is named openly as a known limitation.

### Impact / Encryption (TA0040) — CONTAINED + RAPID RECOVERY
The attacker can encrypt the compromised guest's filesystem; that device goes offline. Blast radius is one VM (isolation prevented spread), recovery is a snapshot rollback measured in minutes, and the host, the audit chain, and every other device remain untouched. The catastrophic hospital-wide encryption event — the one that diverts ambulances and delays care — cannot be reached from a single contained guest.

---

## 6. Control Mapping Summary

| ATT&CK Tactic | CareFortress Control | Verdict |
|---|---|---|
| Initial Access / Execution | None (by design) | Out of scope |
| Persistence | Snapshot rollback, TPM PCR attestation | Contained |
| Privilege Escalation | AppArmor QEMU confinement (enforce) | Critical boundary — validated |
| Defense Evasion | Out-of-guest SHA-256 chained append-only audit | Prevented — validated |
| Discovery | Network isolation, deny-all | Prevented |
| Lateral Movement | Isolated bridges, content-proxy-only egress | Prevented — validated |
| Collection / Exfiltration | HL7/DICOM content proxies | Partially mitigated |
| Impact / Encryption | VM containment + snapshot recovery | Contained |

---

## 7. Residual Risk Register

| ID | Risk | Disposition |
|---|---|---|
| TR-1 | The CareFortress host is the single point of total failure | Host hardening is the highest-priority control; production deployment on dedicated hardware |
| TR-2 | QEMU/virtio escape 0-day would defeat the model | AppArmor confinement raises the bar; not absolute. Keep hypervisor patched |
| TR-3 | Covert-channel exfiltration via permitted HL7/DICOM fields | Accepted residual; deep payload inspection is future work |
| TR-4 | Management API is a path to the host | Pentested and hardened; minimize exposure, key-only access |
| TR-5 | Recovery depends on snapshot integrity | Guest cannot reach snapshot store across hypervisor boundary; snapshots should additionally be immutable/replicated in production |
| TR-6 | Detection depends on a human or pipeline acting on the audit chain | Tamper-evident logging requires an active monitoring process to have defensive value |
| TR-7 | No in-guest EDR | Deliberate trade — device-level prevention is impossible on certified software; the architecture provides fleet-level containment instead |
| TR-8 | Host storage exhaustion pauses guest VMs (ENOSPC) | Observed during validation: a full host disk caused QEMU to pause a guest to prevent corruption — a patient-safety availability condition. Audit-log growth is itself a self-DoS vector. Remediation: hard cap on audit-log disk usage plus storage-pressure alerting well before ENOSPC |
| TR-9 | Audit collector daemon runs unconfined | RESOLVED: profiles converted to named-only (path attachment removed), loaded into kernel, AppArmorProfile= directive added to systemd unit. Collector process confirmed confined under carefortress-log-collector (enforce mode). Child processes transition to unconfined via ix rule -- full child confinement is future work requiring Px discrete profile transitions. Ubuntu 26.04: uutils-coreutils (Rust) ships via cargo at higher priority than GNU coreutils -- profiles allow both path sets for cross-distro compatibility. |

---

## 8. Validation Results

The three highest-value claims were tested empirically on 2026-06-18, from the compromised-guest vantage (medical-vm, 10.10.1.0/24) and from the hypervisor host. The validation was deliberately adversarial and is reported with its findings intact.

### Test 1 — Lateral Movement (TA0008) — PASS
Vantage: a fully-compromised device VM attempting to reach its siblings and the host.

| Target | Result |
|---|---|
| mgmt-vm (10.10.2.0/24) | `Network is unreachable` — no route |
| audit-vm (10.10.3.0/24) | `Network is unreachable` — no route |
| host SSH (gateway:22) | blocked |
| host management API (gateway:8443) | blocked |

The guest's routing table contains only its own /24; it has no route to sibling subnets at all. Lateral movement fails at the routing layer on the guest itself — before the host's cross-bridge forwarding denial is even reached. Two independent layers, either sufficient alone. One compromised device cannot reach another.

### Test 2 — Defense Evasion (TA0005) — PASS
From inside the guest, the only outbound channel is a virtio-serial write node (the log feed); a full filesystem search returned no host audit log — the chain is not present anywhere the guest can reach.

On the host, the chain file carries the append-only attribute. A clobber by the file owner returned "Operation not permitted"; a truncate returned "Permission denied." Chain validation reported **2,791 entries valid, 0 errors, integrity verified.**

This held even though (a) the audit collector was running unconfined (TR-9) and (b) the chain had just survived a host storage-exhaustion event that paused a guest (TR-8). The append-only guarantee is enforced by the kernel at the VFS layer and is independent of both. An attacker who fully owns a guest cannot reach, alter, or truncate the record of their activity.

### Test 3 — Privilege Escalation Boundary (TA0004) — PASS, with finding
All running QEMU processes were confined under per-VM AppArmor profiles (`libvirt-<uuid>`) in enforce mode, each with a separate network-helper subprofile; the host reported 114 profiles in enforce mode. A process escaping a guest is contained within that guest's profile rather than executing freely as host root — the decisive boundary for this tactic is intact and enforced.

The verification also surfaced that the CareFortress security daemons, including the audit collector, are not themselves confined — their intended profiles never loaded. Recorded as TR-9. This is exactly the kind of gap an adversarial validation pass exists to catch, and it was found before public release.

---

## 9. Conclusion

Against TA-1 (ransomware), CareFortress denies the lateral movement that creates fleet-wide outbreaks, denies the log destruction that hides them, and reduces a successful encryption event to a single recoverable device. Against TA-2 (APT), it denies discovery and direct exfiltration and makes stealth extremely difficult through an audit record the adversary cannot reach — while honestly conceding a covert-channel residual in permitted protocol fields.

The three highest-value claims were validated empirically, and the validation itself surfaced two findings (TR-8, TR-9) now tracked for remediation. The architecture is a containment, detection, and recovery layer for the unpatchable device fleet. It does not prevent device compromise and does not protect the broader hospital IT network. Within its scope, it removes the specific conditions that make ransomware against medical devices catastrophic.
