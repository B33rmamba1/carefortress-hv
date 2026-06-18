# CareFortress

**Open source KVM/QEMU hypervisor security platform for certified legacy medical devices.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Phase](https://img.shields.io/badge/Phase-3%20In%20Progress-orange)]()
[![Commits](https://img.shields.io/badge/Commits-GPG%20Signed-green)]()

---

## The Problem

Millions of certified medical devices -- infusion pumps, patient monitors, imaging systems -- run Windows XP, Windows CE, QNX, or VxWorks. FDA certification makes software updates prohibitively expensive. Replacement cycles span 10-15 years.

These devices connect directly to hospital EHR systems via HL7 and DICOM. A compromised device on an isolated VLAN can still weaponize the permitted HL7 port (2575) to attack an EPIC integration engine. VLAN segmentation cannot distinguish a legitimate SpO2 reading from a weaponized exploit payload.

The 2023 FDA cybersecurity guidance mandates that manufacturers address this gap. No accessible solution exists for the legacy fleet already in the field.

## The Solution

CareFortress wraps certified legacy device software in a modern security layer -- without requiring FDA re-certification of the underlying software.

The certified OS runs unchanged inside a KVM/QEMU virtual machine. Security controls enforce at the hypervisor level, below the operating system, where a compromised application cannot reach them.cat > README.md << 'EOF'
# CareFortress

**Open source KVM/QEMU hypervisor security platform for certified legacy medical devices.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Phase](https://img.shields.io/badge/Phase-3%20In%20Progress-orange)]()
[![Commits](https://img.shields.io/badge/Commits-GPG%20Signed-green)]()

---

## The Problem

Millions of certified medical devices -- infusion pumps, patient monitors, imaging systems -- run Windows XP, Windows CE, QNX, or VxWorks. FDA certification makes software updates prohibitively expensive. Replacement cycles span 10-15 years.

These devices connect directly to hospital EHR systems via HL7 and DICOM. A compromised device on an isolated VLAN can still weaponize the permitted HL7 port (2575) to attack an EPIC integration engine. VLAN segmentation cannot distinguish a legitimate SpO2 reading from a weaponized exploit payload.

The 2023 FDA cybersecurity guidance mandates that manufacturers address this gap. No accessible solution exists for the legacy fleet already in the field.

## The Solution

CareFortress wraps certified legacy device software in a modern security layer -- without requiring FDA re-certification of the underlying software.

The certified OS runs unchanged inside a KVM/QEMU virtual machine. Security controls enforce at the hypervisor level, below the operating system, where a compromised application cannot reach them.
Medical Device VM                    CareFortress Host (VM 102)

┌─────────────────────┐             ┌──────────────────────────────┐

│  Certified OS       │             │  AppArmor QEMU profiles       │

│  (XP / CE / QNX)   │──virtio─────│  SHA-256 chained audit log    │

│  App software       │  serial     │  TPM PCR attestation          │

│  unchanged          │             │  Inter-VM policy engine        │

└─────────────────────┘             │  HL7 / DICOM content proxy    │

└──────────────────────────────┘

## Security Controls

| Control | Implementation | Test Result |
|---|---|---|
| VM Network Isolation | UFW + libvirt chain enforcement, 3 isolated networks | Network unreachable -- all directions confirmed |
| AppArmor Mandatory Access Control | Custom QEMU profiles per VM, scoped disk access | DENIED on cross-VM disk access, logged to dmesg |
| Tamper-Evident Audit Logging | virtio-serial channels, SHA-256 chaining, chattr +a | HASH MISMATCH detected on tampered entry, 36,000+ entries validated |
| TPM Measured Boot | tpm2-tools 5.7, SHA-256 PCR baseline, 18 PCRs | 18/18 PCRs match baseline, ATTESTATION PASSED |
| Inter-VM Policy Engine | JSON whitelist, iptables rule injection, deny-all default | Rule enable/disable cycle clean, deny-all enforced |
| HL7 Content Proxy | MLLP framing, per-device message type whitelist | ORU^R01 forwarded, ADT^A01 rejected, malformed payload rejected |
| DICOM Content Proxy | AE Title whitelist, SOP Class enforcement, C-STORE only | AE Title and SOP Class validation enforced |
| Chain Break Detection | validate_chain() on startup, isolate_broken_log() on break | CHAIN BREAK detected after tamper, broken log isolated |
| Append-Only Enforcement | chattr +a at kernel VFS level | PermissionError on modify attempt even as root |
| NTP Hardening | chrony with NTS upstream, authenticated time source | Authenticated: Yes (Cloudflare NTS) |

Every test result is committed to `docs/test-results/`.

## Agent Support

CareFortress uses a manifest-driven module system. Each deployment activates only the modules required for that device type and OS.

| Agent | Target OS | Status |
|---|---|---|
| Linux agent | Ubuntu, Debian, Alpine | Available |
| Windows agent | Windows XP SP3, XP Embedded, CE | Built (PE32+ x86-64) |
| QNX agent | QNX Neutrino 6.x | Available |
| VxWorks agent | VxWorks 6.x (kernel + RTP) | Available |

All agents write identical SHA-256 chained JSON to the virtio-serial channel. The host collector does not care which OS generated the entry.

## Protocol Proxies

| Proxy | Protocol | Key Controls |
|---|---|---|
| HL7 proxy | HL7 v2 over MLLP | Per-device message type whitelist, metadata-only audit logging, PHI redacted by default |
| DICOM proxy | DICOM C-STORE | AE Title whitelist, SOP Class enforcement (CT/MR/DX/US/SC/XA/NM/PET), no C-FIND/C-MOVE/C-GET |

The device VM never has a direct network path to the EPIC integration engine or PACS server.

## Architecture
                HOME / FACILITY NETWORK
                     │
                VM 102 (Hypervisor Host)
                ┌────────────────────────────────────────┐
                │  carefortress-collector.service         │
                │  carefortress-iptables.service          │
                │  carefortress-api.service (8443/HTTPS)  │
                │  chrony NTS (serves guest networks)     │
                │                                         │
      ┌─────────┤  virbr1 (mednet)   10.10.1.0/24        │
      │         │  virbr2 (mgmtnet)  10.10.2.0/24        │
      │         │  virbr3 (auditnet) 10.10.3.0/24        │
      │         └────────────────────────────────────────┘
      │
┌─────┴──────┐    ┌────────────┐    ┌────────────┐
│ medical-vm │    │  mgmt-vm   │    │  audit-vm  │
│ 10.10.1.x  │    │ 10.10.2.x  │    │ 10.10.3.x  │
│ Device OS  │    │ Management │    │ Audit copy │
└────────────┘    └────────────┘    └────────────┘
     │                  │                  │
     └──────────────────┴──────────────────┘
                virtio-serial channels
            (no network path -- hypervisor level)

## Management API

CareFortress includes a FastAPI REST management interface (HTTPS, JWT auth, rate limiting).

```bash
# Health check
curl -sk https://hypervisor-host:8443/health

# Authenticate
TOKEN=$(curl -sk -X POST https://hypervisor-host:8443/auth/token \
    -d "username=admin&password=yourpassword" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# List VM status
curl -sk https://hypervisor-host:8443/vms \
    -H "Authorization: Bearer $TOKEN"

# Run TPM attestation
curl -sk https://hypervisor-host:8443/attestation \
    -H "Authorization: Bearer $TOKEN"
```

## Quick Start

> **Note:** CareFortress is a Phase 3 project. Full deployment documentation and an installer are planned for Phase 3.9. The following is a summary of the architecture -- see `docs/` for detailed setup notes.

**Requirements:**
- Proxmox VE 9.x or bare metal Ubuntu 24.04+ with KVM/QEMU
- Python 3.10+
- tpm2-tools 5.x
- libvirt 9.x

**Deploy a manifest:**
```bash
python3 modules/loader.py modules/manifests/example-linux-infusion-pump.json
```

**Run chain validator:**
```bash
python3 scripts/validate-chain.py
```

**Run TPM attestation:**
```bash
python3 scripts/attest-pcr.py
```

**Start HL7 proxy:**
```bash
python3 modules/proxies/hl7_proxy.py \
    --listen 10.10.1.1:2575 \
    --upstream EPIC-HOST:2575 \
    --device-type infusion_pump
```

## Repository Structure
scripts/          Host-side security scripts (collector, validator, attestation, policy)

modules/

agents/         Per-OS log agents (Linux, Windows, QNX, VxWorks)

proxies/        Protocol proxies (HL7, DICOM)

manifests/      Deployment manifest schema and examples

loader.py       Manifest-driven module loader

dashboard/        FastAPI REST management API

policy/           Inter-VM network policy definitions

docs/

test-results/   Test evidence for every security control

tpm/            PCR baseline files

diagrams/       Network topology diagrams

apparmor-*.txt  AppArmor profiles for host scripts

## Project Status

| Phase | Status |
|---|---|
| Phase 0 -- Security Baseline | Complete |
| Phase 1 -- KVM Foundation | Complete |
| Phase 2 -- Security Layer | Complete |
| Phase 3.0 -- Network Hardening | Complete |
| Phase 3.1 -- NTP Hardening | Complete |
| Phase 3.2 -- Log Rotation + AppArmor | Complete |
| Phase 3.3 -- Modular Agent Architecture | Complete |
| Phase 3.4 -- Protocol Proxies | Complete |
| Phase 3.5 -- FastAPI Dashboard | Complete |
| Phase 3.6 -- ARM Validation | Planned |
| Phase 3.7 -- Compliance Package | Planned |
| Phase 3.8 -- Business / Legal | Planned |
| Phase 3.9 -- Demo Package + Public Launch | Planned |

## Author

James Smith -- Security Engineer  
[linkedin.com/in/smithjamesd89](https://linkedin.com/in/smithjamesd89)  
GPG: `0F882789E2917D31199070ED192C47200722413B`

All commits are GPG signed. The work is verifiable.

## License

MIT License -- see [LICENSE](LICENSE) for details.

CareFortress is open source because security tooling that nobody can inspect is security theater.
