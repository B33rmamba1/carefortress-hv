# CareFortress Host Hardening Profile

**Date:** June 18, 2026
**Author:** James Smith
**Target:** CareFortress KVM Hypervisor Host (Ubuntu 26.04 LTS)
**Baseline kernel:** 7.0.0-22-generic
**CIS benchmark:** CIS Ubuntu Linux 24.04 LTS Benchmark v1.0 (Level 2 Server)
**Framework:** NIST SP 800-123 (Guide to General Server Security)

---

## 1. Architecture Classification

CareFortress runs as a **KVM-based Type 1.5 hypervisor** on a hardened Ubuntu 26.04 LTS host. KVM requires a Linux host kernel and therefore does not qualify as a pure Type 1 hypervisor (no underlying OS). The correct classification is a hosted Type 1 or hybrid hypervisor -- the same category as VMware ESXi (which contains a minimal POSIX layer) and Proxmox VE.

**Security implication:** The Ubuntu host OS is the trust boundary for the entire system. A compromised host OS defeats all guest isolation, AppArmor confinement, and audit chain integrity. Host hardening is therefore the highest-priority security control in the CareFortress architecture, corresponding to TR-1 in docs/APT_THREAT_MODEL.md.

**Production vs lab distinction:** The development lab runs CareFortress as a VM inside Proxmox. In production, CareFortress runs directly on bare-metal hardware with no Proxmox layer. This document applies to the production bare-metal deployment. Lab-specific services (qemu-guest-agent reporting to Proxmox) are noted where they differ.

---

## 2. Verified Baseline State (June 18, 2026)

| Parameter | Value | CIS Requirement | Status |
|---|---|---|---|
| OS | Ubuntu 26.04 LTS (Resolute) | Ubuntu LTS | PASS |
| Kernel | 7.0.0-22-generic | Current LTS kernel | PASS |
| ASLR | kernel.randomize_va_space = 2 | 2 (full) | PASS |
| dmesg restrict | kernel.dmesg_restrict = 1 | 1 | PASS |
| kptr restrict | kernel.kptr_restrict = 1 | 2 | PARTIAL |
| TCP syncookies | net.ipv4.tcp_syncookies = 1 | 1 | PASS |
| ICMP redirects accept | net.ipv4.conf.all.accept_redirects = 0 | 0 | PASS |
| ICMP redirects send | net.ipv4.conf.all.send_redirects = 1 | 0 | FAIL |
| Reverse path filter | net.ipv4.conf.all.rp_filter = 2 | 1 (strict) | FAIL |
| IPv6 router advertisements | net.ipv6.conf.all.accept_ra = 1 | 0 | FAIL |
| SSH password auth | disabled | disabled | PASS |
| SSH root login | disabled | disabled | PASS |
| UFW default | deny incoming, deny routed | deny | PASS |
| AppArmor | 114 profiles enforcing | enforcing | PASS |
| Open ports | 22, 8443 | minimal | PASS |

---

## 3. Default-Deny Application Control

The ThreatLocker model applied to Linux: every executable must be explicitly permitted. Anything not on the allowlist is denied at execution time. CareFortress implements this through a layered approach combining AppArmor application whitelisting, systemd service allowlisting, and a locked package baseline.

### 3.1 Permitted Process Allowlist

The following processes are explicitly permitted on the CareFortress host. All others should generate an AppArmor DENIED log entry.

**CareFortress services (must run):**
- `/usr/bin/python3` -- carefortress-collector, carefortress-api (scoped per-service via named AppArmor profiles)
- `/usr/bin/uvicorn` -- FastAPI ASGI server

**System services (required for operation):**
- `/usr/sbin/sshd` -- remote management
- `/usr/sbin/chronyd` -- NTP time synchronization
- `/usr/sbin/libvirtd` -- KVM/QEMU orchestration
- `/usr/bin/qemu-system-x86_64` -- guest VM processes (per-VM AppArmor profile)
- `/usr/sbin/dnsmasq` -- libvirt DHCP/DNS for guest networks
- `/usr/sbin/rsyslogd` -- system logging
- `/usr/lib/systemd/systemd` -- init system
- `/usr/sbin/cron` -- scheduled tasks

**Administrative (interactive only, not as services):**
- `/usr/bin/bash`, `/usr/bin/sh` -- shell access via SSH
- `/usr/bin/sudo` -- privilege escalation (b33rmamba only)
- `/usr/bin/git` -- repository management
- `/usr/bin/virsh` -- VM management CLI

**Explicitly prohibited on production host:**
- No compilers (`gcc`, `cc`, `g++`)
- No package managers running as services
- No interpreters outside of the CareFortress Python environment
- No Rust/cargo toolchain (development dependency only)
- No NTFS or FUSE filesystem tools

### 3.2 Systemd Service Allowlist

The following services are permitted to run on the production CareFortress host. All others must be disabled and masked.

| Service | Purpose | Production Required |
|---|---|---|
| carefortress-api.service | Management API | YES |
| carefortress-collector.service | Audit log collection | YES |
| carefortress-iptables.service | Network rule persistence | YES |
| chrony.service | NTP | YES |
| ssh.service | Remote management | YES |
| libvirtd.service | KVM orchestration | YES |
| virtlockd.service | VM disk locking | YES |
| virtlogd.service | VM console logging | YES |
| systemd-journald.service | System logging | YES |
| systemd-networkd.service | Network management | YES |
| systemd-resolved.service | DNS resolution | YES |
| systemd-udevd.service | Device management | YES |
| rsyslog.service | System logging | YES |
| cron.service | Scheduled tasks | YES |
| dbus.service | IPC bus | YES |
| polkit.service | Authorization | YES |
| unattended-upgrades.service | Security patches | YES |
| qemu-guest-agent.service | Proxmox reporting | LAB ONLY -- disable in production |
| ModemManager.service | Modem management | NO -- disable and mask |
| multipathd.service | SAN multipath | NO -- disable and mask |
| udisks2.service | Disk management | NO -- disable and mask |
| upower.service | Power management | NO -- disable and mask |

### 3.3 Disable and Mask Unnecessary Services

```bash
# Disable and mask services with no production purpose
sudo systemctl disable --now ModemManager multipathd udisks2 upower
sudo systemctl mask ModemManager multipathd udisks2 upower
echo "Unnecessary services disabled"

# Verify
systemctl is-active ModemManager multipathd udisks2 upower
```

---

## 4. Kernel Hardening

Apply all CIS Level 2 sysctl settings permanently:

```bash
sudo tee /etc/sysctl.d/99-carefortress-hardening.conf << 'SYSCTL'
# CareFortress Host Kernel Hardening
# CIS Ubuntu 26.04 LTS Level 2 -- June 18, 2026

# Memory protection
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1

# Filesystem hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# IPv4 network hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# IPv6 hardening -- disable RA and redirects
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Core dump hardening
kernel.core_uses_pid = 1
SYSCTL

sudo sysctl --system
echo "Kernel hardening applied"
```

---

## 5. SUID Binary Reduction

Remove SUID from binaries not required for CareFortress operation:

```bash
# Audit current SUID binaries
find / -perm -4000 -type f 2>/dev/null | grep -v "snap\|proc" | sort

# Remove SUID from binaries not needed on a headless hypervisor
sudo chmod u-s /usr/bin/fusermount3     # FUSE -- not needed
sudo chmod u-s /usr/bin/ntfs-3g        # NTFS -- not needed
sudo chmod u-s /usr/lib/cargo/bin/su   # Cargo dev tool -- not needed in production
sudo chmod u-s /usr/lib/cargo/bin/sudo # Cargo dev tool -- not needed in production

# Verify remaining SUID set is minimal
echo "Remaining SUID binaries:"
find / -perm -4000 -type f 2>/dev/null | grep -v "snap\|proc" | sort
```

**Permitted SUID binaries on production host:**

| Binary | Purpose | Justification |
|---|---|---|
| /usr/bin/su | User switching | Required for libvirt operations |
| /usr/bin/sudo | Privilege escalation | Required for administration |
| /usr/bin/sudo.ws | Privilege escalation | Ubuntu 26.04 sudo variant |
| /usr/bin/passwd | Password management | Required for user management |
| /usr/bin/chfn | User info change | Standard system binary |
| /usr/bin/chsh | Shell change | Standard system binary |
| /usr/bin/gpasswd | Group management | Required for group operations |
| /usr/bin/mount | Filesystem mount | Required for libvirt disk operations |
| /usr/bin/umount | Filesystem unmount | Required for libvirt disk operations |
| /usr/bin/newgrp | Group login | Standard system binary |
| /usr/lib/openssh/ssh-keysign | SSH host-based auth | Required for SSH |
| /usr/lib/dbus-1.0/dbus-daemon-launch-helper | D-Bus | Required for libvirt/polkit |

---

## 6. Network Exposure Hardening

### 6.1 Scope API to management interface only

Port 8443 currently listens on 0.0.0.0 (all interfaces). In production, bind it to the management interface only:

```bash
# In /etc/systemd/system/carefortress-api.service
# Change the uvicorn bind from 0.0.0.0 to the management interface IP
# ExecStart=... --host 0.0.0.0 --> --host <management-interface-ip>
```

### 6.2 Disable libvirt default network

The libvirt default network (192.168.122.0/24 on virbr0) is not used by CareFortress and adds unnecessary attack surface:

```bash
sudo virsh net-destroy default
sudo virsh net-autostart default --disable
echo "libvirt default network disabled"
```

### 6.3 SSH hardening (additional CIS items)

```bash
sudo tee -a /etc/ssh/sshd_config.d/99-carefortress-hardening.conf << 'SSHCONF'
# CareFortress SSH Hardening -- CIS Level 2
Protocol 2
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers b33rmamba
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
Banner /etc/ssh/banner.txt
LogLevel VERBOSE
SSHCONF

echo "Unauthorized access prohibited. All activity logged." | sudo tee /etc/ssh/banner.txt
sudo systemctl restart ssh
```

---

## 7. File Integrity Baseline

A file integrity baseline captures the SHA-256 hash of every critical system binary and config file. Any subsequent change is detectable. This is the application of the same tamper-evident principle used in the audit chain, applied to the host OS itself.

```bash
# Generate file integrity baseline
sudo find /usr/bin /usr/sbin /usr/lib/systemd /etc/ssh \
    /etc/apparmor.d /etc/systemd/system \
    /home/b33rmamba/carefortress-hv/dashboard \
    /home/b33rmamba/carefortress-hv/scripts \
    -type f 2>/dev/null | sort | \
    sudo xargs sha256sum 2>/dev/null > /etc/carefortress-file-baseline.sha256

sudo chmod 600 /etc/carefortress-file-baseline.sha256
echo "Baseline entries: $(wc -l < /etc/carefortress-file-baseline.sha256)"
```

**Verification script** -- run on every boot or scheduled hourly:

```bash
sudo sha256sum --check /etc/carefortress-file-baseline.sha256 2>&1 | \
    grep -v "OK$" | \
    while read line; do
        echo "FILE INTEGRITY VIOLATION: $line" | \
        logger -t carefortress-integrity -p auth.crit
    done
```

---

## 8. Package Baseline

The production CareFortress host should run the minimum package set required for operation. The current development host has 1,061 packages installed; the production target is under 400.

**Required package categories:**

| Category | Key Packages |
|---|---|
| Kernel and boot | linux-image-generic, grub-efi-amd64, shim-signed |
| Base system | ubuntu-minimal, systemd, udev, dbus |
| KVM/QEMU | qemu-system-x86, libvirt-daemon-system, libvirt-clients |
| Networking | iproute2, iptables, ufw, dnsmasq-base |
| Security | apparmor, apparmor-utils, apparmor-profiles |
| Time | chrony |
| SSH | openssh-server |
| Python runtime | python3, python3-pip (for CareFortress services) |
| Logging | rsyslog |
| TPM | tpm2-tools, tpm2-abrmd |
| Monitoring | at (for scheduled integrity checks) |

**Packages to remove from production host:**

```bash
# Development tools not needed in production
sudo apt-get remove --purge -y \
    gcc g++ make cmake \
    cargo rustc \
    ntfs-3g \
    fuse3 \
    modemmanager \
    multipath-tools \
    udisks2 \
    upower \
    python3-pip  # install to venv only -- remove system pip after CareFortress deps installed

sudo apt-get autoremove --purge -y
sudo apt-get clean
```

---

## 9. Audit Trail for Host OS Events

The CareFortress audit chain captures guest VM events. Host OS security events should also be captured and forwarded. Install and configure auditd for host-level audit logging:

```bash
sudo apt-get install -y auditd audispd-plugins

# Critical audit rules for a hypervisor host
sudo tee /etc/audit/rules.d/99-carefortress.rules << 'AUDITRULES'
# CareFortress Host Audit Rules

# Authentication events
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation

# SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k ssh_config

# CareFortress service files
-w /home/b33rmamba/carefortress-hv/dashboard/api.py -p wa -k carefortress_api
-w /etc/systemd/system/carefortress-api.service -p wa -k carefortress_services
-w /etc/systemd/system/carefortress-collector.service -p wa -k carefortress_services

# AppArmor profile changes
-w /etc/apparmor.d/ -p wa -k apparmor

# Network configuration changes
-w /etc/ufw/ -p wa -k firewall
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modification

# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

# Module loading (potential rootkit vector)
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_load
-w /sbin/modprobe -p x -k module_load
-a always,exit -F arch=b64 -S init_module -S delete_module -k module_load
AUDITRULES

sudo systemctl enable --now auditd
echo "Host audit rules applied"
```

---

## 10. CIS Benchmark Compliance Summary

| CIS Control | Requirement | Status | Notes |
|---|---|---|---|
| 1.1 Filesystem config | nodev/nosuid on removable media | PASS | No removable media on hypervisor |
| 1.5 Bootloader | GRUB password | TODO | Set before production deployment |
| 1.6 Additional process hardening | ASLR, ptrace scope | PASS | Enforced via sysctl |
| 2.1 inetd services | None running | PASS | No inetd/xinetd |
| 2.2 Special purpose services | Minimal services | PARTIAL | ModemManager/udisks2 to remove |
| 3.1 Network parameters (host) | Redirects, source routing | PARTIAL | send_redirects fix required |
| 3.2 Network parameters (router) | Not acting as router | PASS | IP forwarding disabled except libvirt bridges |
| 3.3 IPv6 | RA disabled | FAIL | accept_ra fix required |
| 4.1 Auditd | Installed and running | TODO | Install auditd |
| 4.2 Rsyslog | Active | PASS | rsyslog running |
| 5.1 Cron | Access control | TODO | Restrict crontab access |
| 5.2 SSH | Hardening applied | PARTIAL | Additional config needed |
| 5.3 PAM | Password quality | TODO | Configure pam_pwquality |
| 5.4 User accounts | Root login disabled | PASS | PermitRootLogin no |
| 6.1 System file permissions | SUID audit | PARTIAL | Cargo/ntfs-3g SUID to remove |
| 6.2 User home directories | Permissions | TODO | Verify home directory permissions |

---

## 11. Outstanding Items Before Production Deployment

| Priority | Item | Section |
|---|---|---|
| CRITICAL | Apply kernel sysctl hardening (send_redirects, rp_filter, accept_ra, kptr_restrict) | Section 4 |
| CRITICAL | Disable and mask unnecessary services (ModemManager, multipathd, udisks2, upower) | Section 3.3 |
| CRITICAL | Remove SUID from cargo/ntfs-3g binaries | Section 5 |
| CRITICAL | Set GRUB bootloader password | Section 10 |
| CRITICAL | Install and configure auditd with host audit rules | Section 9 |
| HIGH | Scope API port 8443 to management interface only | Section 6.1 |
| HIGH | Disable libvirt default network (virbr0/192.168.122.0/24) | Section 6.2 |
| HIGH | Apply additional SSH hardening config | Section 6.3 |
| HIGH | Generate file integrity baseline | Section 7 |
| HIGH | Remove development packages (gcc, cargo, ntfs-3g) from production image | Section 8 |
| MEDIUM | Configure pam_pwquality for password policy | Section 10 |
| MEDIUM | Restrict crontab access | Section 10 |
| MEDIUM | Close TR-9: convert AppArmor profiles to named, attach via systemd | APT_THREAT_MODEL.md |
| LOW | Expand LV to 100GB+ | Infrastructure |

---

## 12. Known Issues and Lessons Learned

### SUID Removal -- Ubuntu 26.04 Alternatives System (Critical Warning)

On Ubuntu 26.04, `/usr/bin/sudo` is a symlink managed by the `update-alternatives` system. The alternatives chain resolves as follows:
/usr/bin/sudo -> /etc/alternatives/sudo -> /usr/lib/cargo/bin/sudo

The Rust cargo toolchain registers its own sudo binary in the alternatives system at higher priority than `/usr/bin/sudo.ws`. Removing SUID from `/usr/lib/cargo/bin/sudo` breaks sudo system-wide because the symlink resolves to cargo's binary, not the system sudo.

**Safe SUID removal procedure for Ubuntu 26.04:**

```bash
# Step 1: Check what sudo actually resolves to BEFORE removing SUID
readlink -f /usr/bin/sudo

# Step 2: Switch alternatives to the real system sudo first
sudo update-alternatives --set sudo /usr/bin/sudo.ws

# Step 3: Only then remove SUID from cargo sudo
sudo chmod u-s /usr/lib/cargo/bin/sudo

# Step 4: Verify sudo still works
sudo echo "sudo working"
```

**Recovery procedure if sudo is broken:**
From Proxmox host, use `qm guest exec <vmid>` (requires qemu-guest-agent running):
```bash
qm guest exec 102 -- chmod u+s /usr/bin/sudo.ws
qm guest exec 102 -- update-alternatives --set sudo /usr/bin/sudo.ws
```

This was discovered during the initial hardening pass on June 18, 2026 and recovered via qm guest exec without requiring console access or reboot.
