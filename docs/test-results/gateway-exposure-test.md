# Gateway IP Exposure Test
**Date:** 2026-06-16
**Tester:** James Smith
**Scope:** Services reachable on VM 102 (10.10.1.1) from guest VM networks

## Initial Findings
nmap -sV -T4 -p- 10.10.1.1 from VM 102 (representing mednet perspective):
- Port 22/tcp OPEN -- OpenSSH 10.2p1
- Port 53/tcp OPEN -- dnsmasq 2.92
- 65533 ports filtered

## Risk Assessment
- SSH (22): compromised medical-vm could attempt SSH brute force or exploit against hypervisor host
- DNS (53): potential DNS tunneling exfiltration vector via dnsmasq

## Remediation Applied
- UFW rules added blocking ports 22 and 53 inbound on virbr1/2/3
- iptables INPUT chain rules added (UFW rules insufficient -- traffic hits libvirt chains first)
- carefortress-iptables.service created for persistence on boot

## Verification
nc -zv 10.10.1.1 22 from medical-vm: TIMEOUT (blocked)
nc -zv 10.10.1.1 53 from medical-vm: TIMEOUT (blocked)
