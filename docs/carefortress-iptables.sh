#!/bin/bash
# CareFortress Host Firewall Rules

for BRIDGE in virbr1 virbr2 virbr3; do
    # Block guest VMs from SSHing to hypervisor host
    iptables -I INPUT -i $BRIDGE -p tcp --dport 22 -j DROP
    # Block guest VMs from reaching external DNS
    iptables -I INPUT -i $BRIDGE -p tcp --dport 53 -j DROP
    iptables -I INPUT -i $BRIDGE -p udp --dport 53 -j DROP
    # Allow NTP queries from guest VMs to VM 102 (chrony serves on 0.0.0.0:123)
    iptables -I INPUT -i $BRIDGE -p udp --dport 123 -j ACCEPT
    # Block guest VMs from forwarding NTP to external servers
    iptables -I FORWARD -i $BRIDGE -p udp --dport 123 -j DROP
done
