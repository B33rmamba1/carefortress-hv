#!/bin/bash
# CareFortress - block guest VM access to host services
for BRIDGE in virbr1 virbr2 virbr3; do
    iptables -I INPUT -i $BRIDGE -p tcp --dport 22 -j DROP
    iptables -I INPUT -i $BRIDGE -p tcp --dport 53 -j DROP
    iptables -I INPUT -i $BRIDGE -p udp --dport 53 -j DROP
done
