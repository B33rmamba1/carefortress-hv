#!/usr/bin/env python3
"""
CareFortress Inter-VM Policy Engine
Reads network-policy.json and:
  1. Applies iptables rules to LIBVIRT_FWI chain on host
  2. Injects/removes routes on guest VMs via SSH
Only enabled rules are applied. Default is deny-all.
"""

import json
import subprocess
import sys
import os
from datetime import datetime, timezone

POLICY_FILE = os.path.expanduser("~/carefortress-hv/policy/network-policy.json")
SSH_KEY     = os.path.expanduser("~/.ssh/id_ed25519")
CHAIN_IN    = "LIBVIRT_FWI"
RULE_PREFIX = "carefortress-policy"


def run(cmd, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[policy] ERROR: {' '.join(cmd)}\n  {result.stderr.strip()}")
        sys.exit(1)
    return result


def ssh_run(ip, user, cmd_str):
    result = subprocess.run(
        ["ssh", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
         "-o", "BatchMode=yes", f"{user}@{ip}", cmd_str],
        capture_output=True, text=True
    )
    return result


def flush_policy_rules(policy):
    """Remove all CareFortress iptables rules and routes on all VMs."""
    # Flush iptables
    result = run(["sudo", "iptables", "-L", CHAIN_IN, "--line-numbers", "-n"], check=False)
    to_delete = []
    for line in result.stdout.splitlines():
        if RULE_PREFIX in line:
            num = line.split()[0]
            if num.isdigit():
                to_delete.append(int(num))
    for num in sorted(to_delete, reverse=True):
        run(["sudo", "iptables", "-D", CHAIN_IN, str(num)], check=False)
        print(f"[policy] Removed iptables rule #{num} from {CHAIN_IN}")

    # Flush routes on all VMs
    vms = policy.get("vms", {})
    networks = policy["networks"]
    for vm_name, vm_info in vms.items():
        ip = vm_info["ip"]
        user = vm_info["ssh_user"]
        # Remove any routes to other VM subnets via our gateway
        for net_name, net_info in networks.items():
            if net_name == vm_info["network"]:
                continue
            subnet = net_info["subnet"]
            gateway = networks[vm_info["network"]]["gateway"]
            result = ssh_run(ip, user,
                f"sudo ip route del {subnet} via {gateway} 2>/dev/null; echo ok")
            if "ok" in result.stdout:
                print(f"[policy] Removed route {subnet} from {vm_name}")


def apply_rule(rule, policy):
    vms = policy["vms"]
    networks = policy["networks"]

    src_vm_name = rule["src_vm"]
    dst_vm_name = rule["dst_vm"]
    src_vm = vms[src_vm_name]
    dst_vm = vms[dst_vm_name]
    src_net = networks[src_vm["network"]]
    dst_net = networks[dst_vm["network"]]

    src_bridge = src_net["bridge"]
    dst_bridge = dst_net["bridge"]
    src_subnet = src_net["subnet"]
    dst_subnet = dst_net["subnet"]
    src_gateway = src_net["gateway"]
    dst_gateway = dst_net["gateway"]
    proto = rule["protocol"]
    rule_id = rule["id"]
    comment = f"{RULE_PREFIX}:{rule_id}"

    print(f"[policy] Applying {rule_id}: {rule['description']}")

    # 1. Add iptables forwarding rules on host
    if proto == "icmp":
        run(["sudo", "iptables", "-I", CHAIN_IN, "1",
             "-i", src_bridge, "-o", dst_bridge,
             "-s", src_subnet, "-d", dst_subnet,
             "-p", "icmp", "-m", "comment", "--comment", comment,
             "-j", "ACCEPT"])
        run(["sudo", "iptables", "-I", CHAIN_IN, "1",
             "-i", dst_bridge, "-o", src_bridge,
             "-s", dst_subnet, "-d", src_subnet,
             "-p", "icmp", "-m", "comment", "--comment", comment,
             "-j", "ACCEPT"])
    elif proto == "tcp":
        dst_port = str(rule.get("dst_port", ""))
        run(["sudo", "iptables", "-I", CHAIN_IN, "1",
             "-i", src_bridge, "-o", dst_bridge,
             "-s", src_subnet, "-d", dst_subnet,
             "-p", "tcp", "--dport", dst_port,
             "-m", "comment", "--comment", comment,
             "-j", "ACCEPT"])
        run(["sudo", "iptables", "-I", CHAIN_IN, "1",
             "-i", dst_bridge, "-o", src_bridge,
             "-s", dst_subnet, "-d", src_subnet,
             "-p", "tcp", "--sport", dst_port,
             "-m", "state", "--state", "ESTABLISHED,RELATED",
             "-m", "comment", "--comment", comment,
             "-j", "ACCEPT"])

    # 2. Inject routes on guest VMs via SSH
    # src VM needs route to dst subnet
    r = ssh_run(src_vm["ip"], src_vm["ssh_user"],
        f"sudo ip route replace {dst_subnet} via {src_gateway} && echo ok")
    if "ok" in r.stdout:
        print(f"[policy]   Route {dst_subnet} via {src_gateway} added on {src_vm_name}")
    else:
        print(f"[policy]   WARNING: Could not add route on {src_vm_name}: {r.stderr.strip()}")

    # NOTE: Return route deliberately NOT added on dst VM.
    # Host bridge handles return traffic at kernel level.
    # Adding route on dst_vm increases attack surface — violates least privilege.


def main():
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[policy] CareFortress Policy Engine — {ts}")

    with open(POLICY_FILE) as f:
        policy = json.load(f)

    networks = policy["networks"]
    rules = policy["rules"]
    enabled = [r for r in rules if r.get("enabled", False)]
    disabled = [r for r in rules if not r.get("enabled", False)]

    print(f"[policy] Rules: {len(enabled)} enabled, {len(disabled)} disabled")
    print(f"[policy] Default: {policy['default']}")
    print()

    print(f"[policy] Flushing existing rules and routes...")
    flush_policy_rules(policy)
    print()

    if not enabled:
        print(f"[policy] No enabled rules — all inter-VM traffic denied")
        print(f"[policy] ✅ Policy applied — deny-all enforced")
        return

    for rule in enabled:
        apply_rule(rule, policy)

    print()
    print(f"[policy] ✅ Policy applied — {len(enabled)} rule(s) active")


if __name__ == "__main__":
    main()
