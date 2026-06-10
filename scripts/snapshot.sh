#!/bin/bash
# EdgeMed Secure — VM Snapshot Management Script
# Usage: ./snapshot.sh [create|revert|list] [snapshot-name]

DOMAINS=("medical-vm" "mgmt-vm")
ACTION=${1:-list}
SNAP_NAME=${2:-"manual-$(date +%Y%m%d-%H%M%S)"}

case $ACTION in
  create)
    echo "[+] Creating snapshot '$SNAP_NAME' on all VMs..."
    for domain in "${DOMAINS[@]}"; do
      virsh snapshot-create-as --domain "$domain" \
        --name "$SNAP_NAME" \
        --description "Snapshot created $(date)" \
        --atomic
      echo "[+] $domain — snapshot '$SNAP_NAME' created"
    done
    echo "[+] Done. Verify with: ./snapshot.sh list"
    ;;
  revert)
    echo "[!] Reverting all VMs to snapshot '$SNAP_NAME'..."
    for domain in "${DOMAINS[@]}"; do
      virsh snapshot-revert "$domain" "$SNAP_NAME"
      echo "[+] $domain — reverted to '$SNAP_NAME' — state: $(virsh domstate $domain)"
    done
    echo "[+] Revert complete."
    ;;
  list)
    echo "[+] Current snapshots:"
    for domain in "${DOMAINS[@]}"; do
      echo "--- $domain ---"
      virsh snapshot-list "$domain"
    done
    ;;
  *)
    echo "Usage: $0 [create|revert|list] [snapshot-name]"
    exit 1
    ;;
esac
