# Phase 1 Snapshots
Created: 2026-06-10
Both VMs snapshotted at phase1-baseline while running.
Revert test: medical-vm reverted successfully — state: running.

medical-vm: phase1-baseline — 2026-06-10 02:13:50
mgmt-vm:    phase1-baseline — 2026-06-10 02:13:50

Revert command: virsh snapshot-revert <domain> phase1-baseline
