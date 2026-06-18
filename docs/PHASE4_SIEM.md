# CareFortress Phase 4 — SIEM Integration

**Status:** Planned
**Target:** Q3–Q4 2026
**Effort:** ~40–60 hours
**Closes:** TR-6 (detection depends on human acting on audit chain)

---

## Objective

Extend the CareFortress audit chain from a tamper-evident forensic record into an active detection feed. Phase 4 ships a pluggable SIEM profile system that forwards validated audit chain entries to the operator's existing SIEM platform in real time, while keeping the local chain as the integrity anchor.

This resolves two problems simultaneously:

1. **TR-6** — the audit chain currently requires a human or pipeline to poll it. With a SIEM profile active, every entry is forwarded on write, enabling real-time alerting and correlation.
2. **Host disk growth** — with a SIEM receiving entries on write, local retention drops to a configurable rolling buffer (default 48 hours). The host disk usage for logs becomes bounded and essentially fixed regardless of fleet size or runtime duration.

---

## Design

### Profile model

A SIEM profile is a thin adapter between the CareFortress audit chain schema and a target platform's ingestion interface. The core collector does not change. Profiles are loaded at runtime from `config/siem_profiles/`. Zero profiles configured = current local-only behavior (fully backward compatible).

Each profile is a YAML file defining:

| Field | Description |
|---|---|
| `name` | Profile identifier |
| `transport` | Ingestion method: `https_webhook`, `syslog_tcp`, `syslog_udp`, `kafka` |
| `endpoint` | Target URL or host:port |
| `auth` | Authentication type and credentials (resolved from environment variables) |
| `format` | Output format: `json`, `cef`, `leef`, `ecs` |
| `chain_field` | Field name in target schema where the SHA-256 chain hash is mapped |
| `batch_size` | Number of entries per forwarding batch (default: 50) |
| `retry_on_failure` | Whether to buffer and retry on transport failure |
| `local_buffer_hours` | Local retention in hours when profile is active (default: 48) |

### Integrity model

The chain is verified on the host before forwarding. An entry that fails chain validation is never forwarded — it is held, flagged, and a `CHAIN_BREAK` event is written to both the local log and the SIEM if the transport is reachable. The SIEM receives only entries that have passed host-side chain verification. The chain hash travels with each forwarded entry so the SIEM can independently re-verify if required.

### Architecture
Guest VMs

│ virtio-serial

▼

log-collector.py  ──validates chain──►  audit-chain.log (local, 48h rolling)

│

│ on write (per entry or batched)

▼

siem-forwarder.py  ──loads profile──►  SIEM platform

│

└── profile: splunk_hec.yaml / elastic.yaml / wazuh.yaml / sentinel.yaml / qradar.yaml

`siem-forwarder.py` runs as a second systemd service (`carefortress-siem.service`), reads from the local chain, and forwards via the configured profile. It maintains a cursor (last forwarded entry hash) so it resumes correctly after restart without duplicating or skipping entries.

---

## Supported Platforms

### Splunk (HEC)
- **Transport:** HTTPS webhook
- **Format:** Splunk JSON (`event` wrapper)
- **Auth:** HEC token (`Authorization: Splunk <token>`)
- **Chain field:** `carefortress_chain_hash` in event metadata
- **Coverage:** Most common SIEM in large US health systems

### Elastic / ELK
- **Transport:** Elasticsearch Ingest API or Logstash HTTPS input
- **Format:** Elastic Common Schema (ECS)
- **Auth:** API key (`Authorization: ApiKey <key>`)
- **Chain field:** `event.hash` (ECS field)
- **Coverage:** Common in academic medical centers and research hospitals

### Wazuh
- **Transport:** Syslog TCP or Wazuh Active Response API
- **Format:** JSON (Wazuh agent format)
- **Auth:** Agent registration key
- **Chain field:** `data.carefortress_chain_hash`
- **Coverage:** Best fit for resource-constrained environments and open-source deployments; recommended default for CareFortress reference deployments

### Microsoft Sentinel
- **Transport:** Log Analytics Workspace REST API (DCR/DCE)
- **Format:** JSON (custom table schema)
- **Auth:** Azure AD managed identity or client credentials
- **Chain field:** `CarefortressChainHash_s` (custom column)
- **Coverage:** Growing fast in hospital systems already on Azure / Microsoft 365

### IBM QRadar
- **Transport:** Syslog TCP
- **Format:** LEEF 2.0
- **Auth:** Device support module (DSM) registration
- **Chain field:** `LEEF` custom attribute `chainHash`
- **Coverage:** Common in larger enterprise health systems

---

## Example Profile Files

### `config/siem_profiles/splunk_hec.yaml`
```yaml
name: splunk-hec
transport: https_webhook
endpoint: "${SPLUNK_HEC_URL}/services/collector/event"
auth:
  type: token
  header: "Authorization"
  value: "Splunk ${SPLUNK_HEC_TOKEN}"
format: splunk_json
chain_field: carefortress_chain_hash
batch_size: 50
retry_on_failure: true
local_buffer_hours: 48
```

### `config/siem_profiles/elastic.yaml`
```yaml
name: elastic-ecs
transport: https_webhook
endpoint: "${ELASTIC_ENDPOINT}/_bulk"
auth:
  type: api_key
  header: "Authorization"
  value: "ApiKey ${ELASTIC_API_KEY}"
format: ecs
chain_field: event.hash
batch_size: 100
retry_on_failure: true
local_buffer_hours: 48
```

### `config/siem_profiles/wazuh.yaml`
```yaml
name: wazuh-syslog
transport: syslog_tcp
endpoint: "${WAZUH_MANAGER_IP}:514"
auth:
  type: none
format: json
chain_field: data.carefortress_chain_hash
batch_size: 1
retry_on_failure: true
local_buffer_hours: 48
```

---

## Disk Impact

With any SIEM profile active and `local_buffer_hours: 48`, the local audit log is capped at approximately 48 hours of entries. At three guest VMs heartbeating every 30 seconds plus API and security events, this is roughly 15,000–20,000 entries, or approximately 15–20MB. The host disk usage for logs becomes fixed rather than growing indefinitely.

Without a SIEM profile (local-only mode), existing log rotation behavior applies.

---

## Deliverables

| Item | Description |
|---|---|
| `modules/siem/siem_forwarder.py` | Core forwarder service — cursor management, batching, retry |
| `modules/siem/formats/` | Format adapters: `splunk_json.py`, `ecs.py`, `leef.py`, `cef.py` |
| `modules/siem/transports/` | Transport adapters: `https_webhook.py`, `syslog_tcp.py`, `syslog_udp.py` |
| `config/siem_profiles/` | Example profile YAML files for all 5 platforms |
| `scripts/siem-test.sh` | Connectivity test script — sends one test event per configured profile |
| `/etc/systemd/system/carefortress-siem.service` | Systemd unit for the forwarder service |
| `docs/SIEM_DEPLOYMENT.md` | Operator deployment guide per platform |

---

## Security Considerations

- All credentials resolved from environment variables, never in profile YAML files
- Profile YAML files committed to repo contain only structure, no secrets
- Forwarder service runs under a separate systemd service account with minimum required permissions
- Chain verification happens before forwarding — SIEM receives only verified entries
- If the SIEM transport fails, entries are buffered locally (within `local_buffer_hours`) and retried — no silent data loss
- AppArmor profile for `siem-forwarder.py` scoped to: read audit chain, write cursor file, outbound network to configured SIEM endpoint only

---

## Closes

| Finding | Resolution |
|---|---|
| TR-6 (APT_THREAT_MODEL.md) | Active forwarding to SIEM enables real-time detection, not just forensic logging |
| TR-8 partial (APT_THREAT_MODEL.md) | `local_buffer_hours` caps local retention; disk usage becomes bounded |
