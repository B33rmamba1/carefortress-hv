#!/usr/bin/env python3
"""
CareFortress HL7 Proxy
Content-aware HL7 v2 inspection proxy for medical device to EPIC integration.

Listens on mednet (10.10.1.1:2575) for HL7 messages from the device VM.
Validates every message against a per-device-type whitelist.
Logs metadata to the audit chain (no PHI in the log by default).
Forwards clean messages to the EPIC integration engine upstream.
Rejects and logs invalid messages -- never forwards.

This is the email gateway model applied to medical device HL7 traffic.
The device VM never has a direct network path to EPIC.

Architecture:
  medical-vm -> CareFortress HL7 proxy (10.10.1.1:2575) -> EPIC (upstream)

MLLP framing:
  HL7 v2 messages are wrapped in MLLP (Minimal Lower Layer Protocol):
  <VT> message <FS><CR>
  where VT = 0x0B, FS = 0x1C, CR = 0x0D

Usage:
  python3 hl7_proxy.py --listen 10.10.1.1:2575 --upstream 192.168.10.50:2575 \
      --device-type infusion_pump --log-phi false
"""

import socket
import threading
import json
import hashlib
import logging
import argparse
import os
import sys
import time
from datetime import datetime, timezone

# ── MLLP framing bytes ────────────────────────────────────────────────
MLLP_VT = b'\x0b'   # start of block
MLLP_FS = b'\x1c'   # end of block
MLLP_CR = b'\x0d'   # carriage return

# ── Per-device-type HL7 message type whitelists ───────────────────────
# Format: {device_type: [permitted_message_types]}
# Message type is the first two components of MSH-9 (e.g. ORU^R01)
DEVICE_WHITELISTS = {
    'infusion_pump': [
        'ORU^R01',   # observation result -- SpO2, flow rate, drug level
        'ACK',       # acknowledgement
    ],
    'patient_monitor': [
        'ORU^R01',   # observation result -- vitals, waveforms
        'ACK',
    ],
    'imaging_device': [
        'ORU^R01',   # imaging result
        'ORM^O01',   # order message (limited)
        'ACK',
    ],
    'diagnostic_device': [
        'ORU^R01',   # diagnostic result
        'ACK',
    ],
    'generic': [
        'ORU^R01',
        'ACK',
    ],
}

# ── Audit chain state ─────────────────────────────────────────────────
_chain_lock = threading.Lock()
_prev_hash = '0' * 64
_entry_count = 0

LOG_FILE = os.path.expanduser('~/carefortress-hv/logs/audit-chain.log')

def _write_audit(event_type, fields):
    """Write a metadata-only entry to the audit chain. No PHI."""
    global _prev_hash, _entry_count
    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        'ts': ts,
        'source': 'hl7-proxy',
        'type': event_type,
    }
    payload.update(fields)
    payload_json = json.dumps(payload, sort_keys=True)
    with _chain_lock:
        hash_input = _prev_hash + payload_json
        new_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        entry = {
            'collected_ts': ts,
            'source_vm': 'hl7-proxy',
            'payload': payload,
            'prev_hash': _prev_hash,
            'chain_hash': new_hash,
        }
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            _prev_hash = new_hash
            _entry_count += 1
        except Exception as e:
            logging.error(f'[hl7-proxy] audit write failed: {e}')

# ── MLLP send/receive ─────────────────────────────────────────────────
def mllp_recv(sock):
    """Read one MLLP-framed HL7 message from socket. Returns raw message bytes or None."""
    buf = b''
    sock.settimeout(30)
    try:
        # Wait for VT start byte
        while True:
            b = sock.recv(1)
            if not b:
                return None
            if b == MLLP_VT:
                break
        # Read until FS+CR
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
            if MLLP_FS + MLLP_CR in buf:
                # Strip the FS+CR trailer
                buf = buf[:buf.index(MLLP_FS + MLLP_CR)]
                return buf
    except socket.timeout:
        return None
    except Exception:
        return None

def mllp_send(sock, message_bytes):
    """Send one MLLP-framed HL7 message."""
    sock.sendall(MLLP_VT + message_bytes + MLLP_FS + MLLP_CR)

def mllp_ack(message_id, accept=True):
    """Build a minimal HL7 ACK response."""
    ts = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    code = 'AA' if accept else 'AR'
    ack = (
        f'MSH|^~\\&|CAREFORTRESS|PROXY|DEVICE|PROXY|{ts}||ACK|{ts}001|P|2.4\r'
        f'MSA|{code}|{message_id}|{"Message accepted" if accept else "Message rejected by CareFortress proxy"}\r'
    )
    return ack.encode('ascii')

# ── HL7 message validation ────────────────────────────────────────────
def validate_message(raw_bytes, device_type, log_phi=False):
    """
    Parse and validate an HL7 v2 message.
    Returns (valid, msg_type, msg_id, reason)
    """
    try:
        text = raw_bytes.decode('ascii', errors='replace')
        msg = hl7.parse(text)
    except Exception as e:
        return False, 'PARSE_ERROR', '', f'HL7 parse failed: {e}'

    try:
        # Extract MSH fields
        msh = msg.segment('MSH')
        msg_type_raw = str(msh[9])           # e.g. ORU^R01
        msg_id = str(msh[10])                # message control ID
        sending_app = str(msh[3])
        sending_fac = str(msh[4])
        version = str(msh[12])
    except Exception as e:
        return False, 'PARSE_ERROR', '', f'MSH field extraction failed: {e}'

    # Normalize message type -- strip subcomponents beyond first two
    parts = msg_type_raw.split('^')
    if len(parts) >= 2:
        msg_type = f'{parts[0]}^{parts[1]}'
    else:
        msg_type = parts[0]

    # Check against whitelist
    whitelist = DEVICE_WHITELISTS.get(device_type, DEVICE_WHITELISTS['generic'])
    if msg_type not in whitelist and msg_type.split('^')[0] not in [w.split('^')[0] for w in whitelist if w == 'ACK']:
        return False, msg_type, msg_id, f'Message type {msg_type} not in whitelist for {device_type}'

    # Validate version -- accept 2.x only
    if not version.startswith('2.'):
        return False, msg_type, msg_id, f'Unsupported HL7 version: {version}'

    return True, msg_type, msg_id, 'OK'

# ── Connection handler ────────────────────────────────────────────────
def handle_connection(client_sock, client_addr, upstream_addr, device_type, log_phi):
    """Handle one device connection. One thread per connection."""
    import hl7 as hl7_module
    client_ip = client_addr[0]
    logging.info(f'[hl7-proxy] connection from {client_ip}')
    _write_audit('CONNECT', {'client': client_ip, 'device_type': device_type})

    # Connect to upstream EPIC integration engine
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream_host, upstream_port = upstream_addr
    try:
        upstream_sock.connect((upstream_host, upstream_port))
        logging.info(f'[hl7-proxy] connected to upstream {upstream_host}:{upstream_port}')
    except Exception as e:
        logging.error(f'[hl7-proxy] upstream connect failed: {e}')
        _write_audit('UPSTREAM_FAIL', {'error': str(e)})
        client_sock.close()
        return

    try:
        while True:
            raw = mllp_recv(client_sock)
            if raw is None:
                break

            msg_size = len(raw)
            valid, msg_type, msg_id, reason = validate_message(raw, device_type, log_phi)

            if valid:
                # Forward to upstream
                try:
                    mllp_send(upstream_sock, raw)
                    # Read ACK from upstream and relay back to device
                    ack_raw = mllp_recv(upstream_sock)
                    if ack_raw:
                        mllp_send(client_sock, ack_raw)
                    _write_audit('FORWARD', {
                        'client': client_ip,
                        'msg_type': msg_type,
                        'msg_id': msg_id,
                        'size': msg_size,
                    })
                    logging.info(f'[hl7-proxy] FORWARD {msg_type} from {client_ip} ({msg_size}b)')
                except Exception as e:
                    logging.error(f'[hl7-proxy] forward error: {e}')
                    _write_audit('FORWARD_ERROR', {'error': str(e), 'msg_type': msg_type})
                    mllp_send(client_sock, mllp_ack(msg_id, accept=False))
            else:
                # Reject -- send AR ACK back to device, do NOT forward
                mllp_send(client_sock, mllp_ack(msg_id, accept=False))
                _write_audit('REJECT', {
                    'client': client_ip,
                    'msg_type': msg_type,
                    'msg_id': msg_id,
                    'reason': reason,
                    'size': msg_size,
                })
                logging.warning(f'[hl7-proxy] REJECT {msg_type} from {client_ip}: {reason}')

    except Exception as e:
        logging.error(f'[hl7-proxy] handler error: {e}')
    finally:
        client_sock.close()
        upstream_sock.close()
        _write_audit('DISCONNECT', {'client': client_ip})
        logging.info(f'[hl7-proxy] {client_ip} disconnected')

# ── Main ──────────────────────────────────────────────────────────────
def main():
    import hl7 as hl7_module

    parser = argparse.ArgumentParser(description='CareFortress HL7 Proxy')
    parser.add_argument('--listen',      default='10.10.1.1:2575',
                        help='Listen address (default: 10.10.1.1:2575)')
    parser.add_argument('--upstream',    required=True,
                        help='EPIC integration engine address (host:port)')
    parser.add_argument('--device-type', default='generic',
                        choices=list(DEVICE_WHITELISTS.keys()),
                        help='Device type for whitelist selection')
    parser.add_argument('--log-phi',     action='store_true', default=False,
                        help='Include PHI fields in audit log (default: off)')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    # Parse listen address
    listen_host, listen_port = args.listen.rsplit(':', 1)
    listen_port = int(listen_port)

    # Parse upstream address
    upstream_host, upstream_port = args.upstream.rsplit(':', 1)
    upstream_addr = (upstream_host, int(upstream_port))

    logging.info(f'[hl7-proxy] CareFortress HL7 Proxy starting')
    logging.info(f'[hl7-proxy] Listen:      {listen_host}:{listen_port}')
    logging.info(f'[hl7-proxy] Upstream:    {upstream_host}:{upstream_port}')
    logging.info(f'[hl7-proxy] Device type: {args.device_type}')
    logging.info(f'[hl7-proxy] Whitelist:   {DEVICE_WHITELISTS[args.device_type]}')
    logging.info(f'[hl7-proxy] Log PHI:     {args.log_phi}')

    _write_audit('START', {
        'listen': args.listen,
        'upstream': args.upstream,
        'device_type': args.device_type,
    })

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(5)
    logging.info(f'[hl7-proxy] Listening on {listen_host}:{listen_port}')

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, client_addr, upstream_addr, args.device_type, args.log_phi),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        logging.info('[hl7-proxy] Shutting down')
        _write_audit('STOP', {'reason': 'operator shutdown'})
    finally:
        server.close()

if __name__ == '__main__':
    main()
