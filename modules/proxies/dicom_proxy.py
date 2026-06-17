#!/usr/bin/env python3
"""
CareFortress DICOM Proxy
AE Title and SOP Class enforcing proxy for medical imaging devices.

Listens on mednet (10.10.1.1:104) for DICOM connections from the device VM.
Enforces AE Title whitelist -- only known device AE Titles accepted.
Enforces SOP Class whitelist -- only permitted SOP Classes forwarded.
Allows C-STORE only from device VM -- no C-FIND, C-MOVE, C-GET.
Logs metadata to the audit chain (no PHI by default).
Forwards clean studies to the PACS server upstream.

Architecture:
  imaging-vm -> CareFortress DICOM proxy (10.10.1.1:104) -> PACS (upstream)

The imaging device VM never has a direct network path to PACS.

Usage:
  python3 dicom_proxy.py --listen 10.10.1.1:104 --upstream 192.168.10.60:104 \
      --proxy-ae CFPROXY --pacs-ae PACS01 \
      --allowed-ae IMAGER01 --allowed-ae IMAGER02
"""

import json
import hashlib
import logging
import argparse
import os
import threading
from datetime import datetime, timezone

from pynetdicom import AE, evt, StoragePresentationContexts
from pynetdicom.sop_class import (
    CTImageStorage,
    MRImageStorage,
    DigitalXRayImageStorageForPresentation,
    UltrasoundImageStorage,
    SecondaryCaptureImageStorage,
    XRayAngiographicImageStorage,
    NuclearMedicineImageStorage,
    PositronEmissionTomographyImageStorage,
)

# ── Permitted SOP Classes (imaging only -- no structured reports or orders) ──
PERMITTED_SOP_CLASSES = [
    CTImageStorage,
    MRImageStorage,
    DigitalXRayImageStorageForPresentation,
    UltrasoundImageStorage,
    SecondaryCaptureImageStorage,
    XRayAngiographicImageStorage,
    NuclearMedicineImageStorage,
    PositronEmissionTomographyImageStorage,
]

# ── Audit chain state ─────────────────────────────────────────────────
_chain_lock = threading.Lock()
_prev_hash = '0' * 64
_entry_count = 0

LOG_FILE = os.path.expanduser('~/carefortress-hv/logs/audit-chain.log')

def _write_audit(event_type, fields):
    """Write metadata-only entry to audit chain. No PHI."""
    global _prev_hash, _entry_count
    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        'ts': ts,
        'source': 'dicom-proxy',
        'type': event_type,
    }
    payload.update(fields)
    payload_json = json.dumps(payload, sort_keys=True)
    with _chain_lock:
        hash_input = _prev_hash + payload_json
        new_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        entry = {
            'collected_ts': ts,
            'source_vm': 'dicom-proxy',
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
            logging.error(f'[dicom-proxy] audit write failed: {e}')

def build_proxy(proxy_ae_title, pacs_ae_title, pacs_addr, allowed_aes, log_phi):
    """Build and return the pynetdicom AE configured as a C-STORE SCP/SCU proxy."""

    ae = AE(ae_title=proxy_ae_title)

    # Accept all permitted SOP classes from device
    for sop in PERMITTED_SOP_CLASSES:
        ae.add_supported_context(sop)

    def handle_store(event):
        """Called for each incoming C-STORE from the device."""
        requestor_ae = event.assoc.requestor.ae_title.strip()
        ds = event.dataset
        ds.file_meta = event.file_meta

        # AE Title whitelist check
        if requestor_ae not in allowed_aes:
            logging.warning(f'[dicom-proxy] REJECT -- unknown AE Title: {requestor_ae}')
            _write_audit('REJECT', {
                'reason': 'AE Title not in whitelist',
                'ae_title': requestor_ae,
            })
            return 0xA700  # refused -- out of resources (reject code)

        # SOP Class check
        sop_class = getattr(ds, 'SOPClassUID', 'unknown')
        sop_instance = getattr(ds, 'SOPInstanceUID', 'unknown')
        modality = getattr(ds, 'Modality', 'unknown')
        study_uid = getattr(ds, 'StudyInstanceUID', 'unknown')

        permitted_uids = [str(s) for s in PERMITTED_SOP_CLASSES]
        if str(sop_class) not in permitted_uids:
            logging.warning(f'[dicom-proxy] REJECT -- SOP Class not permitted: {sop_class}')
            _write_audit('REJECT', {
                'reason': 'SOP Class not permitted',
                'ae_title': requestor_ae,
                'sop_class': str(sop_class),
                'modality': modality,
            })
            return 0xA900  # error -- data set does not match SOP class

        # Forward to PACS via C-STORE SCU
        pacs_host, pacs_port = pacs_addr
        forward_ae = AE()
        forward_ae.add_requested_context(sop_class)

        assoc = forward_ae.associate(pacs_host, pacs_port, ae_title=pacs_ae_title)
        if not assoc.is_established:
            logging.error(f'[dicom-proxy] PACS association failed for {pacs_host}:{pacs_port}')
            _write_audit('FORWARD_ERROR', {
                'reason': 'PACS association failed',
                'ae_title': requestor_ae,
                'sop_class': str(sop_class),
            })
            return 0xA700

        status = assoc.send_c_store(ds)
        assoc.release()

        if status and status.Status == 0x0000:
            _write_audit('FORWARD', {
                'ae_title': requestor_ae,
                'sop_class': str(sop_class),
                'modality': modality,
                'study_uid': study_uid if log_phi else 'redacted',
                'sop_instance': sop_instance if log_phi else 'redacted',
            })
            logging.info(f'[dicom-proxy] FORWARD {modality} from {requestor_ae} to PACS')
            return 0x0000  # success
        else:
            _write_audit('FORWARD_ERROR', {
                'reason': 'PACS C-STORE failed',
                'ae_title': requestor_ae,
                'status': str(status.Status) if status else 'no status',
            })
            logging.error(f'[dicom-proxy] PACS C-STORE failed for {requestor_ae}')
            return 0xA700

    def handle_assoc_open(event):
        requestor_ae = event.assoc.requestor.ae_title.strip()
        requestor_addr = event.assoc.requestor.address
        logging.info(f'[dicom-proxy] association from {requestor_ae} ({requestor_addr})')
        _write_audit('CONNECT', {
            'ae_title': requestor_ae,
            'address': requestor_addr,
        })

    def handle_assoc_close(event):
        requestor_ae = event.assoc.requestor.ae_title.strip()
        _write_audit('DISCONNECT', {'ae_title': requestor_ae})

    handlers = [
        (evt.EVT_C_STORE, handle_store),
        (evt.EVT_CONN_OPEN, handle_assoc_open),
        (evt.EVT_CONN_CLOSE, handle_assoc_close),
    ]

    return ae, handlers


def main():
    parser = argparse.ArgumentParser(description='CareFortress DICOM Proxy')
    parser.add_argument('--listen',      default='10.10.1.1:104',
                        help='Listen address (default: 10.10.1.1:104)')
    parser.add_argument('--upstream',    required=True,
                        help='PACS server address (host:port)')
    parser.add_argument('--proxy-ae',    default='CFPROXY',
                        help='AE Title for this proxy (default: CFPROXY)')
    parser.add_argument('--pacs-ae',     default='PACS01',
                        help='AE Title of upstream PACS (default: PACS01)')
    parser.add_argument('--allowed-ae',  action='append', dest='allowed_aes',
                        default=[], help='Permitted device AE Title (repeatable)')
    parser.add_argument('--log-phi',     action='store_true', default=False,
                        help='Include PHI fields in audit log (default: off)')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    listen_host, listen_port = args.listen.rsplit(':', 1)
    listen_port = int(listen_port)

    pacs_host, pacs_port = args.upstream.rsplit(':', 1)
    pacs_addr = (pacs_host, int(pacs_port))

    allowed_aes = args.allowed_aes if args.allowed_aes else []

    logging.info('[dicom-proxy] CareFortress DICOM Proxy starting')
    logging.info(f'[dicom-proxy] Listen:      {listen_host}:{listen_port}')
    logging.info(f'[dicom-proxy] Upstream:    {pacs_host}:{pacs_port}')
    logging.info(f'[dicom-proxy] Proxy AE:    {args.proxy_ae}')
    logging.info(f'[dicom-proxy] PACS AE:     {args.pacs_ae}')
    logging.info(f'[dicom-proxy] Allowed AEs: {allowed_aes if allowed_aes else "ALL (warning: open)"}')
    logging.info(f'[dicom-proxy] SOP classes: {len(PERMITTED_SOP_CLASSES)} permitted')
    logging.info(f'[dicom-proxy] Log PHI:     {args.log_phi}')

    _write_audit('START', {
        'listen': args.listen,
        'upstream': args.upstream,
        'proxy_ae': args.proxy_ae,
        'pacs_ae': args.pacs_ae,
        'allowed_aes': allowed_aes,
    })

    ae, handlers = build_proxy(
        args.proxy_ae, args.pacs_ae, pacs_addr, allowed_aes, args.log_phi
    )

    ae.start_server(
        (listen_host, listen_port),
        block=True,
        evt_handlers=handlers
    )

if __name__ == '__main__':
    main()
