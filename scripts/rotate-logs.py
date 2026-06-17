#!/usr/bin/env python3
"""
CareFortress Log Rotation with Chain Continuity
Rotates audit-chain.log when it exceeds MAX_SIZE_MB.
Each new log file starts with a genesis entry referencing
the last hash of the previous file — preserving chain continuity
across rotation boundaries.
"""
import os
import json
import hashlib
import shutil
from datetime import datetime, timezone

LOG_FILE = os.path.expanduser('~/carefortress-hv/logs/audit-chain.log')
ARCHIVE_DIR = os.path.expanduser('~/carefortress-hv/logs/archive')
MAX_SIZE_MB = 50

def get_last_hash(log_file):
    last = None
    with open(log_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if not last:
        return '0' * 64
    try:
        return json.loads(last).get('chain_hash', '0' * 64)
    except Exception:
        return hashlib.sha256(last.encode()).hexdigest()

def rotate():
    if not os.path.exists(LOG_FILE):
        print('[rotate] No log file found.')
        return

    size_mb = os.path.getsize(LOG_FILE) / (1024 * 1024)
    if size_mb < MAX_SIZE_MB:
        print(f'[rotate] Log size {size_mb:.2f}MB below threshold {MAX_SIZE_MB}MB -- no rotation needed.')
        return

    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    archive_path = os.path.join(ARCHIVE_DIR, f'audit-chain-{ts}.log')

    last_hash = get_last_hash(LOG_FILE)

    # Remove chattr +a to allow move
    os.system(f'sudo chattr -a {LOG_FILE} 2>/dev/null')
    shutil.move(LOG_FILE, archive_path)
    # Set append-only on archived file -- immutable evidence
    os.system(f'sudo chattr +a {archive_path} 2>/dev/null')
    print(f'[rotate] Rotated {LOG_FILE} to {archive_path}')

    # Write genesis entry for new log referencing previous file
    prev_ref = os.path.basename(archive_path)
    entry = {
        'type': 'ROTATION_GENESIS',
        'collected_ts': datetime.now(timezone.utc).isoformat(),
        'source_vm': 'collector',
        'payload': {
            'msg': f'Log rotated. Previous file: {prev_ref}',
            'prev_file': prev_ref,
        },
        'prev_hash': last_hash,
    }
    entry_json = json.dumps(entry, sort_keys=True)
    new_hash = hashlib.sha256((last_hash + entry_json).encode()).hexdigest()
    entry['chain_hash'] = new_hash

    with open(LOG_FILE, 'w') as f:
        f.write(json.dumps(entry) + '\n')

    os.system(f'sudo chattr +a {LOG_FILE} 2>/dev/null')
    print(f'[rotate] New log started. Genesis references: {prev_ref}')
    print(f'[rotate] Prev hash: {last_hash[:16]}... New hash: {new_hash[:16]}...')

if __name__ == '__main__':
    rotate()
