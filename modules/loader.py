#!/usr/bin/env python3
"""
CareFortress Module Loader
Reads a deployment manifest and activates the correct modules
for the target device OS and configuration.
"""
import json
import os
import sys

MODULES_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(MODULES_DIR)

AGENT_MAP = {
    'linux':              'agents/linux/agent_linux.py',
    'windows':            'agents/windows/agent_windows.c',
    'qnx':                'agents/qnx/agent_qnx.c',
    'vxworks':            'agents/vxworks/agent_vxworks.c',
}

PROXY_MAP = {
    'hl7':    'proxies/hl7_proxy.py',
    'dicom':  'proxies/dicom_proxy.py',
}

def load_manifest(path):
    with open(path) as f:
        manifest = json.load(f)
    required = ['device_id', 'device_type', 'os', 'modules']
    for field in required:
        if field not in manifest:
            raise ValueError(f'Manifest missing required field: {field}')
    return manifest

def resolve_modules(manifest):
    """Returns list of modules to activate for this deployment."""
    mods = manifest['modules']
    active = {}

    # Agent
    agent_key = mods.get('agent')
    if agent_key not in AGENT_MAP:
        raise ValueError(f'Unknown agent: {agent_key}')
    active['agent'] = {
        'key': agent_key,
        'path': os.path.join(MODULES_DIR, AGENT_MAP[agent_key]),
    }

    # Protocol proxy
    proxy_key = mods.get('protocol_proxy', 'none')
    if proxy_key == 'hl7':
        active['proxy'] = {
            'key': 'hl7',
            'path': os.path.join(MODULES_DIR, PROXY_MAP['hl7']),
            'port': mods.get('hl7_port', 2575),
            'version': mods.get('hl7_version', '2.4'),
            'upstream': mods.get('epic_integration_engine'),
        }
    elif proxy_key == 'dicom':
        active['proxy'] = {
            'key': 'dicom',
            'path': os.path.join(MODULES_DIR, PROXY_MAP['dicom']),
            'port': mods.get('dicom_port', 104),
            'upstream': mods.get('pacs_server'),
        }
    elif proxy_key == 'both':
        active['hl7_proxy'] = {
            'key': 'hl7',
            'path': os.path.join(MODULES_DIR, PROXY_MAP['hl7']),
            'port': mods.get('hl7_port', 2575),
            'version': mods.get('hl7_version', '2.4'),
            'upstream': mods.get('epic_integration_engine'),
        }
        active['dicom_proxy'] = {
            'key': 'dicom',
            'path': os.path.join(MODULES_DIR, PROXY_MAP['dicom']),
            'port': mods.get('dicom_port', 104),
            'upstream': mods.get('pacs_server'),
        }

    return active

def print_deployment_plan(manifest, active_modules):
    print(f'[loader] CareFortress Deployment Plan')
    print(f'[loader] Device ID:   {manifest["device_id"]}')
    print(f'[loader] Device Type: {manifest["device_type"]}')
    print(f'[loader] Guest OS:    {manifest["os"]}')
    print(f'[loader] Active modules:')
    for key, mod in active_modules.items():
        exists = os.path.exists(mod['path'])
        status = 'available' if exists else 'NOT YET BUILT'
        print(f'[loader]   {key}: {mod["key"]} -- {status}')
        if 'upstream' in mod and mod['upstream']:
            print(f'[loader]     upstream: {mod["upstream"]}')
        if 'port' in mod:
            print(f'[loader]     port: {mod["port"]}')

def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <manifest.json>')
        sys.exit(1)
    manifest_path = sys.argv[1]
    manifest = load_manifest(manifest_path)
    active = resolve_modules(manifest)
    print_deployment_plan(manifest, active)
    return active

if __name__ == '__main__':
    main()
