#!/usr/bin/env python3
"""Check that the public research export excludes identifying and unrelated records."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', 'work', 'inputs', 'downloads', '__pycache__'}
# Generic schema checks contain no recorded local names or identifier values.
OPERATIONAL = re.compile(r'"(?:containers|active_containers|service_state|host_cmdline)"\s*:|<domain\s+type=')
JOURNAL = re.compile(r'"(?:_MACHINE' + r'_ID|_BOOT' + r'_ID|_HOST' + r'NAME|__SEQNUM' + r'_ID|__CUR' + r'SOR)"\s*:')
DEVICE = re.compile(r'^(?:unique' + r'_id|gpu' + r'_id)\s+\d+', re.M)
SECRETS = re.compile(r'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')

def audit():
    errors = []; checked = 0
    for p in ROOT.rglob('*'):
        rel=p.relative_to(ROOT)
        if rel.parts[0] in SKIP or '__pycache__' in rel.parts or rel.parts[0].startswith('.venv') or not p.is_file():
            continue
        checked += 1
        name=str(rel)
        if ('vm'+'-plan-v1/') in name or p.name in {'sysfs-'+'unique_id.txt','sysfs-'+'serial_number.txt','sysfs-'+'product_number.txt'} or re.search(r'/kfd/node\d+-gpu' + r'_id\.txt$',name):
            errors.append({'path':name,'reason':'excluded observation record'})
        b=p.read_bytes()
        if b'\0' in b:
            errors.append({'path':name,'reason':'unexpected binary payload'}); continue
        s=b.decode(errors='replace')
        if OPERATIONAL.search(s): errors.append({'path':name,'reason':'unrelated operational record'})
        if SECRETS.search(s): errors.append({'path':name,'reason':'credential marker'})
        if p.suffix in {'.json','.jsonl'} and JOURNAL.search(s):
            errors.append({'path':name,'reason':'identifying journal metadata'})
        if '/kfd/' in name and DEVICE.search(s):
            errors.append({'path':name,'reason':'persistent device identifier'})
        if p.name=='rocminfo.txt' and re.search(r'^\s*Uuid\s*:',s,re.M|re.I):
            errors.append({'path':name,'reason':'runtime device UUID'})
    return {'files_checked':checked,'passed':not errors,'errors':errors}

if __name__=='__main__':
    result=audit(); print(json.dumps(result,indent=2)); raise SystemExit(not result['passed'])
