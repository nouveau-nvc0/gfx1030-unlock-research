#!/usr/bin/env python3
"""Check listed RLC direct-call targets against separately available roots."""
import hashlib
import json
import lzma
import re
from pathlib import Path

root = Path('evidence/navi21-unlock/disassembly-v1')
directory = root/'rlc-iram-functions'
roots = {int(p.stem, 16) for p in directory.glob('*.txt')}
scans = ['rlc-iram-store-scan.json', 'rlc-startup-cfg.json',
         'rlc-interrupt-entry-cfg.json', 'rlc-context-restore-cfg.json',
         'rlc-context-save-cfg.json', 'rlc-window-spill-cfg.json',
         'rlc-alternate-save-cfg.json']
calls = {}
for name in scans:
    data = json.loads((root/name).read_text())
    for report in data['reports']:
        for call in report['calls']:
            if call['operation'] not in ('call0', 'call4', 'call8', 'call12'):
                continue
            calls[call['pc']] = call
missing = [c for c in calls.values() if c.get('target') is None or int(c['target'],16) not in roots]
raw_only = []
for path in directory.glob('*.txt'):
    for line in path.read_text().splitlines():
        m = re.match(r'\s*([0-9a-f]+):.*\bcall(?:0|4|8|12)\b.*target=(0x[0-9a-f]+)', line)
        if m and int(m[2],16) not in roots:
            raw_only.append(dict(listing=str(path), pc=hex(int(m[1],16)), target=m[2],
                                 in_reached_call_inventory=hex(int(m[1],16)) in calls))
blob = lzma.open('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz','rb').read()
assert hashlib.sha256(blob).hexdigest() == '19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
needle = (0x5fff9ad0).to_bytes(4,'little')
hits = [hex(i) for i in range(len(blob)-3) if blob[i:i+4] == needle]
path = directory/'09ad0.txt'
checked = 0
for line in path.read_text().splitlines():
    m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+', line)
    if m:
        pc, raw = int(m[1],16), bytes.fromhex(m[2])
        assert blob[0xb360+pc:0xb360+pc+len(raw)] == raw
        checked += 1
result = dict(scan_hashes={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in scans},
              direct_call_sites=len(calls), missing_separate_target_roots=missing,
              raw_listing_targets_without_roots=raw_only,
              alternate_save_byte_checks=checked, alternate_save_literal_offsets=hits,
              scope='Coverage of direct calls in listed local CFG scans only. Root availability does not prove complete callee traversal, semantics, non-ENTRY/vector coverage or indirect-call closure.')
(root/'rlc-direct-root-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
