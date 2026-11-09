#!/usr/bin/env python3
"""Extract offline callback registrations from local CFG argument constants."""
import hashlib
import json
import lzma
from pathlib import Path
import struct

root = Path('/workspace/gfx1030-unlock-research/evidence/navi21-unlock/disassembly-v1')
blob = lzma.decompress(Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes())
assert hashlib.sha256(blob).hexdigest() == '0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
code = blob[0x200:]
scan = json.loads((root / 'all-entry-store-scan.json').read_text())
registrations = []
new_roots = []
source = 'All-entry local CFG registration arguments, registered-roots-v1'
for function in scan['reports']:
    for call in function['calls']:
        helper = call['target']
        if helper not in ('0x38a94', '0x3274c', '0x35448', '0x2648', '0x22a0'):
            continue
        values = call['integer_constants']
        index = values.get('a10')
        pointer = values.get('a11')
        targets = []
        if helper in ('0x2648', '0x22a0'):
            if index:
                targets = [(None, int(index, 16))]
        elif index is not None and pointer is not None:
            i, p = int(index, 16), int(pointer, 16)
            if helper == '0x35448':
                targets = [(p + off, struct.unpack_from('<I', code, p + off)[0])
                           for off in (0, 4, 8, 12)]
            else:
                targets = [((0x9c00 if helper == '0x38a94' else 0x9cc4) + i * 4, p)]
        row = dict(caller=function['listing'], call_pc=call['pc'], helper=helper,
                   argument0=index, argument1=pointer, targets=[])
        for slot, target in targets:
            if not target:
                continue
            entry = target + 1 < len(code) and code[target] == 0x36 and code[target + 1] & 15 == 1
            row['targets'].append(dict(slot=hex(slot) if slot is not None else None,
                                       target=hex(target), entry_candidate=entry))
            new_roots.append(dict(source=source, context=call['pc'],
                                  slot=hex(slot) if slot is not None else helper,
                                  target=hex(target), entry_candidate=entry))
        registrations.append(row)
(root / 'registered-roots-audit.json').write_text(json.dumps(dict(
    scope='Known local constants only; no global runtime immutability claim.',
    registrations=registrations), indent=2) + '\n')
path = root / 'additional-callback-roots.json'
roots = [r for r in json.loads(path.read_text()) if r['source'] != source]
path.write_text(json.dumps(roots + new_roots, indent=2) + '\n')
print(len(registrations), 'registrations;', len({r['target'] for r in new_roots}), 'unique callback targets')
