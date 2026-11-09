#!/usr/bin/env python3
"""Extract the offline SMU event descriptors; never accesses hardware."""
import hashlib
import json
import lzma
from pathlib import Path
import struct

root = Path('/workspace/gfx1030-unlock-research/evidence/navi21-unlock/disassembly-v1')
blob = lzma.decompress(Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes())
digest = hashlib.sha256(blob).hexdigest()
assert digest == '0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
code = blob[0x200:]
rows = []
for i in range(20):
    address = 0x7374 + 24 * i
    data = code[address:address + 24]
    target = struct.unpack_from('<I', data, 20)[0]
    assert code[target] == 0x36 and code[target + 1] & 15 == 1
    rows.append(dict(index=i, address=hex(address), raw=data.hex(),
                     block=struct.unpack_from('<H', data)[0], instance=data[2],
                     bit=data[3], kind=data[4], enabled=data[6],
                     next_index=struct.unpack_from('<h', data, 16)[0],
                     callback_slot=hex(address + 20), target=hex(target)))
result = dict(firmware_sha256=digest, code_file_offset='0x200',
              scope='Initial image only; RAM mutations and mapping not attested.',
              bounds_evidence='144c: a2=7278, fields+fc, stride24, count20; 335cc ends a2=7458.',
              lookup_evidence='1c50: index*24, returns7374+index*24; 19c4/1cc8 call descriptor+20.',
              records=rows)
(root / 'event-dispatch-table.json').write_text(json.dumps(result, indent=2) + '\n')
path = root / 'additional-callback-roots.json'
roots = json.loads(path.read_text())
source = '20 event descriptors, bounded initialization144c and lookup1c50'
roots = [r for r in roots if r['source'] != source]
roots.extend(dict(source=source, context=r['address'], slot=r['callback_slot'],
                  target=r['target'], entry_candidate=True) for r in rows)
path.write_text(json.dumps(roots, indent=2) + '\n')
print('Extracted 20 records;', len({r['target'] for r in rows}), 'unique callbacks')
