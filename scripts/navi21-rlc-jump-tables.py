#!/usr/bin/env python3
"""Extract four bounded RLC switch tables from pinned firmware; offline only."""
import hashlib
import json
import lzma
from pathlib import Path
import struct

root = Path('evidence/navi21-unlock/disassembly-v1')
blob = lzma.decompress(Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
digest = hashlib.sha256(blob).hexdigest()
assert digest == '19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
# Bounds and index biases recovered from unsigned BGEU preceding each JX.
specs = [
    ('02b44.txt', 0x2b6c, 0x40, 51, 10, 0x2b61),
    ('07d24.txt', 0x7d42, 0xc50, 21, 16, 0x7d3a),
    ('082c0.txt', 0x82f1, 0xcb0, 39, 0, 0x82e6),
    ('083fc.txt', 0x8436, 0xd50, 102, 0, 0x842b),
]
tables, edges = [], {}
for listing, pc, offset, count, bias, guard in specs:
    values = struct.unpack_from('<' + 'I'*count, blob, 0x1b560 + offset)
    assert all(0x5fff0000 <= value < 0x60000000 for value in values)
    targets = sorted({value-0x5fff0000 for value in values})
    edges[listing] = {hex(pc): [hex(target) for target in targets]}
    tables.append(dict(listing=listing, jump=hex(pc), unsigned_guard=hex(guard),
                       table=hex(0x5ffec000+offset), count=count, input_bias=bias,
                       entries=[dict(input=i+bias, target=hex(value-0x5fff0000))
                                for i,value in enumerate(values)],
                       unique_targets=len(targets)))
result = dict(firmware_sha256=digest,
              scope='Initial firmware DRAM tables under inferred virtual map; runtime mutation not excluded.',
              tables=tables, edges=edges)
(root/'rlc-jump-tables.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps([dict(listing=t['listing'], count=t['count'], unique=t['unique_targets']) for t in tables]))
