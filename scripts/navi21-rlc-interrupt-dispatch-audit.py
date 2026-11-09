#!/usr/bin/env python3
"""Offline byte-checked expansion of RLC interrupt dispatcher entries."""
import hashlib
import json
import lzma
import re
import struct
import subprocess
from pathlib import Path

root = Path('evidence/navi21-unlock/disassembly-v1')
blob = lzma.open('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz', 'rb').read()
sha = hashlib.sha256(blob).hexdigest()
assert sha == '19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
iram, dram = blob[0xb360:0x1b360], blob[0x1b560:0x1f560]
lines = (root/'rlc-iram-functions/09830.txt').read_text().splitlines()
counts = {}
paths = []
for start, end in ((0x9874, 0x9950), (0x9950, 0x9a7f)):
    selected = []
    for line in lines:
        m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+', line)
        if not m or not start <= int(m[1], 16) < end:
            continue
        pc, raw = int(m[1], 16), bytes.fromhex(m[2])
        assert iram[pc:pc+len(raw)] == raw, hex(pc)
        selected.append(line)
    path = root/f'rlc-iram-functions/{start:05x}.txt'
    path.write_text('; Separate interrupt entry; bytes checked against pinned IRAM.\n' + '\n'.join(selected) + '\n')
    paths.append(str(path))
    counts[hex(start)] = len(selected)
subprocess.run(['python3', 'scripts/navi21-smu-cfg-scan.py', *paths,
                '--output', str(root/'rlc-interrupt-entry-cfg.json')], check=True)
scan = json.loads((root/'rlc-iram-store-scan.json').read_text())
registrations = []
for report in scan['reports']:
    for call in report['calls']:
        if call.get('target') != '0x9830':
            continue
        k = call['integer_constants']
        index = int(k['a10'], 16)
        target = int(k['a11'], 16) or 0x5fffa360
        assert 0 <= index < 8
        registrations.append(dict(pc=call['pc'], index=index,
                                  slot=hex(0x5ffed818-8*index), target=hex(target)))
assert len(registrations) == 7
initial = []
for bit in range(8):
    # NSAU(1<<bit)=31-bit, so dispatch and registration select the same cell.
    slot = 0x5ffed720+8*(31-bit)
    target, arg = struct.unpack_from('<II', dram, slot-0x5ffec000)
    assert (target, arg) == (0x5fffa360, bit)
    initial.append(dict(interrupt_bit=bit, slot=hex(slot), target=hex(target), argument=arg))
result = dict(firmware_sha256=sha, byte_checked_instructions=counts,
              initial_low_eight_interrupt_slots=initial, known_direct_registrations=registrations,
              second_dispatcher_mask='0x84: bits2/7, slots5ffed808/5ffed7e0',
              scope='Initial DRAM and known direct registrations; first dispatcher hardware interrupt range is not independently established.',
              limitations=['Register-window rotation and exception return are not modeled by the local CFG scanner; inspect its unknown_operations.',
                           'Runtime computed writes, external engine updates, and non-listed registration callers remain open.',
                           'No added registered target6944/74c4; this is not global indirect-call closure.'])
(root/'rlc-interrupt-dispatch-audit.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
