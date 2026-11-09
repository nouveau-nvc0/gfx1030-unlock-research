#!/usr/bin/env python3
"""Reproduce offline SMU IRQ-mask evidence; no device access."""
import hashlib
import json
import lzma
import pathlib
import re
import struct

E = pathlib.Path('evidence/navi21-unlock/disassembly-v1')
firmware = pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz')
blob = lzma.decompress(firmware.read_bytes())
sha = hashlib.sha256(blob).hexdigest()
assert sha == '0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
code = blob[0x200:]
roots = ('00f10', '00f58', '01724', '01794', '017c0', '01a44', '01a8c', '0290c')
inputs = []
for root in roots:
    p = E / 'all-entry-candidates' / (root + '.txt')
    count = 0
    for line in p.read_text().splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s', line)
        if not m:
            continue
        pc = int(m[1], 16)
        raw = bytes.fromhex(m[2])
        assert code[pc:pc+len(raw)] == raw, (str(p), hex(pc))
        count += 1
    assert count
    inputs.append({'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'byte_checked_records': count})
scanpath = E / 'all-entry-store-scan-rsync.json'
scan = json.loads(scanpath.read_text())
hits = []
for report in scan['reports']:
    for s in report['stores']:
        addr = s.get('address')
        if addr and 0x786c <= int(addr, 16) < 0x787c:
            hits.append({'listing': report['listing'], **s})
initial = list(struct.unpack_from('<4I', code, 0x786c))
assert initial == [0xffffffff] * 4
receipt = {
    'firmware_sha256': sha, 'code_file_offset': '0x200',
    'scope': 'Byte consistency and initial file values; semantic interpretation is in companion text. Local store locator is not all-write coverage.',
    'listing_inputs': inputs,
    'locator_sha256': hashlib.sha256(scanpath.read_bytes()).hexdigest(),
    'initial_first_mask': [hex(x) for x in struct.unpack_from('<4I', code, 0x785c)],
    'initial_second_mask': [hex(x) for x in initial],
    'second_mask_fixed_store_hits': hits,
    'channel_bits': [{'channel': ch, 'irq': irq, 'word': irq//32, 'bit': irq%32,
                      'second_mask_address': hex(0x786c+4*(irq//32)),
                      'initial_bit': (initial[irq//32] >> (irq%32)) & 1}
                     for ch, irq in ((7,88),(8,89))],
    'runtime_mask_observed': False,
    'complete_write_coverage': False,
}
(E / 'smu-irq-mask-audit.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps({'listings':len(inputs),'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'fixed_store_hits':len(hits),'initial_channel_bits':[x['initial_bit'] for x in receipt['channel_bits']]}))
