#!/usr/bin/env python3
"""Offline signed-section boundary and packed-register locator; no GPU access."""
import hashlib
import json
import lzma
from pathlib import Path
import struct

root = Path('/workspace/gfx1030-unlock-research/evidence/navi21-unlock')
audit = json.loads((root / 'cc-access-v1/rlc-container-audit.json').read_text())
blob = lzma.decompress(Path(audit['source']).read_bytes())
assert hashlib.sha256(blob).hexdigest() == audit['sha256']
sections = [dict(name='main_ucode', offset=256, size=25088)] + audit['sections']
out = []
for section in sections:
    offset, size = section['offset'], section['size']
    if not size:
        continue
    raw = blob[offset:offset + size]
    assert len(raw) == size
    assert raw[16:20] == b'$PS1'
    length = struct.unpack_from('<I', raw, 20)[0]
    assert length + 512 == size
    body = raw[256:256 + length]
    out.append(dict(name=section['name'], section_offset=hex(offset),
                    section_size=size, header_marker='$PS1',
                    length_field=length, body_offset=hex(offset + 256),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                    body_prefix=body[:32].hex()))
    if section['name'] == 'save_restore_list_srm_size_bytes':
        srm = body
        srm_offset = offset + 256
assert len(srm) % 8 == 0
registers = {0x2249:'CC_GC_SA_UNIT_DISABLE', 0x226f:'CC_GC_SHADER_ARRAY_CONFIG',
             0x224a:'GC_USER_SA_UNIT_DISABLE', 0x2270:'GC_USER_SHADER_ARRAY_CONFIG'}
hits = []
for offset in range(0, len(srm), 8):
    first, second = struct.unpack_from('<II', srm, offset)
    address = first & 0xffff
    if address in registers:
        hits.append(dict(file_offset=hex(srm_offset + offset),
                         body_offset=hex(offset), packed_word=hex(first),
                         second_word=hex(second), low16=hex(address),
                         candidate_register=registers[address]))
result = dict(source=audit['source'], firmware_sha256=audit['sha256'],
              sections=out, srm_candidate_pair_count=len(srm)//8, hits=hits,
              interpretation='Structural boundary inferred from repeated headers and exact length arithmetic. Low16 register matches include USER positive controls. Packed field semantics and SRM consumer instruction effects remain unproved.',
              limitations=['No proof the second word is a value, permission or opcode.',
                           'No claim of CC write acceptance or identification of writer instruction.',
                           'Disk image only; not fresh loaded-image attestation.'])
(root / 'disassembly-v1/rlc-srm-packed-registers.json').write_text(json.dumps(result, indent=2)+'\n')
print(len(out), 'wrapped sections;', len(hits), 'CC/USER candidate records')
