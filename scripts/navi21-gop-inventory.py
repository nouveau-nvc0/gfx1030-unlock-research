#!/usr/bin/env python3
"""Offline extraction and PE inventory of the two pinned reference-ROM GOPs."""
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, '/tmp/navi21-gop/python')
sys.path.insert(0, '/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
from uefi_firmware import efi_compressor
import pefile

root = Path('evidence/navi21-unlock/disassembly-v1')
references = json.loads(Path('evidence/navi21-unlock/xt-rom-comparison-v1/full-reference-comparison.json').read_text())
out = Path('/tmp/navi21-gop/extracted')
out.mkdir(parents=True, exist_ok=True)
sha = lambda data: hashlib.sha256(data).hexdigest()
images = []
for variant in ('baseline', 'candidate'):
    reference = references[variant]
    rom = Path(reference['path']).read_bytes()
    assert sha(rom) == reference['sha256']
    for index, item in enumerate(reference['pcir_images'][1:]):
        data = rom[item['offset']:item['offset']+item['bytes']]
        assert data[:2] == b'\x55\xaa'
        assert struct.unpack_from('<I', data, 4)[0] == 0xef1
        machine, compression = struct.unpack_from('<HH', data, 10)
        payload_offset = struct.unpack_from('<H', data, 22)[0]
        assert compression == 1
        compressed_size, original_size = struct.unpack_from('<II', data, payload_offset)
        payload = data[payload_offset:payload_offset+8+compressed_size]
        assert len(payload) == compressed_size+8
        decoded = efi_compressor.EfiDecompress(payload, len(payload))
        assert len(decoded) == original_size
        pe = pefile.PE(data=decoded)
        assert pe.FILE_HEADER.Machine == machine
        path = out/f'{variant}-{machine:04x}.efi'
        path.write_bytes(decoded)
        sections = []
        for section in pe.sections:
            contents = section.get_data()
            sections.append(dict(name=section.Name.rstrip(b'\0').decode(),
                rva=hex(section.VirtualAddress), raw=hex(section.PointerToRawData),
                bytes=len(contents), virtual_bytes=section.Misc_VirtualSize,
                executable=bool(section.Characteristics & 0x20000000), sha256=sha(contents)))
        images.append(dict(variant=variant, machine=hex(machine), rom_sha256=sha(rom),
            rom_offset=hex(item['offset']), compressed_sha256=sha(payload),
            extracted=str(path), bytes=len(decoded), sha256=sha(decoded),
            image_base=hex(pe.OPTIONAL_HEADER.ImageBase), entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            sections=sections))
comparisons = []
for machine in sorted({im['machine'] for im in images}):
    a,b = [im for im in images if im['machine']==machine]
    comparisons.append(dict(machine=machine, identical=a['sha256']==b['sha256'],
        section_equal={s['name']:s['sha256']==t['sha256'] for s,t in zip(a['sections'],b['sections'])}))
result = dict(scope='Reference-ROM GOP extraction only; no firmware execution or installed-ROM identity claim.',
              decompressor='uefi_firmware 1.16 EfiDecompress', images=images, comparisons=comparisons)
(root/'gop-inventory.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(comparisons))
