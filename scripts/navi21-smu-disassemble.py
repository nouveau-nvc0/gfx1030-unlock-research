#!/usr/bin/env python3
"""Offline targeted Xtensa listing; never accesses a GPU.

GNU lx106 handles density instructions; Capstone supplies windowed instructions.
Neither decoder establishes that arbitrary input bytes are executable code.
"""
import argparse
import hashlib
import json
import lzma
import pathlib
import re
import subprocess
import tempfile

import capstone

p = argparse.ArgumentParser()
p.add_argument('--firmware', required=True)
p.add_argument('--kind', choices=('smu', 'rlc-iram'), default='smu')
p.add_argument('--objdump', required=True)
p.add_argument('--start', type=lambda x: int(x, 0), required=True)
p.add_argument('--stop', type=lambda x: int(x, 0), required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
raw = pathlib.Path(a.firmware).read_bytes()
blob = lzma.decompress(raw) if a.firmware.endswith('.xz') else raw
expected = ('0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d' if a.kind == 'smu'
            else '19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0')
assert hashlib.sha256(blob).hexdigest() == expected, 'unreviewed firmware layout'
code_offset = 0x200 if a.kind == 'smu' else 0xb360
code = blob[code_offset:] if a.kind == 'smu' else blob[code_offset:code_offset+0x10000]
assert 0 <= a.start < a.stop <= len(code)
decoder = capstone.Cs(capstone.CS_ARCH_XTENSA, 0)
with tempfile.TemporaryDirectory() as tmp:
    binary = pathlib.Path(tmp) / 'smc.bin'
    binary.write_bytes(code)
    result = subprocess.check_output([
        a.objdump, '-D', '-b', 'binary', '-m', 'xtensa',
        f'--start-address={a.start}', f'--stop-address={a.stop}', str(binary)
    ], text=True)
lines = []
for line in result.splitlines():
    if a.kind == 'rlc-iram':
        literal = re.search(r'\bl32r\s+a\d+,\s*(0x[0-9a-f]+)', line)
        if literal and '(' not in line:
            relative = int(literal[1], 16)
            dram_offset = (relative + 0x4000) & 0xffffffff
            if dram_offset < 0x4000:
                value = int.from_bytes(blob[0x1b560+dram_offset:0x1b564+dram_offset], 'little')
                line += f' ({hex(value)}) ; inferred DRAM map 0x5ffec000'
    m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]+)\s+excw', line)
    if m:
        pc = int(m[1], 16)
        data = bytes.fromhex(m[2])
        # Cache-test option absent from both configured decoders. Encoding
        # verified against Cadence ISA Summary table218 and QEMU de233_fpu
        # Opcode_{lict,licw,ldct}_Slot_inst_encode (see evidence provenance).
        word = int.from_bytes(data, 'little')
        # QEMU de233_fpu encodes WSR.MISC1 as 0x13f500 (t register)
        # and DHWBI as 0x007052. Restrict the latter to this observed
        # zero-displacement instance; do not guess offset scaling.
        extra = None
        compare = {0x03f100: 'rsr.ccompare1', 0x03f200: 'rsr.ccompare2',
                   0x13f100: 'wsr.ccompare1', 0x13f200: 'wsr.ccompare2',
                   # QEMU de233_fpu Opcode_{rsr,wsr}_{epc4,eps4,excsave4}.
                   0x03b400: 'rsr.epc4', 0x13b400: 'wsr.epc4',
                   0x03c400: 'rsr.eps4', 0x13c400: 'wsr.eps4',
                   0x03d400: 'rsr.excsave4', 0x13d400: 'wsr.excsave4'}.get(word & 0xffff0f)
        if len(data) == 3 and compare:
            extra = f'{compare} a{(word >> 4) & 15}'
        if len(data) == 3 and word & 0xffff0f == 0x13f500:
            extra = f'wsr.misc1    a{(word >> 4) & 15}'
        elif data == bytes.fromhex('527200'):
            extra = 'dhwbi        a2, 0'
        elif data == bytes.fromhex('627200'):
            extra = 'dhi          a2, 0'
        elif data == bytes.fromhex('e27200'):
            extra = 'ihi          a2, 0'
        if extra:
            lines.append(f'{pc:08x}: {m[2]:8s} {extra} ; verified QEMU encoding')
            continue
        cache_op = {0xf10000: 'lict', 0xf12000: 'licw',
                    0xf18000: 'ldct'}.get(word & 0xfff00f)
        if len(data) == 3 and cache_op:
            line = (f'{pc:08x}: {m[2]:8s} {cache_op:12s} '
                    f'a{(word >> 4) & 15}, a{(word >> 8) & 15}'
                    ' ; verified cache-test encoding')
            lines.append(line)
            continue
        decoded = list(decoder.disasm(data, pc))
        if len(decoded) == 1 and decoded[0].size == len(data):
            ins = decoded[0]
            line = f'{pc:08x}: {m[2]:8s} {ins.mnemonic:12s} {ins.op_str} ; Capstone'
            if ins.mnemonic in ('call0', 'call4', 'call8', 'call12') and len(data) == 3:
                imm = int.from_bytes(data, 'little') >> 6
                if imm & (1 << 17):
                    imm -= 1 << 18
                line += f' ; target=0x{(pc & ~3) + 4 + imm * 4:x}'
    direct = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{6})\s+(call0|call4|call8|call12)\b', line)
    if direct and 'target=' not in line:
        pc = int(direct[1], 16)
        imm = int.from_bytes(bytes.fromhex(direct[2]), 'little') >> 6
        if imm & (1 << 17):
            imm -= 1 << 18
        line += f' ; target=0x{(pc & ~3) + 4 + imm * 4:x}'
    lines.append(line)
pathlib.Path(a.output).write_text('\n'.join(lines) + '\n')
pathlib.Path(a.output + '.json').write_text(json.dumps({
    'firmware_sha256': expected, 'code_file_offset': hex(code_offset), 'kind':a.kind,
    'start': hex(a.start), 'stop': hex(a.stop),
    'mapping_status': 'analysis coordinates, global runtime base not attested',
    'capstone': capstone.__version__,
    'objdump_sha256': hashlib.sha256(pathlib.Path(a.objdump).read_bytes()).hexdigest(),
    'limitation': 'targeted linear decode, not execution or complete CFG validation'
}, indent=2) + '\n')
