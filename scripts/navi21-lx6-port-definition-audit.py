#!/usr/bin/env python3
"""Compare exact TOC port candidates with the pinned local register database."""
import hashlib
import json
import pathlib
import tarfile

archive = pathlib.Path('/workspace/gfx1030-unlock-research/inputs/research/umr-058a7045-source.tar.gz')
out = pathlib.Path('evidence/navi21-unlock/disassembly-v1')
reports = {}
with tarfile.open(archive) as tar:
    for member in tar:
        if not member.isfile() or not member.name.startswith('database/ip/gc_') or not member.name.endswith('.reg'):
            continue
        raw = tar.extractfile(member).read()
        entries = []
        current = None
        for line in raw.decode().splitlines():
            if line.startswith(('mm', 'reg')):
                fields = line.split()
                current = {'name': fields[0], 'offset': fields[2], 'fields': []}
                entries.append(current)
            elif line.startswith('\t') and current is not None:
                current['fields'].append(line.strip())
        selected = [e for e in entries if int(e['offset'], 0) in (0x5b55, 0x5b56) or 'RLC_LX6_DRAM_' in e['name'] or (member.name.endswith('gc_10_3_0.reg') and 'RLC_SRM_DRAM_' in e['name'])]
        if selected or member.name.endswith('gc_10_3_0.reg'):
            reports[member.name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'entries': selected}
nav = reports['database/ip/gc_10_3_0.reg']['entries']
assert not any(int(e['offset'], 0) in (0x5b55, 0x5b56) for e in nav)
assert {e['offset'] for e in nav} == {'0x5b71', '0x5b72'}
nextgen = reports['database/ip/gc_11_0_0.reg']['entries']
assert [(e['offset'], e['fields']) for e in nextgen] == [('0x5b68', ['ADDR 0 10']), ('0x5b69', ['DATA 0 31'])]
result = {
    'archive': str(archive), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'reports': reports,
    'conclusion': 'No Navi21 register-name or index-width confirmation for TOC ports fb55/fb56. Published SRM ports are a different pair. GC11 LX6 names and widths cannot be transferred to GC10.3.',
    'index_limit': 'GC11 ADDR field has 11 bits. Treating it as a DWORD index covers 8192 bytes, whereas Sienna TOC DRAM size is 16384 bytes. This does not establish either actual index unit; it prevents borrowing the GC11 field definition without further evidence.',
    'next_dependency': 'Resolve port/index semantics from Sienna code or a matching primary register description. SMU regional alias still requires separate evidence.',
    'scope': 'Offline database comparison only; no hardware transactions.'
}
(out / 'lx6-port-definition-audit.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'database_files_with_selected_entries': len(reports), 'navi21_candidate_names': 0, 'gc11_address_bits': 11}))
