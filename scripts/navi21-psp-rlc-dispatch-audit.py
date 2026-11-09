#!/usr/bin/env python3
"""Resolve two local SYS selector paths into previously decoded RLC callers."""
import hashlib,json,lzma,pathlib
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def rows(a,z):
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
windows={hex(a):rows(a,z) for a,z in [(0xdffe,0xe030),(0xe0e2,0xe0e8),(0xe0f6,0xe0fa),(0xe138,0xe164),(0xe168,0xe16c),(0xe2a2,0xe2a4),(0xe366,0xe368),(0xe9c2,0xe9d4),(0xe8e0,0xe8e4)]}
d={int(x['file_offset'],0):x for v in windows.values() for x in v}
assert d[0xe000]['operands']=='r1, #0x106f'
assert d[0xe01e]['operands']=='r1, #0x1031'
assert d[0xe016]['operands']=='r7, r4, #0x38'
assert d[0xe0f6]['mnemonic']=='tbb' and d[0xe168]['mnemonic']=='tbb'
assert 0xe0fa+2*b[0xe0fa+0x28]==0xe2a2
assert 0xe16c+2*b[0xe16c+1]==0xe366
assert d[0xe2a2]['operands']=='0xe9c2' and d[0xe366]['operands']=='0xe9cc'
assert d[0xe9c6]['operands']=='0xf0dc' and d[0xe9ce]['operands']=='0x17210'
r={'firmware_sha256':sha,'capstone_version':capstone.__version__,'windows':windows,
 'paths':[
 {'internal_selector':'0x1059','arithmetic':'1059-1031=28; 1031<1059<106f;28<3e','table_file':'0xe0fa','index':0x28,'entry':b[0xe122],'target':'0xe2a2','branch':'0xe9c2','call':'0xf0dc','arguments':'r0=packet+38,r1=0'},
 {'internal_selector':'0x1070','arithmetic':'1070-106f=1;1<e; high-range comparisons not selected','table_file':'0xe16c','index':1,'entry':b[0xe16d],'target':'0xe366','branch':'0xe9cc','call':'0x17210','arguments':'r0=DWORD[packet+38]'}],
 'shared_context':'r4 is packet pointer; selector loaded from[r4]; r7 setr4+38. Both branches join e8e0, moving result into r6 before branch ed74.',
 'limits':['Earlier validation at56fc and input-buffer handling remain prerequisites','These are internal SYS selectors, not demonstrated PSP ring command IDs','Outer function entry, runtime code placement and upstream translation remain open','Downstream start path still assumes SVC7b/7c read/write meanings','No changed CC payload or hardware acceptance established'],
 'scope':'Offline local control-flow and byte-table arithmetic. No hardware access.'}
(E/'psp-rlc-dispatch-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':len(d),'selectors':[x['internal_selector'] for x in r['paths']],'tables_checked':2}))
