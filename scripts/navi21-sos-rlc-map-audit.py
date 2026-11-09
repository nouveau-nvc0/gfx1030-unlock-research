#!/usr/bin/env python3
"""Resolve the local mapping setup used for RLC base-register accesses."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def rows(a,z):
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
windows={hex(a):rows(a,z) for a,z in [(0x27238,0x27292),(0x24b30,0x24b74),(0x25dc4,0x25e18)]}
literals={hex(a):hex(struct.unpack_from('<I',b,a)[0]) for a in (0x24b74,0x25e18,0x25e1c,0x25e20,0x27294,0x27298,0x2729c)}
assert list(literals.values())==['0x8898','0x3220050','0x8898','0xfff00000','0x6054','0x6010','0x3010000']
checks=[]
for address in [0x3ed70,0x3ed74,0x3ed78,0x3b000]:
 end=address+8
 assert end<=0x3900000 and end>=address and end<=0x3700000 and end<=0x3000000
 checks.append({'address':hex(address),'range_end':hex(end),'range_function_return':0,'mapped_pointer':hex(0x1000000+(address&0xfffff))})
r={'firmware_sha256':sha,'capstone_version':capstone.__version__,'windows':windows,'literals':literals,'concrete_range_checks':checks,
 'range_reasoning':'27238 rejects overlap with two upper intervals and unsigned wrap. All four small addresses pass. Later global-state branches either return0 early or reach comparisonend<=3000000, also returning0. Conditional on ordinary completion of global reads, state values cannot produce return10 for these addresses.',
 'slot0_setup':[
 '24b30 uses slot0, attributes0, finalflag0 for7b/7c. Target>>20=0, so STRH[8898]=0 and STRH[889a]=1.',
 '25dc4 writes attributes0 to03220050. Reads activehalfword889a=1, leaving stored high-address halfword unchanged.',
 'Slot parity0 selects the lower-half update ofDWORD03220000. Inserted bits are0; existing upper16 preserved, lower16 cleared.',
 '24b30 returns01000000+(target&fffff);7c size4 STR uses that pointer and follows withDSB.'
 ],
 'limits':['Firmware runtime mapping of low kernel code remains structurally inferred','Global/table reads and setup stores assumed to complete; no hardware observation','Actual window physical identity and effect of write still require corroboration','This resolves a local range/setup dependency, not a changed CC producer or hardware acceptance'],
 'scope':'Offline exact bytes and arithmetic; no hardware actions.'}
(E/'sos-rlc-map-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':sum(map(len,windows.values())),'concrete_addresses':len(checks),'slot_control':'0x03220050','slot_selector':'0x03220000'}))
