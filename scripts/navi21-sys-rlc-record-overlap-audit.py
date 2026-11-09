#!/usr/bin/env python3
"""Conditional address proof for the SYS record versus RLC DRAM snapshot."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def decode(a,z):
 rows=[dict(offset=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(r['bytes'])) for r in rows)==z-a
 return rows
windows={hex(a):decode(a,z) for a,z in [(0xfef0,0xff12),(0xff88,0xffea),(0xa808,0xa82c),(0xe546,0xe55a)]}
d={int(r['offset'],0):r for rows in windows.values() for r in rows}
assert d[0xffa6]['mnemonic']=='bfc' and d[0xffa6]['operands']=='r0, #0, #0x14'
assert d[0xe54c]['operands']=='0x10de8' and d[0xe554]['operands']=='0x9eb0'
assert struct.unpack_from('<I',b,0xfffc)[0]==struct.unpack_from('<I',b,0xa82c)[0]==0xe3fb60
sources={}
for n in ['sys-rlc-record-audit.json','sys-rlc-record-origin-audit.json','psp-rlc-base-locator.json','rlcg-toc-audit.json']:
 p=E/n;sources[n]=hashlib.sha256(p.read_bytes()).hexdigest()
toc=json.loads((E/'rlcg-toc-audit.json').read_text())
r=next(x for x in toc['entries'] if x['id']==27)
assert r['offset_bytes']==0x545000
snapshot_delta=0x400000+r['offset_bytes'];snapshot_size=0x4000
# Comparing relative offsets is sufficient: addition of the common base is bijective.
# G-H is an integer multiple of 2^24 in the established translation formula.
modulus=1<<20
assert (1<<24)%modulus==0
assert snapshot_delta%modulus==0x45000
assert snapshot_delta%modulus+snapshot_size==0x49000
assert 28 < snapshot_delta%modulus
# Every possible F gives a whole-MiB size, including maximum count bits.
for f in range(64):
 s=(((f>>1)&31)+1+(f&1))*modulus
 assert (s-modulus)%modulus==0
r={'firmware_sha256':sha,'source_receipt_sha256':sources,'windows':windows,
 'new_local_edges':[
 'fef6 loads r5=e3fb60, the same table base used by a808. Thus offset input DWORD[r5+230] and feature DWORD[r5+f4] are from this table, not an unknown caller pointer. Runtime table population is still open.',
 'Dispatch arm e546 sets packet+38 fromDWORD[r5], then passesr7 to10de8; arm e552 passesDWORD[packet+38] to count setter9eb0. Exact selectors and source of dispatchr5 remain open.'
 ],
 'conditional_proof':{
 'assumptions':['O is produced byffb8 on the audited path and not subsequently changed to an unaligned value.', 'G and H obey the audited14808 relation at the compared operations.', 'SVC address mapping and RLC snapshot use the compared address domains as inferred; actual mapping completion is not observed.', 'RLC uses the audited ID27 descriptor and G+400000 base.'],
 'record_relative_to_H':'O+S-0x100000; O and S are multiples of0x100000; length28 bytes.',
 'translation':'G-H=(-C+D)<<24 with masked24-bit C/D, modulo2^64; divisible by0x100000.',
 'snapshot_relative_to_G':hex(snapshot_delta),
 'snapshot_length':hex(snapshot_size),
 'record_residues_mod_1MiB':'[0,0x1c)',
 'snapshot_residues_mod_1MiB':'[0x45000,0x49000)',
 'conclusion':'Disjoint. Under these assumptions the28-byte record copy cannot directly overwrite any byte of the16KiB RLC DRAM snapshot, including saved CC masks and the gate.',
 'not_proved':'An indirect effect through a consumer of the record; other O writers/order; actual runtime execution; hardware CC acceptance.'},
 'next':'Identify consumer of the record address sent through1e130/1e058, or return to unresolved LX6 saved-mask/gate producers. Do not treat the record bitfields themselves as CC masks.'}
(E/'sys-rlc-record-overlap-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':len(d),'record_residues':'0..1b','snapshot_residues':'45000..48fff','conditional_direct_overlap':False}))
