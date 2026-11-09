#!/usr/bin/env python3
"""Check the SOS SVC dispatch and concrete load/store helper instructions."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
def decode(a,z,mode):
 c=capstone.Cs(capstone.CS_ARCH_ARM,mode)
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a, (hex(a),hex(z),r[-1] if r else None)
 return r
ranges=[(0x21bb0,0x21bfc,capstone.CS_MODE_ARM),(0x25f34,0x25f9c,16),(0x26090,0x260ce,16),(0x26810,0x26828,16),(0x2683c,0x26848,16),(0x2685a,0x26866,16),(0x2536e,0x253b2,16),(0x27422,0x27456,16),(0x24b30,0x24b74,16),(0x26a5c,0x26a76,16),(0x26a88,0x26a90,16)]
windows={hex(a):decode(a,z,m) for a,z,m in ranges}
d={int(x['file_offset'],0):x for rs in windows.values() for x in rs}
assert struct.unpack_from('<I',b,0x21d3c)[0]==0x45c5
assert 0x21970+0x45c4==0x25f34
entries={}
for svc,target in [(0x7b,0x26810),(0x7c,0x26824)]:
 a=0x260d0+4*(svc-0x51);v=struct.unpack_from('<I',b,a)[0];assert 0x260d0+v==target
 entries[hex(svc)]={'entry_file':hex(a),'value':hex(v),'target_file':hex(target)}
assert 0x26a76+2*b[0x26a78]==0x26a88
assert d[0x253a2]['mnemonic']=='ldr' and d[0x253a4]['mnemonic']=='str'
assert d[0x27452]['operands']=='r5, [r0]' and d[0x27442]['mnemonic']=='dsb'
r={'firmware_sha256':sha,'capstone_version':capstone.__version__,'windows':windows,'svc_table_entries':entries,
 'code_mapping':'ARM vector code in payload at21970 reads pointer45c5 then BLX. Interpreting low kernel code as payload-relative maps Thumb45c4 tofile25f34, whose code extracts and dispatches matching operation ranges. This is structurally corroborated, not a live address-map observation.',
 'routes':{'0x7b':'25f34 ->26090 tableindex2a ->26810; pointer check22f5c then2536e. Size4 path loads mapped DWORD and stores to output pointer.', '0x7c':'25f34 ->26090 tableindex2b ->26824 ->2685a ->27422. Size4 path STRvalue to mapped pointer, thenDSB.', '0xf2':'25f34 high-operation branch ->26a5c,index2 ->26a88 ->234c4 withsaved r0/r1.'},
 'mapping_helper':'24b30 calls27238(address,8), and on zero result programs index high bits through table pointer then calls25dc4. Returns01000000+(address&fffff) for helper slot0. Nonzero initial result returns0; callers here do not separately test mapped pointer. Actual mapping acceptance/behavior not inferred from STR alone.',
 'meaning':'7b and7c have concrete memory-load and memory-store implementations behind a mapping helper. This replaces the earlier inference based only on argument shapes. RLC register identity still depends on mapped address space and success of the setup.',
 'limits':['Dispatcher state checks and mapping helpers27238/25dc4 require follow-up','SVCf2 route reaches234c4 but SYS delivery not yet traced','global2060ec producer still not found','No live address/state or changed CC acceptance'],
 'scope':'Offline instruction analysis only.'}
(E/'sos-svc-route-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'decoded_instructions':len(d),'routes':['0x7b','0x7c','0xf2'],'concrete_write':'STR at file27452 thenDSB'}))
