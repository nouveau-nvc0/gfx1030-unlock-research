#!/usr/bin/env python3
"""Offline checks of record preparation and its address-base producer."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest()
assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def decode(a,z):
 r=[{'offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
windows={hex(a):decode(a,z) for a,z in [(0x169b4,0x169d4),(0x5864,0x5880),(0x17210,0x17242),(0x10de8,0x10e94),(0x14808,0x14858),(0x14cd8,0x14cf2),(0x9e28,0x9e2e),(0xf37e,0xf3b4),(0x10f52,0x10f72),(0xff88,0xffea),(0x9eb0,0x9eb8)]}
d={int(x['offset'],0):x for rows in windows.values() for x in rows}
for a,m,o in [(0x169be,'bic.w','r2, r2, r0, lsl #1'),(0x169c2,'str','r2, [r1, #4]'),(0x169ca,'str','r2, [r1, #8]'),(0x17214,'bl','0x169b4'),(0x17222,'bl','0x14070'),(0x10e5a,'strd','r0, r1, [r6, #0x28]'),(0x10e7c,'bl','0x14808'),(0x14850,'strd','r1, r0, [r7]'),(0xffb8,'str','r0, [r1]'),(0xffba,'bl','0x14cd8')]:
 assert (d[a]['mnemonic'],d[a]['operands'])==(m,o),(hex(a),d[a])
pools={hex(a):hex(struct.unpack_from('<I',b,a)[0]) for a in [0x169d4,0x169d8,0x5880,0x10f78,0x14cf4,0x9e30,0x10008,0x9eb8]}
assert pools['0x169d8']=='0xe5cc24' and pools['0x10f78']=='0xe1fbc8'
initial={hex(v):hex(struct.unpack_from('<I',b,v-0xdfff00)[0]) for v in range(0xe1fbc8,0xe1fbf8,4)}
r={'firmware_sha256':sha,'capstone_version':capstone.__version__,'windows':windows,'literal_pools':pools,'candidate_affine_mapping_initial_words':initial,
'findings':[
 'Before17210 calls14070(18,arg), it calls169b4(arg). Ifbyte[e5c978+13]!=0, record DWORD+4 and+8 each become old & ~(arg<<1), truncated32bits. Thus the full pre-start path DOES modify record fields even though14070 operation18 does not.',
 '169b4 then clears argbit31 and tail-calls5864. For each setbit k,5864 clears DWORD[e40360+4*k]. Maximum k30. This is a separate SYS RAM array, not an established saved-CC array.',
 '10de8 receives pointerP; r4=DWORD[P]. When H=uint64[e1fbf0] is zero, alignment/size checks permit copying uint64[r4] to H at10e5a, and DWORD[r4+8] to[e1fbd0]. If H already exists, the local path compares incoming address and returns without rewriting it.',
 'After successful1bd58/1bc90,10e7c calls14808(Hlow,Hhigh,&G), whereG=uint64[e1fbe8]. 14808 computesG=H-((read6a1b0&ffffff)<<24)+((read6a15c&ffffff)<<24),modulo2^64. This is an actual link between the two bases on this path; translation reads are not measured.',
 'ff90 obtains a808(0x24); adds4*(DWORD[r5+230]&01ffffff), then5MiB, truncates to32bits and clears low20bits. If DWORD[r5+f4]&1e0 is nonzero,ffb8 stores this result into O=e1fbdc, thenffba calls14cd8. Inputr5 origin, table-size return and full ordering remain open.',
 '9eb0 is a direct setter of uint32[e1fbac] fromarg0; caller remains open.',
 '10f52 error path and f37e conditional teardown clear bothG/H. Consequently their earlier values cannot be assumed to persist through these branches.',
 '14cd8 setsF bit0 then ORs uint32[e1fbac]<<1 into F. It does not replace/clear prior count bits; F remains uint32[e1fbd4]. Input producer and invocation ordering remain open.',
 'Candidate affine mappingdfff00 places initial O/F/G/H words at zero, but file initial values do not prove later runtime values or absence of other writers.'
],
'next_edges':[
 'Trace r5/input-table origins for O producerffb8 and callers of count setter9eb0; determine caller/packet fields for10de8.',
 'Identify record consumer and map destinationH+O+S-1MiB into same address domain as RLC saved block before claiming overlap/non-overlap.',
 'Record bit-clearing is not evidence of CC mask changes: local target is e5cc24+4/+8, not LX6 saved masks. Changed CC producer and accepted write condition remain unresolved.'
], 'scope':'Static local paths with exact instruction checks; no hardware reads or writes.'}
(E/'sys-rlc-record-origin-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':len(d),'pre_start_record_fields_changed':[4,8],'H_G_translation_path':'10e5a->10e7c->14850'}))
