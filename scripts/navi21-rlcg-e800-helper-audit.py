#!/usr/bin/env python3
"""Pin the indexed RLCG helper structure without assigning a physical block."""
import hashlib,json,lzma,pathlib,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack_from('<6144I',b,0x200)
def word(pc):return w[pc-0x2000]
expected=[0xcc81e800,0xda01e804,0xc425e805,0x26640002,0x964ffffe,0xd901e804,0xc425e805,0x26640002,0x9a4ffffe,0xc40de803,0x90000000,0xcc81e800,0xccc1e801,0xd881e804,0xc425e805,0x26640001,0x964ffffe,0xd841e804,0xc425e805,0x26640001,0x9a4ffffe,0x90000000]
assert [word(pc) for pc in range(0x2e7a,0x2e90)]==expected
# Compare exact encoded fields using the already retained partial ISA model.
assert (word(0x2e7a)>>22)&15==2 and (word(0x2e85)>>22)&15==2
assert (word(0x2e86)>>22)&15==3 and (word(0x2e83)>>18)&15==3
calls={}
for target in [0x2e7a,0x2e85]:
 sites=[i+0x2000 for i,v in enumerate(w) if v==(0x8c000000|target)]
 calls[hex(target)]=[{'pc':hex(pc),'preceding_word':f'{word(pc-1):08x}','immediate_index':word(pc-1)&65535 if word(pc-1)&0xffff0000==0xc0080000 else None} for pc in sites]
assert len(calls['0x2e7a'])==76 and len(calls['0x2e85'])==89
assert all(x['immediate_index'] is not None for x in calls['0x2e7a'])
r={'firmware_sha256':sha,'raw_words':[{'pc':hex(pc),'word':f'{word(pc):08x}'} for pc in range(0x2e7a,0x2e90)],'calls':calls,'findings':['Both helpers first store r2 to operand e800 in encoded address mode1; no local mask, scaling or index range check precedes that store.','Read-shaped helper obtains r3 from e803 after two status polls using mask2. Write-shaped helper stores r3 to e801 and uses status mask1. Both use control operand e804 and status operand e805.','This is an indexed transaction interface under the retained partial ISA interpretation, not an immediate store to address r2. Index-to-register or index-to-RAM correspondence remains unidentified.','The76 read calls have immediately preceding fixed index assignments. The89 write calls still require caller dataflow; nearby constants alone are not a proven bound.','No CC or saved-mask address relationship is established by this helper structure. Do not identify its physical block from another generation or from multiplication of e800 alone.'],'next':'For this family, obtain matching-generation index-map evidence before treating a numerical index as CC or RAM. Retain write caller provenance as open; no model-independent no-CC conclusion.','scope':'22 raw words and literal call inventory; partial ISA, no physical mapping or runtime behavior established. No hardware access.'}
(E/'rlcg-e800-helper-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'raw_words':22,'read_calls':76,'write_calls':89,'physical_index_map':'unresolved'}))
