#!/usr/bin/env python3
"""Check whether the known LX6 bulk path requires a nonzero port index."""
import hashlib,json,lzma,pathlib,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
p=E/'rlcg-toc-audit.json';toc=json.loads(p.read_text())
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()==toc['rlc_sha256']
w=struct.unpack('<6144I',b[0x200:0x6200])
def seq(pc,expected):assert list(w[pc-0x2000:pc-0x2000+len(expected)])==expected
calls=[i+0x2000 for i,v in enumerate(w) if v==0x8c0035d7]
assert calls==[0x311d,0x31b0,0x31fb]
seq(0x311b,[0xc54b020b,0x14ac0010,0x8c0035d7])
seq(0x31ae,[0xc54b020b,0x14ac0010,0x8c0035d7])
seq(0x31f6,[0xc54b020b,0x14ac0010,0xc54b020a,0xc020ffff,0x7e0a4009,0x8c0035d7])
seq(0x35d7,[0x12640002,0xc03a4000,0xc02abc00,0x2aa80004,0x8c0030a6,0xcc01c065,0xcec1c064,0xcc01c067,0xce41c066,0xcf81c063,0xce81c0e8,0x90000000])
rows=[r for r in toc['entries'] if r['address_register']=='0xfb55' or r['data_register']=='0xfb56']
assert [r['id'] for r in rows]==[10,27]
assert all(r['address_register']=='0xfb55' and r['data_register']=='0xfb56' and r['start_word']==0 and r['index']==0 and r['size_bytes_base_units']==16384 for r in rows)
other_starts=[{'id':r['id'],'port':r['address_register'],'start':r['start_word']} for r in toc['entries'] if r['start_word']]
assert [r['id'] for r in other_starts]==[1,2]
result={
 'rlc_sha256':hashlib.sha256(b).hexdigest(),'toc_receipt_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
 'index_helper':'0x35d7','all_immediate_helper_calls':[hex(c) for c in calls],
 'raw_helper_words':[hex(x) for x in w[0x15d7:0x15e3]],
 'lx6_dram_descriptors':rows,'other_nonzero_descriptor_starts':other_starts,
 'interpretation':'Under the existing partial RLCG decoding, each caller supplies DW3 high16 unchanged as the immediate index value. Helper shifts the register address left2, not the supplied index. Both LX6 DRAM descriptors supply zero. Bulk load/save then uses fixed data port and byte count16384.',
 'what_this_does_not_determine':['Nonzero LX6 index unit, width, or wrap behavior','SMU alias and transaction availability','Whether independent accesses reproduce the DMA port behavior','Changed payload producer or callable restore','Hardware acceptance of changed CC'],
 'dependency_correction':'Nonzero index units are a requirement for addressed single-location access, not for the already observed zero-start whole-block DMA setup. The whole-block alternative still needs a proven changed payload source and invocation; it is not an established SMU write route.',
 'scope':'Exact firmware words and descriptors checked offline. Partial instruction meanings and actual device behavior remain distinct from byte verification.'}
(E/'rlcg-lx6-index-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'helper_calls':len(calls),'lx6_descriptors':len(rows),'lx6_start_indices':[r['start_word'] for r in rows],'transfer_bytes':16384}))
