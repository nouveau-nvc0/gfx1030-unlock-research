#!/usr/bin/env python3
"""Trace the local constant index setup for every literal e800 write call."""
import hashlib,json,lzma,pathlib,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack_from('<6144I',b,0x200)
helper=json.loads((E/'rlcg-e800-helper-audit.json').read_text())
assert helper['firmware_sha256']==sha
assert [w[int(x['pc'],16)-0x2000] for x in helper['raw_words']]==[int(x['word'],16) for x in helper['raw_words']]
# Existing partial ISA: immediate/load destination bits18..21;
# immediate arithmetic and extended ALU destination bits22..25.
# Read helper2e7a writes r9/r3 only and stores r2 to the index port.
def disposition(v):
 if v==0x8c002e7a:return 'known read helper preserves r2'
 if v>>24 in [0xc0,0xc4]:
  dest=(v>>18)&15
  assert dest in [3,4,5]
  return 'immediate/load destination r'+str(dest)
 if v>>24 in [0x10,0x11,0x24,0x25,0x28,0x7c,0x7d]:
  dest=(v>>22)&15
  assert dest in [3,4,5,6]
  return 'ALU destination r'+str(dest)
 raise AssertionError(f'unclassified intervening word {v:08x}')
rows=[];ops={}
for i,v in enumerate(w):
 if v!=0x8c002e85:continue
 for j in range(i-1,max(0,i-20),-1):
  if w[j]&0xffff0000==0xc0080000:break
 else:raise AssertionError(hex(i+0x2000))
 middle=[]
 for k in range(j+1,i):
  reason=disposition(w[k]);ops[f'{w[k]:08x}']=reason
  middle.append({'pc':hex(k+0x2000),'word':f'{w[k]:08x}','interpretation':reason})
 rows.append({'call':hex(i+0x2000),'index_setup':hex(j+0x2000),'index':hex(w[j]&65535),'setup_word':f'{w[j]:08x}','intervening':middle})
assert len(rows)==89
indices=sorted({int(r['index'],16) for r in rows})
assert indices==[2,3,9,14,15,18,19,33,35,37,39,40,41,43,44,49,50,52,53,54,56,96,97]
r={'firmware_sha256':sha,'helper_audit_sha256':hashlib.sha256((E/'rlcg-e800-helper-audit.json').read_bytes()).hexdigest(),'calls':rows,'unique_intervening_words':ops,'indices':[hex(i) for i in indices],'findings':['Every literal2e85 call has a preceding immediate r2 assignment within19words. Intervening words are classified ALU/immediate/load operations targeting other registers or the checked2e7a read helper. No intervening conditional/unconditional branch occurs.','Under this partial ISA and fallthrough-from-setup assumption, all89 write sites use one of23 fixed indices. Dynamic data values do not become the index along these local sequences.','This replaces the previous local caller-dataflow gap, but not the unknown physical index map. Fixed small indices alone do not establish that CC or saved RAM cannot be selected.'],'limits':['No full RLCG CFG: incoming transfers to the middle of a sequence, other code entries and computed calls remain unbounded.','Partial ISA destination-field interpretation is retained, not an independent processor specification.','Values written and all later hardware effects are not bounded by this index audit. No hardware access.']}
(E/'rlcg-e800-write-indices-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'literal_write_calls':len(rows),'constant_indices':len(indices),'classified_intervening_words':len(ops),'maximum_intervening_words':max(len(x['intervening']) for x in rows)}))
