#!/usr/bin/env python3
"""Bound selected unresolved LX6 stores from byte-checked existing listings."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560]
inputs=[];records={}
for root in ['04664','046c4','05138','0542c','08b3c','08b78','09830']:
 p=E/'rlc-iram-functions'/f'{root}.txt';n=0;rows={}
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   a=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[a:a+len(raw)]==raw
   rows[a]=(m[2],m[3]);n+=1
 records.update(rows);inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
# Verify the loop increments and exits supporting the enumerated bounds.
for a,raw in {0x46ba:'8bcc',0x46bc:'f79cd6',0x471a:'8bcc',0x471c:'f79cd6',0x516a:'22c202',0x5173:'b6e2eb',0x5445:'2b22',0x544c:'b6e2ed',0x8b5e:'2b44',0x8b60:'5794f4',0x8d9d:'a0a054',0x985c:'9c05'}.items():assert records[a][0]==raw
# Literal cells independently identify destination bases and end pointers.
for p,value in {0x5ffed3d0:0x5ffee464,0x5ffed3d4:0x5ffee4ec,0x5ffed3d8:0x5ffee574,0x5ffed454:0x5ffed9d4,0x5ffed458:0x5ffed9e4,0x5ffed68c:0x5ffee5f8}.items():assert struct.unpack_from('<I',dram,p-0x5ffec000)[0]==value
ranges=[]
for name,start,end,stride,widths in [('4664',0x5ffee464,0x5ffee4ec,8,[(0,4),(4,4)]),('46c4',0x5ffee4ec,0x5ffee574,8,[(0,4),(4,4)]),('5138',0x5ffed9e4,0x5ffedae4,4,[(0,4)]),('542c',0x5ffed9e4,0x5ffedae4,4,[(0,4)]),('8b3c',0x5ffee5fc,0x5ffee63c,2,[(0,1),(1,1)])]:
 written={p+j+k for p in range(start,end,stride) for j,n in widths for k in range(n)}
 assert written==set(range(start,end))
 assert 0x5ffee452 not in written and not written.intersection(range(0x5ffedfc4,0x5ffee004))
 ranges.append({'procedure':name,'start':hex(start),'end_exclusive':hex(end),'written_bytes':len(written),'loop_iterations':(end-start)//stride,'overlaps_CC_or_gate':False})
scanpath=E/'rlc-iram-store-scan.json';scan=json.loads(scanpath.read_text());calls=[]
for r in scan['reports']:
 for c in r['calls']:
  if c.get('target')=='0x9830':
   assert c['integer_constants']['a13']=='0x0'
   calls.append({'listing':r['listing'],'pc':c['pc'],'output_pointer':0})
assert len(calls)==7
r={'firmware_sha256':sha,'inputs':inputs,'bounded_local_store_ranges':ranges,'known_9830_calls':calls,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),
 'findings':[
 '4664 and46c4 each copy17 pairs ofDWORDs from hardware data registers to adjacent RAM ranges. Neither reaches gatee452, located18hex bytes before the first range, or savedCC arrays.',
 '5138 and542c index64 DWORDs using even loop counter0..126 divided by2; their fixed table ends atdae4, below savedCCdfc4.',
 '8b3c fills exactly64bytes frome5fc toe63b with50. 8d89 later writes one byte at e5fc+uint32[e63c]. Initializer sets index0 and8da0 writes(index+1)&63. Hence ring write stays in that range IF no other writer changes index; global exclusion is not claimed.',
 '9830 accepts index<8 and writes callback cells in[d7e0,d820). Its optional store9868 uses output pointera5; seven known direct CALL8 sites passa13=0, becoming calleea5=0, so that store is skipped for those calls. Indirect callers remain unbounded.',
 'These are exclusions of concrete candidate stores, not a proof that no LX6 instruction or engine can change CC/gate.'
 ],
 'remaining':'Computed stores in other procedures, unobserved state changes and indirect callers; prioritize producer candidates rather than rechecking these bounded loops.',
 'scope':'Offline listings checked against pinned code bytes and literal cells. Full interpretation retains inferred LX6 DRAM placement and existing partial CFG assumptions. No hardware access.'}
(E/'rlc-computed-store-bounds-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'bounded_loops':len(ranges),'known_null_output_calls':len(calls)}))
