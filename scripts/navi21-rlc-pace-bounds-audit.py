#!/usr/bin/env python3
"""Bounded offline checks for two PACE selectors and the state ring."""
import hashlib,itertools,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];inputs=[]
for root in ('01ca8','01d10','029c4','029ec','02a0c','02ab8'):
 p=E/'rlc-iram-functions'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
# Both selectors terminate on a comparison outcome or after15 iterations.
# Abstract booleans include all comparison results, independently of FP values.
returns=set();reads=set()
for outcomes in itertools.product((False,True),repeat=15):
 count=0
 for i,taken in enumerate(outcomes):
  reads.add(0x5ffee27c+4*i)
  if taken:break
  count+=1
 returns.add(count)
assert returns==set(range(16))
ring=[0x5ffee41c-64+4*i+8 for i in range(16)]
assert ring==list(range(0x5ffee3e4,0x5ffee424,4))
assert all((i+1)&15 in range(16) for i in range(16))
assert all(not a<=0x5ffee452<a+4 for a in ring)
# Exact ring DWORD index that would instead cover the gate-bearing DWORD.
assert (0x5ffee450-ring[0])//4==27
scanpath=E/'rlc-iram-store-scan.json';scan=json.loads(scanpath.read_text());writers=[]
for r in scan['reports']:
 for s in r['stores']:
  if s.get('address')=='0x5ffee424':writers.append({'listing':r['listing'],**s})
assert {s['pc'] for s in writers}=={'0x1cfd','0x2a70','0x2aff'}
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'inputs':inputs,
'locator_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),
'selector_29c4':{'coefficient_reads':[hex(x) for x in sorted(reads)],'abstract_outcomes':32768,'possible_return_indices':sorted(returns)},
'selector_29ec':{'derived_integer_reads':[hex(0x5ffee278+0x110+4*i) for i in range(15)],'same_return_bound':[0,15]},
'ring':{'index_address':'0x5ffee424','known_fixed_writers':writers,'write_addresses':[hex(a) for a in ring],'gate_word_index':27,'invariant':'Initializer0, both updates (old+1)&15; conditional on no other writer.'},
'scope':'Local selector bounds and conditional ring invariant. No proof of all index writers, all coefficient consumers, or complete later dataflow.'}
(E/'rlc-pace-bounds-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'selector_outcomes':32768,'ring_addresses':len(ring),'fixed_index_writers':len(writers)}))
