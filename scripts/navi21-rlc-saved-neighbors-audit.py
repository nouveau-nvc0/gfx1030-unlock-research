#!/usr/bin/env python3
"""Check neighboring snapshot writers against exact saved-CC intervals."""
import hashlib,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];p=E/'rlc-saved-neighbors-cfg.json';cfg=json.loads(p.read_text());out=[]
for root,r in zip(['06e10','072f4','07390'],cfg['reports'],strict=True):
 assert r['listing'].endswith('/'+root+'.txt')
 assert not r['unknown_operations'] and not r['unresolved_or_external_edges'] and not r['calls']
 rows=[];stack=[]
 for s in r['stores']:
  if s['address'] is None:
   assert root=='06e10' and s['base']=='a1' and s['offset']=='0';stack.append(s);continue
  a=int(s['address'],0);op=s['operation'].removesuffix('.n');width={'s8i':1,'s16i':2,'s32i':4}[op]
  assert not(a<0x5ffee004 and a+width>0x5ffedfc4)
  assert not(a<=0x5ffee452<a+width)
  if 0x5ffec000<=a<0x5fff0000:rows.append({'pc':s['pc'],'address':hex(a),'end_exclusive':hex(a+width),'width':width})
 listing=pathlib.Path(r['listing']);n=0
 for line in listing.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1
 out.append({'root':root,'reached':r['reachable_in_window'],'local_ram_stores':rows,'stack_stores':stack,'listing_sha256':hashlib.sha256(listing.read_bytes()).hexdigest(),'byte_checked_records':n})
assert len(cfg['reports'])==3
ram=[s for r in out for s in r['local_ram_stores']]
assert len(ram)==18 and max(int(s['end_exclusive'],0) for s in ram)==0x5ffedfc4
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'cfg_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'scanner_sha256':hashlib.sha256(pathlib.Path('scripts/navi21-smu-cfg-scan.py').read_bytes()).hexdigest(),'reports':out,'CC_interval':['0x5ffedfc4','0x5ffee004'],'last_neighbor_end_exclusive':'0x5ffedfc4',
'scope':'Three normal function entries only. Constant address propagation covers all their reachable direct stores; one frame-local store assumes the normal entry frame. No callee effects exist in these three functions. Other writers, altered pointers/state and alternate entries are not globally excluded.'}
(E/'rlc-saved-neighbors-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'instructions':sum(r['reached'] for r in out),'records':sum(r['byte_checked_records'] for r in out),'neighbor_stores':len(ram),'stack_stores':sum(len(r['stack_stores']) for r in out)}))
