#!/usr/bin/env python3
"""Record state-selection bounds and precise limits of the pointer-write locator."""
import hashlib,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
roots=['1d488','1d7ec','1d714','1d77c','28b50','1f1a4','1d6f8','1b42c','1bf68','1bf94'];inputs=[];records={}
for root in roots:
 p=E/'all-entry-candidates'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;records[pc]=(m[2],m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n})
for pc,raw in {0x1d497:'62041f',0x1d4a9:'820420',0x1d4ac:'920421',0x1d4b2:'8a66',0x1d4b4:'673927',0x1d4b7:'e05611',0x1d4ba:'82228b',0x1d4c1:'e00800',0x1d4da:'1b66',0x1d4dc:'67bbda',0x1d7f7:'224301'}.items():assert records[pc][0]==raw
# All sums of two byte inputs lie0..510. First call requires sum<=byte end.
possible={s for s in range(511) for end in range(256) if s<=end};assert possible==set(range(256))
scanpath=E/'all-entry-store-scan.json';scan=json.loads(scanpath.read_text());targets={hex(p+0x22c) for p in [0x101fc,0x1042c,0x1065c,0x1088c]};located=[];sameoffset=[];callers=[]
for r in scan['reports']:
 for s in r['stores']:
  if s.get('address') in targets:located.append({'listing':r['listing'],**s})
  if s.get('offset')=='0x22c':sameoffset.append({'listing':r['listing'],**s})
 for c in r['calls']:
  if c.get('target')=='0x1bf68':callers.append({'listing':r['listing'],**c})
assert not located
assert len(callers)==1 and callers[0]['integer_constants']['a10']=='0x110d4'
r={'firmware_sha256':sha,'inputs':inputs,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),'callback_index_bound':[0,255],'table_read_span_bytes':1024,'fixed_pointer_cell_locator_hits':located,'same_offset_stores_not_automatically_related':sameoffset,'known_1bf68_callers':callers,'findings':['1d488 sums cursor and start bytes without byte truncation, then compares against byte end BEFORE calling. Values256..510 skip the callback loop; subsequent indices remain<=the reloaded byte end. Hence each executed table lookup is within entries0..255, assuming ordinary callees preserve local state registers. This does not prove the table contains256 valid functions.','1d7ec, present in the initial second-level tables, writes1 to[P+1] using reloaded global15874; it does not assign global15874. This byte selects an early-return/resumption path in1d488 after callback.','1d714->1f1a4 clearsP+1 then drives1d6f8->1b42c.1d77c->28b50 updates maskP+12 and may drive the same machinery. These handlers do not locally assignP+22c or start/end bytes; their transitive effects remain open.','No fixed-address store to the four initialP+22c cells is located in the retained scan. Same-offset stores with different or unknown bases do not establish either a writer or its absence.','A separate helper1bf68 writes offsets32/33, but its only located caller passes110d4, not one of the four selected structures. Do not infer shared state solely from matching field offsets.'],'remaining':'Concrete startup/copy producers of state start/end and table contents, plus second-level callbacks and pointer stability. Initialzero state is not command-time state.','scope':'Offline local branch/index bounds and locator precision. Full writer/caller coverage, live address mapping and CC acceptance are not established.'}
(E/'smu-command41-state-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'records':sum(x['records'] for x in inputs),'index_bound':[0,255],'located_fixed_table_pointer_writers':len(located)}))
