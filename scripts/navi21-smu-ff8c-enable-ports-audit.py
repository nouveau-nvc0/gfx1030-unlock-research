#!/usr/bin/env python3
"""Pin ff8c enable call sites and state8's concrete indexed-port transaction."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
scanpath=E/'all-entry-store-scan.json';scan=json.loads(scanpath.read_text());calls=[]
for r in scan['reports']:
 for c in r['calls']:
  k=c.get('integer_constants',{})
  if c.get('target')=='0x28b80' and k.get('a10')=='0xff8c' and k.get('a11') in ['0x1','0x9']:
   calls.append({'listing':r['listing'],'pc':c['pc'],'group':int(k['a11'],16),'enable':int(k['a12'],16)})
assert len(calls)==8
roots=sorted({pathlib.Path(x['listing']).stem for x in calls}|{'1de0c','31508','2f3e0','28b80'});inputs=[];records={}
for root in roots:
 p=E/'all-entry-candidates'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;records[pc]=(m[2],m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n})
for c in calls:assert 'target=0x28b80' in records[int(c['pc'],16)][1]
for pc,raw in {0x31515:'224102',0x3153d:'426595',0x31546:'2225a2',0x2f3ed:'224102',0x2f415:'526695',0x2f41b:'4266a2',0x1de32:'2c3a',0x1de34:'b1f6d4',0x1de93:'2c3a',0x1de95:'b1ddd4',0x28b89:'4245e0'}.items():assert records[pc][0]==raw
for addr,value in [(0x1320c,0x1ce18),(0x13fe8,0xfffe4000),(0x13418,0xffffc7ff),(0x13620,0x141ce00)]:assert struct.unpack_from('<I',b,512+addr)[0]==value
# Follow byte2 replacement and the two documented-by-listing bit insertions.
selector=35;argument=0x1ce18;relative=(argument+0xfffe4000)&0xffffffff
control=1|(selector<<16)
control=(control&0xfffff803)|(((relative>>2)&255)<<2)
control=(control&0xffffc7ff)|(((relative>>10)&7)<<11)
assert relative==0xe18 and control==0x231a19
out={'firmware_sha256':sha,'inputs':inputs,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),'group_enable_calls':calls,'indexed_transaction':{'caller':'0x1de0c','read_helper':'0x31508','write_helper':'0x2f3e0','selector':selector,'argument':hex(argument),'relative_field':hex(relative),'packed_control':hex(control),'control_address':'0x0141d054','data_address':'0x0141d088'},'findings':['Concrete group9 enable calls1db92/1dbe8/1f5c4; disable1dc48. Group1 enables1ddfd/1ee4e/1f517; disable1df3f. These are static call-site producers, not observed execution.','28b80 stores the enable byte atff8c+1e0+8*group:101b4(group9),10174(group1). Neither address is the global pointer15874.','State8 helper1de0c invokes31508/2f3e0 with35 and1ce18. The second parameter is reduced by1c000 and packed into bitfields; final control231a19 goes to0141d054 and data uses0141d088. It is not a direct store at1ce18.','The branch with nonzero argument writes(read_value|3)&ffffffef; zero branch writes read_value&ffffffec through that interface. Additional direct writes0141cb0c/0141d700 and call373f4 remain separate.','No CC or LX6 saved-array address relation has been established for these ports. A small field update cannot be described as changing CC without that relation.'],'next':'Resolve physical meaning of0141d054/0141d088 and the concrete state2 operations only if they supply a CC dependency; retain entry/state/poll conditions.','scope':'Offline local producers and exact address/control arithmetic. Full call effects, runtime enable state, indexed-register identity and hardware acceptance remain open.'}
(E/'smu-ff8c-enable-ports-audit.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'byte_checked_records':sum(x['records'] for x in inputs),'enable_sites':len(calls),'packed_control':hex(control)}))
