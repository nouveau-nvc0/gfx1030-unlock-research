#!/usr/bin/env python3
"""Trace command41's initial workers and identify its second callback layer."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
def word(a):return struct.unpack_from('<I',b,512+a)[0]
roots=['1d7a8','1d698','1d60c','1d594','1d480','25b68','28b80','1d554','1f354','1d488','1d7fc']
inputs=[];records={}
for root in roots:
 p=E/'all-entry-candidates'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;records[pc]=(m[2],m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
for pc,raw in {0x1d4ba:'82228b',0x1d4bf:'8808',0x1d4c1:'e00800',0x1d7dd:'a2247f',0x1d7e2:'b24a00',0x1d483:'1df0',0x1d7ff:'1df0'}.items():assert records[pc][0]==raw
pointers=[word(0x12d10+4*i) for i in range(4)];workers=[word(0x12d20+4*i) for i in range(4)]
assert pointers==[0x101fc,0x1042c,0x1065c,0x1088c]
assert workers==[0x1d698,0x1d60c,0x1d594,0x1d480]
structures=[]
for p in pointers:
 t=word(p+0x22c);assert t in [0x115a0,0x115e0]
 state=list(b[512+p+30:512+p+34]);assert state==[0,0,0,0]
 assert word(t)==0x1d7fc
 structures.append({'base':hex(p),'next_base':hex(p+0x230),'initial_callback_table':hex(t),'initial_step0_state_cursor_start_end':state,'initial_callback0':hex(word(t))})
scanpath=E/'all-entry-store-scan.json';scan=json.loads(scanpath.read_text());setups=[]
for report in scan['reports']:
 if pathlib.Path(report['listing']).stem not in ['1d698','1d60c','1d594']:continue
 for c in report['calls']:
  if c.get('target') not in ['0x25b68','0x28b80']:continue
  k=c['integer_constants'];slot=int(k['a11'],16)
  if c['target']=='0x25b68':
   src=int(k['a12'],16);dst=int(k['a13'],16)
   fields=[(8*slot+0x1dc,4),(36*src+24,4),(36*dst+28,2)]
  else:fields=[(8*slot+0x1e0,1)]
  assert all(0<=off and off+width<=0x230 for off,width in fields)
  assert all(not (off<=0x22c<off+width) for off,width in fields)
  setups.append({'worker':pathlib.Path(report['listing']).stem,'call':c['pc'],'helper':c['target'],'relative_writes':[{'offset':hex(off),'width':width} for off,width in fields]})
assert len(setups)==24
# 1d554 searches32 fixed-size pair entries; selected slot changes values,
# but its possible pair writes all stay below the callback-table pointer.
assert 0x15c+31*4+4==0x1dc
r={'firmware_sha256':sha,'inputs':inputs,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),'initial_structures':structures,'initial_workers':[hex(x) for x in workers],'setup_calls':setups,'findings':['Three initial workers configure the selected structure through25b68/28b80, clear its byte1, then call1f354->1d488. Fourth worker1d480 immediately returns.','24 setup calls have constant field indices; computed writes stay within the230hex-byte selected structure and do not reach its callback-table pointer+22c. 1d554 pair writes range+15c..+1db under its32-entry loop. These are local bounds, not whole-callee closure.','1d488 loads pointer[P+22c], then callback from that table indexed by state bytesP+1f/P+20, bounded locally by byteP+21. Therefore command41 has a second data-dependent callback layer before the final pointer reload/store.','All four initial structures have zero step0 state/cursor/start/end and callback0=1d7fc, an immediate-return function. This describes image initialization only, not actual command-time contents.','Final store1d7e2 still rereads global15874 after callbacks. Stability across runtime callbacks, helper1d538/error path, synchronization and other writers remains unproved.'],'next':'Trace initialization/runtime writers of P+22c and state bytes+1f/+20/+21, and reachable second-level callbacks before claiming final pointer preservation or a CC connection.','scope':'Offline normal-worker setup and initial image layout. Selector ranges outside0..3, runtime mutations, address aliases and hardware acceptance remain open. No hardware access.'}
(E/'smu-command41-workers-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'setup_calls':len(setups),'structures':len(structures),'second_callback':'0x1d4c1'}))
