#!/usr/bin/env python3
"""Enumerate the LX6 4004 selector offline; no firmware execution."""
import hashlib,lzma,struct
import pathlib,re,json
p=pathlib.Path('evidence/navi21-unlock/disassembly-v1/rlc-iram-functions/04004.txt');code={}
for line in p.read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)',line)
 if m:code[int(m[1],16)]=(len(m[2])//2,m[3].removesuffix('.n'),m[4])
def run(low):
 r={'a2':low,'a3':None,'a4':None,'a5':None,'a6':None};pc=0x4004;trace=[]
 def v(x):return r[x] if x.startswith('a') else int(x,0)&0xffffffff
 for _ in range(200):
  if pc==0x406d:return {'low6':low,'address':hex(r['a2']),'word_slot':r['a14'],'trace':[hex(x) for x in trace]}
  trace.append(pc);n,op,s=code[pc];a=[x.strip() for x in s.split(';')[0].split(',')];nxt=pc+n
  if op in ['entry','s32i']:pass
  elif op=='l32r':r[a[0]]=int(re.search(r'\((0x[0-9a-f]+)\)',s)[1],16)
  elif op in ['mov','movi']:r[a[0]]=v(a[1])
  elif op=='extui':r[a[0]]=(v(a[1])>>v(a[2]))&((1<<v(a[3]))-1)
  elif op=='addi':r[a[0]]=(v(a[1])+v(a[2]))&0xffffffff
  elif op=='moveqz':
   if v(a[2])==0:r[a[0]]=v(a[1])
  elif op=='j':nxt=int(a[0],16)
  elif op in ['beqz','bnez']:
   if (v(a[0])==0)==(op=='beqz'):nxt=int(a[1],16)
  elif op in ['bltu','bltui','bgeu','bgeui']:
   if (v(a[0])<v(a[1]))==(op in ['bltu','bltui']):nxt=int(a[2],16)
  elif op in ['bany','bnone']:
   if bool(v(a[0])&v(a[1]))==(op=='bany'):nxt=int(a[2],16)
  else:raise ValueError(hex(pc),op,s)
  pc=nxt
 raise ValueError('bound')

E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
rawcode=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560]
count=0
for line in p.read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
 if m:
  a=int(m[1],16);raw=bytes.fromhex(m[2]);assert rawcode[a:a+len(raw)]==raw;count+=1
# Independently pin loop increment, 64-byte boundary, and base reset.
for a,raw in {0x407c:'e07e11',0x40ac:'4b22',0x40b3:'4b77',0x40b8:'26d708',0x40c4:'219de4',0x410c:'0c0e',0x4111:'46d9ff'}.items():assert rawcode[a:a+len(bytes.fromhex(raw))].hex()==raw
rows=[run(i) for i in range(64)];destinations=set()
for r in rows:
 i=r['low6'];base=int(r['address'],16);slot=r['word_slot']
 assert (base,slot)==((0x3ba68+i,i//4) if i%4==0 else (0,0))
 assert 0<=slot<16
 starts=[0x68000000+base+4*j for j in range(16-slot)]
 r['first_chunk_maximum_word_addresses']=[hex(x) for x in starts]
 destinations.update(starts)
# Subsequent chunks reset a2 and a14 regardless of total length.
destinations.update(range(0x6803ba68,0x6803baa8,4))
cc={0x68008924,0x680089bc,0x680098f4}
assert not destinations & cc
out={'firmware_sha256':sha,'listing_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':count,'selector_cases':rows,'possible_word_destinations':[hex(x) for x in sorted(destinations)],
'proof':[
 'Before406d, the control computation reads only low6 of originala2. Other incoming values remainNone in the interpreter: any arithmetic/branch dependency on them would fail. Stack and initial fixed hardware stores are skipped only for this selector calculation.',
 'Aligned low6=4*k selectsaddress3ba68+4*k andwordslotk for k0..15. Unaligned values selectaddress0/slot0. This describes code, not validated caller inputs.',
 '407c sets a7=4*slot;40b3 advances4;40b8 exits inner loop whena7=64. Other length check can only exit earlier. Thus at most16-slot consecutiveDWORDs per chunk.',
 '40c4 resets a2=3ba68 and410c resets slot0 before any next chunk. General caller length cannot make this destination walk beyond the fixed16-word bank.',
 'All40a0 starting addresses lie in68000000..6800003c or6803ba68..6803baa4. None targets the three reviewed CC registers. This conclusion does not require assuming the caller length is small.'
],
'limits':['Conditional on the decoded local control flow and ordinaryCALL8 register preservation.','Other fixed stores and hardware-side interpretation may have indirect effects; address exclusion is not absence of all CC effects.','No live invocation or hardware CC acceptance established. No hardware access.']}
(E/'rlc-4004-destination-audit.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'selector_cases':len(rows),'possible_word_destinations':len(destinations),'CC_destination_hits':len(destinations&cc)}))
