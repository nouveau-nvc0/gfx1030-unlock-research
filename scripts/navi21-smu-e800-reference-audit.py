#!/usr/bin/env python3
"""Check SMU literals for a concrete counterpart of the RLCG indexed ports."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
values=set()
for base,step in [(0xe800,1),(0xeb00,1),(0x3a000,4),(0x3ac00,4),(0x123a000,4),(0x123ac00,4)]:
 values.update(base+step*x for x in [0,1,3,4,5])
hits={v:[] for v in values}
for i in range(len(b)-3):
 v=struct.unpack_from('<I',b,i)[0]
 if v in hits:hits[v].append(hex(i))
assert {hex(v):x for v,x in hits.items() if x}=={'0xe800':['0x13a88']}
inputs=[];rows={}
for root in ['25394','274b0']:
 p=E/'all-entry-candidates'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;rows[pc]=(m[2],m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
for pc,raw in {0x25397:'413cb9',0x2539a:'2022a0',0x2539d:'4022a0',0x253a0:'22227f',0x253a3:'2023b0',0x274e1:'31e9b0',0x274fc:'3343c4',0x274ff:'0343c2',0x27502:'2343c3',0x27505:'1343c5'}.items():assert rows[pc][0]==raw
r={'firmware_sha256':sha,'literal_search':{hex(v):hits[v] for v in sorted(values)},'inputs':inputs,'findings':['Only full literal e800 occurs, at file13a88/code13888, among these30 candidate port coordinates. No e800/eb00 port correspondence follows from this.','25394 uses e800 as a table base: returns DWORD[e800+20*arg0+1fc]+8*arg1. No indexed-port handshake occurs in this short routine.','274b0 loads the same base and stores numeric data at offsets308/30c/310/314 among other fields. These direct address uses are not the RLCG e800/e801/e803/e804/e805 protocol.','The two retained literal consumers do not provide the missing physical map. This distinguishes a concrete same-number data use from a port identity claim.'],'limits':['Literal search does not exclude computed coordinates or additional instruction streams.','No claim that all consumers or later data effects are covered.','SMU and RLCG address numbers are not interchangeable without a proven address relation. No hardware access.']}
(E/'smu-e800-reference-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'candidate_coordinates':len(values),'literal_hits':sum(map(len,hits.values())),'byte_checked_records':sum(x['byte_checked_records'] for x in inputs)}))
