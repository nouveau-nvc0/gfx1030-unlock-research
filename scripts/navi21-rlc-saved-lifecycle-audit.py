#!/usr/bin/env python3
"""Local order of CC save/restore calls; no global execution or timing claim."""
import hashlib,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];inputs=[];maps={}
for root in ['03a00','032a4','035d8','038ec','05bc8']:
 p=E/'rlc-iram-functions'/(root+'.txt');ins={};n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1;ins[pc]=(raw,m[3],m[4])
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n});maps[root]=ins
ins=maps['03a00']
assert ins[0x3a81][1]=='beqz' and '0x3b38' in ins[0x3a81][2]
assert 'target=0x6944' in ins[0x3b32][2] and 'target=0x6944' in ins[0x3c0e][2]
# Prove contiguous straight-line instruction boundaries between skip target and
# save call. Calls may wait/fail; no claim that reaching start ensures return.
pc=0x3b38;path=[];calls=[]
while pc<=0x3c0e:
 raw,op,args=ins[pc];path.append(hex(pc))
 assert not op.startswith('b') and op not in ('j','jx','retw.n','retw')
 if op.startswith('call'):calls.append({'pc':hex(pc),'operand':args})
 pc+=len(raw)
assert path[-1]=='0x3c0e'
# Exact initialized stack bytes immediately preceding the save-word rebuild.
for pc in [0x3bba,0x3bbd,0x3bc0,0x3bc3,0x3bc6,0x3bc9,0x3bcc,0x3bcf]:
 assert ins[pc][1]=='s8i' and ins[pc][2].split(',')[0]=='a4'
assert 'movi.n'==ins[0x3a7f][1] and ins[0x3a7f][2]=='a4, 0'
# 38ec is an additional local save but no known normal invocation in retainedIRAM.
target=0x38ec;incoming=[]
for pc in range(len(code)-2):
 v=int.from_bytes(code[pc:pc+3],'little');off=v>>6
 if off&(1<<17):off-=1<<18
 if v&15==5 and ((pc+4)&~3)+off*4==target:incoming.append(hex(pc))
assert incoming==[]
pat=(0x5fff0000+target).to_bytes(4,'little');pointers=[hex(i) for i in range(len(b)-3) if b[i:i+4]==pat];assert not pointers
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'inputs':inputs,'gate_branch':'3a81 zero->3b38','local_order':{'gate_zero_at_test':['skip3b32restore','3c0e save(0,0)'],'gate_nonzero_at_test':['3b32 restore(1,1)','3c0e save(0,0)']},'straightline_skip_to_save':path,'intervening_calls':calls,'38ec_immediate_call_hits':incoming,'38ec_absolute_pointer_hits':pointers,
'scope':'Local order after reaching3a81 and conditional on intervening calls returning. No global guarantee of entering callback or completion. Gate may change externally; current saved arrays are unknown. Initial zero image does not determine later restore data.'}
(E/'rlc-saved-lifecycle-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'records':sum(x['records'] for x in inputs),'straightline_instructions':len(path),'calls_on_path':len(calls)}))
