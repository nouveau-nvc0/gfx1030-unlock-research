#!/usr/bin/env python3
"""Offline audit of the RLC 35-word scratch consumer, not a hardware test."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b= lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560]
inputs=[]; records={}
for name in ('01d10','083fc'):
 p=E/'rlc-iram-functions'/(name+'.txt');text=p.read_text();count=0
 for line in text.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw
   if name=='01d10':records[pc]=(len(raw),m[3])
   count+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':count})
# Straight-line copy segment; only constants and origin labels are propagated.
regs={'a4':0x5ffee264,'a5':0x5ffee2dc};rows=[];pc=0x1d46
while pc<0x1e12:
 size,text=records[pc];op=text.split()[0]
 if op=='l32r':
  m=re.search(r'l32r\s+(a\d+),.*\((0x[0-9a-f]+)\)',text);assert m
  regs[m[1]]=int(m[2],16)
 elif op=='addi':
  m=re.match(r'addi\s+(a\d+),\s*(a\d+),\s*(-?\d+)',text);assert m
  regs[m[1]]=regs[m[2]]+int(m[3])
 elif op in ('l32i','l32i.n'):
  m=re.match(r'l32i(?:\.n)?\s+(a\d+),\s*(a\d+),\s*(0x[0-9a-f]+|\d+)',text);assert m
  addr=regs[m[2]]+int(m[3],0);assert isinstance(addr,int)
  regs[m[1]]={'load_pc':hex(pc),'source':addr}
 elif op in ('s32i','s32i.n'):
  m=re.match(r's32i(?:\.n)?\s+(a\d+),\s*(a\d+),\s*(0x[0-9a-f]+|\d+)',text);assert m
  value=regs[m[1]];assert isinstance(value,dict)
  dst=regs[m[2]]+int(m[3],0)
  rows.append({'load_pc':value['load_pc'],'store_pc':hex(pc),'scratch_address':hex(value['source']),'destination':hex(dst)})
 elif op=='extui':
  m=re.match(r'extui\s+(a\d+),',text);regs[m[1]]=None
 else:raise AssertionError((hex(pc),text))
 pc+=size
assert pc==0x1e12 and len(rows)==35
assert [int(r['scratch_address'],16) for r in rows]==list(range(0x78000340,0x780003cc,4))
assert sorted(int(r['destination'],16) for r in rows)==list(range(0x5ffee278,0x5ffee304,4))
# Candidate pairing is positional; the port's physical mapping remains inferred.
for i,r in enumerate(rows):r.update(word_index=i,candidate_smu_source=hex(0xfce8+4*i),candidate_port_index=hex(0xd0+i))
assert struct.unpack_from('<I',dram,0xd50+32*4)[0]==0x5fff8537
cc_ranges=[(0x5ffedfc4,0x5ffedfe4),(0x5ffedfe4,0x5ffee004)]
assert all(not lo<=int(r['destination'],16)<hi for r in rows for lo,hi in cc_ranges)
assert all(not int(r['destination'],16)<=0x5ffee452<int(r['destination'],16)+4 for r in rows)
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'inputs':inputs,'copies':rows,
'command_table':{'base':'0x5ffecd50','index':32,'target':'0x5fff8537','call_pc':'0x8545','callee':'0x1d10'},
'copy_destination_interval':['0x5ffee278','0x5ffee304'],'direct_copy_overlaps_saved_cc_or_gate':False,
'scope':'Exact software copy and initial command-table entry. Matching d0/35-word SMU block strongly supports an interface correspondence; physical port alias and automatic index movement remain unobserved. Later dataflow is not closed.'}
(E/'rlc-scratch-consumer-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'word_copies':len(rows),'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'command':32,'direct_cc_or_gate_overlap':False}))
