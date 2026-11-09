#!/usr/bin/env python3
"""Audit the local PACE level writer; consumes a fresh local CFG receipt."""
import hashlib,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];inputs=[]
for root in ('022d8','029b0'):
 p=E/'rlc-iram-functions'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'byte_checked_records':n})
p=E/'rlc-pace-level-cfg.json';d=json.loads(p.read_text());r=d['reports'][0]
assert r['listing'].endswith('/022d8.txt')
assert not r['unknown_operations'] and not r['unresolved_or_external_edges']
fixed=sorted({s['address'] for s in r['stores'] if s['address']})
assert fixed==['0x5ffee272','0x5ffee3c4','0x5ffee3c5','0x5ffee3c9','0x6803b274','0x6803ba44']
stack=[s for s in r['stores'] if s['address'] is None]
assert all(s['base']=='a1' and int(s['offset'],0) in (0,4,8,12,24,32) for s in stack)
assert all(c['target']=='0x2b44' for c in r['calls'])
h=(S/'gc_10_3_0_offset.h').read_text();mh=(S/'gc_10_3_0_sh_mask.h').read_text()
names={}
for name,addr in [('mmRLC_RLCS_GENERAL_2',0x3ba44),('mmRLC_SPARE_INT_2',0x3b274),('mmRLC_SPP_PVT_LEVEL_MAX',0x3b484)]:
 m=re.search(r'^#define\s+'+name+r'\s+(0x[0-9a-f]+)',h,re.M);assert m and (0xa000+int(m[1],16))*4==addr
 names[name]=hex(addr)
assert re.search(r'RLC_SPP_PVT_LEVEL_MAX__LEVEL_MASK\s+0x0000000FL',mh)
lookup=[0x5ffee2e4-108+204+4*i for i in range(256)]
assert min(lookup)==0x5ffee344 and max(lookup)==0x5ffee740
result={'inputs':inputs,'cfg_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'cfg_tool_sha256':hashlib.sha256(pathlib.Path('scripts/navi21-smu-cfg-scan.py').read_bytes()).hexdigest(),
'headers':{n:hashlib.sha256((S/n).read_bytes()).hexdigest() for n in ('gc_10_3_0_offset.h','gc_10_3_0_sh_mask.h')},
'local_reached_instructions':r['reachable_in_window'],'direct_store_sites':len(r['stores']),'fixed_store_addresses':fixed,'stack_store_sites':len(stack),'callees':r['calls'],'named_registers':names,
'index_sources':{'245e':'zero on known joined paths','248d':'hardware low8, or descending low8 index, or bounded-by-input adjustment','2595':'hardware low8, or descending low8 index, or bounded-by-input adjustment'},
'29b0_byte_lookup_interval':['0x5ffee344','0x5ffee744'],'eight_bit_decrement_zero':255,
'scope':'Local direct writes only. Header field mask does not prove unused bits readzero; decrement arithmetic does not prove a reachable out-of-range execution. Calls and later dataflow remain separate.'}
(E/'rlc-pace-level-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'listing_records':sum(x['byte_checked_records'] for x in inputs),'reached':r['reachable_in_window'],'direct_store_sites':len(r['stores']),'fixed_addresses':len(fixed),'stack_stores':len(stack)}))
