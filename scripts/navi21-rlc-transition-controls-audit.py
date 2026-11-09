#!/usr/bin/env python3
"""Bound the local restore-transition callee group and identify SERDES fields."""
import hashlib,json,lzma,pathlib,re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];p=E/'rlc-transition-controls-cfg.json';cfg=json.loads(p.read_text());expected={'037d8':{'0x1194','0x383c'},'03724':set(),'0383c':{'0x59e4'},'01194':set(),'059e4':set()};records=[];ram=[]
for r in cfg['reports']:
 root=pathlib.Path(r['listing']).stem;assert root in expected
 assert not r['unknown_operations'] and not r['unresolved_or_external_edges']
 assert {c['target'] for c in r['calls']}==expected[root]
 for s in r['stores']:
  if s['address'] is None:assert s['base']=='a1';continue
  a=int(s['address'],0);width={'s8i':1,'s16i':2,'s32i':4}[s['operation'].removesuffix('.n')]
  assert not(a<0x5ffee004 and a+width>0x5ffedfc4) and not(a<=0x5ffee452<a+width)
  if 0x5ffec000<=a<0x5fff0000:ram.append(s)
 q=pathlib.Path(r['listing']);n=0
 for line in q.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1
 records.append({'listing':str(q),'sha256':hashlib.sha256(q.read_bytes()).hexdigest(),'records':n,'reachable':r['reachable_in_window']})
assert {s['address'] for s in ram}=={'0x5ffee453','0x5ffee454','0x5ffee25e'}
h=(S/'gc_10_3_0_offset.h').read_text();d=dict(re.findall(r'^#define\s+(mm\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*$',h,re.M));ports={}
for name,addr in [('MASK',0x3b178),('CTRL',0x3b17c),('DATA',0x3b180),('BUSY',0x3b184)]:
 n='mmRLC_SERDES_'+name;assert d[n+'_BASE_IDX']=='1' and 4*(0xa000+int(d[n],0))==addr;ports[n]=hex(addr)
ctrl=1|2|(0x1fff<<3)|(12<<16);assert ctrl==0xcfffb
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'cfg_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'scanner_sha256':hashlib.sha256(pathlib.Path('scripts/navi21-smu-cfg-scan.py').read_bytes()).hexdigest(),'header_sha256':hashlib.sha256(h.encode()).hexdigest(),'listings':records,'ram_stores':ram,'ports':ports,'383c_serial_command':{'mask':'0xf0003','control':hex(ctrl),'data':'383c argument','BPM_BROADCAST':1,'BPM_REG_WRITE':1,'BPM_LONG_CMD':0,'BPM_ADDR':'0x1fff','REG_ADDR':12},
'scope':'Complete local direct-store/call inventory of this five-function group at normal entries. Hardware downstream effects, interrupts, computed entry variants and actual completion are not covered. No direct e452 or savedCC write; hardware serial command is not proven unrelated to hardware CC acceptance.'}
(E/'rlc-transition-controls-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'instructions':sum(x['reachable'] for x in records),'records':sum(x['records'] for x in records),'RAM_addresses':sorted({s['address'] for s in ram}),'serial_ctrl':hex(ctrl)}))
