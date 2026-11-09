#!/usr/bin/env python3
"""Offline closure runner; uses pinned local decoder environment in /tmp/navi21-disasm.
No hardware access. Requires existing inventory and callback evidence.
"""
import pathlib,subprocess,os,json,re,collections,time,argparse
parser=argparse.ArgumentParser()
parser.add_argument('--all-entry-candidates',action='store_true',help='Separate locator sweep; not proof that each candidate is executable')
args=parser.parse_args()
root=pathlib.Path('/workspace/gfx1030-unlock-research/evidence/navi21-unlock/disassembly-v1');b=pathlib.Path('/tmp/navi21-disasm/smc-code.bin').read_bytes();env=dict(os.environ,PYTHONPATH='/tmp/navi21-disasm/python')
entries=[p for p in range(0,len(b)-3,4) if b[p]==0x36 and b[p+1]&15==1 ];entryset=set(entries)
js=json.loads((root/'message-handler-inventory.json').read_text());roots={int(x['entry'],16) for x in js['handlers']};roots.update([0x38d10,0x334d8,0x34008,0x349b0,0x37a70,0x333d8])
for row in json.loads((root/'transfer-table.json').read_text()):
 roots.update(int(row[k],16) for k in ['callback_37110','callback_3744c'] if int(row[k],16))
roots.update([0x1d698,0x1d60c,0x1d594,0x1d480])
for row in json.loads((root/'additional-callback-roots.json').read_text()):
 if row['entry_candidate']:roots.add(int(row['target'],16))
name='all-entry-candidates' if args.all_entry_candidates else 'call-closure'
if args.all_entry_candidates: roots.update(entries)
out=root/name;out.mkdir(exist_ok=True);queue=collections.deque(sorted(roots));seen=set();rejected=set();records=[];t=time.monotonic()
while queue:
 a=queue.popleft()
 if a in seen:continue
 seen.add(a)
 if a not in entryset:
  rejected.add(a);continue
 z=next((x for x in entries if x>a),len(b));p=out/f'{a:05x}.txt'
 if not p.exists() or json.loads(pathlib.Path(str(p)+'.json').read_text())['stop'] != hex(z):
  subprocess.run(['python3','/workspace/gfx1030-unlock-research/scripts/navi21-smu-disassemble.py','--firmware','/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz','--objdump','/tmp/navi21-disasm/binutils/usr/bin/xtensa-lx106-elf-objdump','--start',hex(a),'--stop',hex(z),'--output',str(p)],env=env,check=True,stdout=subprocess.DEVNULL)
 s=p.read_text()
 code={}
 for line in s.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)',line)
  if m:code[int(m[1],16)]=(m[3],m[4],line)
 pcs=sorted(code);sizes={pc:len(re.match(r'\s*[0-9a-f]+:\s+([0-9a-f]+)',code[pc][2])[1])//2 for pc in pcs};nxt={pc:pc+sizes[pc] for pc in pcs if pc+sizes[pc] in code};todo=[a];live=set()
 while todo:
  pc=todo.pop()
  if pc in live or pc not in code:continue
  live.add(pc);op,arg,line=code[pc]
  if op.startswith('ret') or op in ('ill','excw'):continue
  if op=='j' or op.startswith(('b','loop')):
   m=re.search(r'(0x[0-9a-f]+)\s*(?:;.*)?$',arg);rel=re.search(r'\.\s*([+-])\s*(0x[0-9a-f]+|\d+)',arg)
   target=(pc+(1 if rel[1]=='+' else -1)*int(rel[2],0) if rel else int(m[1],16) if m else None)
   if target in code:todo.append(target)
   if op=='j':continue
  if pc in nxt:todo.append(nxt[pc])
 live_text='\n'.join(code[pc][2] for pc in live)
 calls={int(x,16) for x in re.findall(r'target=0x([0-9a-f]+)',live_text)}
 records.append({'entry':hex(a),'candidate_end':hex(z),'direct_calls':[hex(x) for x in sorted(calls)],'indirect_calls':live_text.count('callx'),'unresolved_excw':len(re.findall(r'\bexcw\b',live_text)), 'reachable_in_window':len(live)})
 queue.extend(sorted(calls-seen))
 if len(records)%100==0: print('decoded',len(records),'pending',len(queue),'seconds',round(time.monotonic()-t),flush=True)
(root/(name+'.json')).write_text(json.dumps({'scope':('All aligned ENTRY candidates including possible data; locator only. ' if args.all_entry_candidates else '')+'Recursive reachable direct-call closure of static message roots plus startup/reset and known callback tables. ENTRY-candidate windows, not complete CFG. Rejected targets and indirect calls remain unresolved.','roots':[hex(x) for x in sorted(roots)],'rejected_targets':[hex(x) for x in sorted(rejected)],'functions':records},indent=2)+'\n')
print('DONE',len(records),'rejected',len(rejected),'indirect sites',sum(x['indirect_calls'] for x in records),'decoder-gap functions',sum(x['unresolved_excw']>0 for x in records),flush=True)
