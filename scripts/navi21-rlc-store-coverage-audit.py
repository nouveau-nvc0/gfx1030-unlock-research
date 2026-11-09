#!/usr/bin/env python3
"""Refresh the scoped LX6 store inventory and expose local coverage limits."""
import collections,hashlib,json,pathlib,subprocess
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');oldpath=E/'rlc-iram-store-scan.json';old=json.loads(oldpath.read_text());scanner=pathlib.Path('scripts/navi21-smu-cfg-scan.py');out=E/'rlc-iram-store-scan-current.json'
args=['python3',str(scanner),*[r['listing'] for r in old['reports']],'--output',str(out)]
if old['indirect_edges']:args+=['--indirect-edges',old['indirect_edges']]
subprocess.run(args,check=True)
a=json.loads(out.read_text());prior={r['listing']:r for r in old['reports']};changed=[];inputs=[];unknown=[];stops=[];missing=[];unresolved=[]
for r in a['reports']:
 p=pathlib.Path(r['listing']);inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 previous={s['pc']:s for s in prior[r['listing']]['stores']}
 assert set(previous)=={s['pc'] for s in r['stores']}
 for s in r['stores']:
  if s['address']!=previous[s['pc']]['address']:changed.append({'listing':str(p),'pc':s['pc'],'old_address':previous[s['pc']]['address'],'address':s['address']})
  if s['address'] is None and s['base']!='a1':unresolved.append({'listing':str(p),**s})
 if r['unknown_operations']:unknown.append({'listing':str(p),'operations':r['unknown_operations']})
 stops.extend({'listing':str(p),**s} for s in r['reached_stop_instructions'])
 missing.extend({'listing':str(p),'pc':pc} for pc in r['missing_fallthrough'])
assert len(a['reports'])==236 and len(changed)==7 and len(unresolved)==108
assert {c['address'] for c in changed}=={'0x5ffee272','0x5ffee3c4','0x5ffee3c5'}
assert not stops
assert {m['pc'] for m in missing}=={'0x97f5','0xa465'}
r={'scanner_sha256':hashlib.sha256(scanner.read_bytes()).hexdigest(),'historical_scan_sha256':hashlib.sha256(oldpath.read_bytes()).hexdigest(),'current_scan_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'inputs':inputs,'procedures':len(a['reports']),'reached_stores':sum(len(x['stores']) for x in a['reports']),'newly_resolved_stores':changed,'unknown_non_stack_base_stores':unresolved,'unknown_operations':unknown,'reached_stop_instructions':stops,'missing_fallthrough':missing,
'findings':[
 'All2399 previously listed stores remain in the refreshed local analysis. Only seven addresses change, matching the prior027ccMOVT result. No new CC/gate writer is established.',
 '108 non-a1 stores remain address-unknown to the simple constant scanner. This count includes separately bounded loops, caller-dependent output pointers and known CC save/copy routines; it is NOT108 new candidate producers.',
 'Reached excw/ill stops are now explicitly reported; none occurs in these236 local entry analyses. Two missing fallthroughs occur after calls:97f5->a304 and a465->97f0. Possible return/resumption and adjacent code are not silently treated as covered.',
 'Unknown operations remain in12 listings and call/indirect boundaries retain earlier limits. No whole-firmware absence claim follows from this inventory.'
],
'next':'Use the remaining computed-store list with existing bounded-loop/caller receipts; avoid treating already resolved candidates as new. Prioritize indirect writers and entry coverage that can actually affect saved masks or gate.',
'scope':'Reanalysis of the same236 listings and initial indirect-edge table; not new firmware discovery or complete runtime coverage. No hardware access.'}
(E/'rlc-store-coverage-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'procedures':r['procedures'],'stores':r['reached_stores'],'changed_addresses':len(changed),'unknown_non_stack_base_stores':len(unresolved),'missing_fallthroughs':len(missing)}))
