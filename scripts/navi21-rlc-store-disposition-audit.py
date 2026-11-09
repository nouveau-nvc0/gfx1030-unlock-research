#!/usr/bin/env python3
"""Link every current unresolved-address store to a bounded scope or open item."""
import collections, hashlib, json, lzma, pathlib, re
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
source=E/'rlc-store-coverage-audit.json'
p=json.loads(source.read_text())
rows=p['unknown_non_stack_base_stores']
groups={}
def group(roots, status, evidence, limit):
 for root in roots.split():
  assert root not in groups
  groups[root]=(status,evidence.split(),limit)
group('01d10','bounded_derived_arrays','rlc-derived-store-audit.json','Three local loops; incoming values select stored values, not destination addresses. Other entries and later consumers remain outside this bound.')
group('02a0c 02ab8','conditional_ring_and_local_stack','rlc-pace-bounds-audit.json rlc-local-copy-bounds.json','Ring index must retain0..15. Known writers preserve that range; other writers remain open.')
group('02b44','local_stack','rlc-local-copy-bounds.json','Ordinary entry, register windows and unmodified live registers; copied values do not determine destination.')
group('02edc 035d8 038ec 03a00','local_stack','rlc-gate-local-alias-audit.json','Ordinary separate stack; no claim about other entries or stack placement at runtime.')
group('032c8','caller_dependent_index','rlc-gate-index-audit.json','Known direct indices0/1/2; indirect or interior entry is not bounded.')
group('04004','bounded_register_window','rlc-4004-destination-audit.json','Decoded selector/chunk paths and ordinary calls; hardware side effects remain separate.')
group('04374 065d8','bounded_destinations','rlc-window-store-audit.json','Local paths only; does not establish complete firmware coverage.')
group('04664 046c4 05138 0542c 08b3c','bounded_destinations','rlc-computed-store-bounds-audit.json','Local loop boundaries only.')
group('08b78','conditional_ring','rlc-computed-store-bounds-audit.json','Requires ring index0..63; other index writers not excluded.')
group('09830','bounded_slots_and_optional_output','rlc-computed-store-bounds-audit.json','Seven known callers have null output. Other callers may supply another output address.')
group('071ac','known_CC_save','','Known four arrays: CC WGP/RB and USER WGP/RB. These stores save register values; no transformation established.')
group('074c4','slot_dependent_snapshot','rlc-snapshot-sources.json','Custom slots can overlap CC/gate; known default slot31 does not. Actual alternative slot invocation remains open.')
group('09a84','context_pointer_dependent','rlc-context-layout-audit.json','Known context path only; general pointer provenance is not established by this inventory.')
group('0a1fc','caller_dependent_copy','rlc-copy-entry-audit.json','Two known calls copy20bytes away from CC/gate. Computed/interior entries remain open.')
group('054c8 05528','local_stack_new_byte_check','','Four stores use freshly formed a1 aliases; checks below establish offsets, not runtime stack placement.')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
checks={'054c8':{0x54da:'8bc1',0x54e7:'326c00',0x54ea:'325c02'},'05528':{0x557f:'d2c110',0x5590:'490d',0x5592:'425d02'}}
byte_checks=[]
for root,expected in checks.items():
 path=E/'rlc-iram-functions'/(root+'.txt'); records={}
 for line in path.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[0xb360+pc:0xb360+pc+len(raw)]==raw;records[pc]=m[2]
 for pc,raw in expected.items():assert records[pc]==raw
 byte_checks.append({'listing':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'records':len(records),'stack_offsets':[8,12] if root=='054c8' else [16,20],'widths':[4,2]})
result=[];used=set();refs={}
for row in rows:
 root=pathlib.Path(row['listing']).stem;status,evidence,limit=groups[root];used.add(root)
 for name in evidence:
  path=E/name;refs[name]=hashlib.sha256(path.read_bytes()).hexdigest()
 result.append({**row,'disposition':status,'evidence':evidence,'remaining_condition':limit})
assert used==set(groups) and len(result)==108
assert len({(r['listing'],r['pc']) for r in result})==108
out={'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'store_count':len(result),'counts':dict(collections.Counter(r['disposition'] for r in result)),'evidence_sha256':refs,'new_stack_alias_checks':byte_checks,'stores':result,'next':'All108 entries now have local dispositions. Prioritize actual alternate slot, pointer, index or entry producers; do not repeat bounded-loop checks without new evidence. This inventory is not a complete firmware absence proof.','scope':'Offline disposition of108 scanner-unknown non-a1 stores; conditional exclusions remain conditional. No hardware access.'}
(E/'rlc-store-disposition-audit.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'stores':108,'counts':out['counts'],'new_byte_checked_records':sum(x['records'] for x in byte_checks)}))
