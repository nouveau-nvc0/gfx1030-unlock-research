#!/usr/bin/env python3
"""Extend the earlier SMU port locator with concrete TOC-derived LX6 candidates."""
import hashlib,json,lzma,pathlib,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());assert hashlib.sha256(b).hexdigest()=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
p=E/'rlcg-toc-audit.json';toc=json.loads(p.read_text());rows=[r for r in toc['entries'] if r['id'] in (10,27)];assert len(rows)==2
assert all(r['address_register']=='0xfb55' and r['data_register']=='0xfb56' and r['size_bytes_base_units']==0x4000 for r in rows)
values=[0xfb55,0xfb56]
for base in (0,0x1200000,0x60000000,0x68000000):values.extend(base+4*x for x in (0xfb55,0xfb56))
scanp=E/'all-entry-store-scan-rsync.json';scan=json.loads(scanp.read_text());hits=[]
for r in scan['reports']:
 for s in r['stores']:
  if s['address'] and int(s['address'],0) in values:hits.append({'listing':r['listing'],'store':s})
literals={hex(v):[hex(i) for i in range(len(b)-3) if b[i:i+4]==struct.pack('<I',v)] for v in values}
assert not hits and all(not h for h in literals.values())
result={'smu_sha256':hashlib.sha256(b).hexdigest(),'toc_receipt_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'scan_receipt_sha256':hashlib.sha256(scanp.read_bytes()).hexdigest(),'scan_roots':len(scan['reports']),'candidate_dwords':['0xfb55','0xfb56'],'candidate_public_bytes':['0x3ed54','0x3ed58'],'all_byte_literal_matches':literals,'fixed_store_matches':hits,
'connection':'Concrete TOC boot/snapshot DRAM pair supplies a stronger LX6-memory endpoint candidate than earlier generic SRM_DRAM/GPM_SCRATCH names. SMU generic store can only be connected to it after its physical alias and acceptance are established.',
'open_dependencies':['TOC port pair to actual LX6 DRAM identity and indexing units','SMU address alias and allowed physical transactions at those ports','availability of generic store dispatch/channel and per-command conditions','state lifetime and callable CC restore path','hardware acceptance of changed CC values'],
'scope':'No literal or previously resolved fixed-store match for10candidate encodings. Does not exclude computed access. Cross-engine mapping remains an inference, not a demonstrated write route.'}
(E/'smu-lx6-port-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'encodings':len(values),'scan_roots':len(scan['reports']),'literal_matches':sum(map(len,literals.values())),'fixed_stores':len(hits)}))
