#!/usr/bin/env python3
"""Audit known direct callers of RLC's indexed state-byte setter."""
import hashlib,json
from pathlib import Path
root=Path('evidence/navi21-unlock/disassembly-v1')
scan=root/'rlc-iram-store-scan.json';data=json.loads(scan.read_text());calls=[];nearby=[]
base=0x5ffee44c;gate=base+6
for report in data['reports']:
 for c in report['calls']:
  if c.get('target')!='0x32c8':continue
  k=c['integer_constants'];index=int(k['a10'],16);value=int(k['a11'],16)
  assert index in (0,1,2)
  address=(base+index+9)&0xffffffff
  assert address!=gate
  calls.append(dict(listing=report['listing'],pc=c['pc'],index=index,value=value,indexed_address=hex(address),aggregate_address=hex(base+1)))
 for s in report['stores']:
  if s.get('address') and base<=int(s['address'],16)<base+12:nearby.append(dict(listing=report['listing'],**s))
assert len(calls)==5
listing=root/'rlc-iram-functions/032c8.txt';text=listing.read_text()
for fragment in ('9a82','324809','224901'):assert fragment in text
result=dict(scope='Existing reachable-window scan direct CALL8 sites only; initial-table CFG and local constant assumptions retained. Not indirect-caller closure.',
 scan_sha256=hashlib.sha256(scan.read_bytes()).hexdigest(),setter_listing_sha256=hashlib.sha256(listing.read_bytes()).hexdigest(),
 gate=hex(gate),known_calls=calls,nearby_fixed_stores=nearby,
 remaining='Unknown indirect entry, general computed RAM stores, copy/engine effects and state restore can still affect gate; producer not established.')
(root/'rlc-gate-index-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS:five known calls write e455/e456/e457 and aggregate e44d, not gate e452')
