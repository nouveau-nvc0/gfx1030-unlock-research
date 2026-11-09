#!/usr/bin/env python3
"""Pinned RLC startup data audit, no execution or hardware access."""
import hashlib,json,lzma,re,struct
from pathlib import Path
root=Path('evidence/navi21-unlock/disassembly-v1')
b= lzma.decompress(Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
d=b[0x1b560:0x1f560];code=b[0xb360:0x1b360]
def word(a):return struct.unpack_from('<I',d,a-0x5ffec000)[0]
checked=0
for line in (root/'rlc-iram-functions/00648.txt').read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
 if m:
  a=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[a:a+len(raw)]==raw,(hex(a),raw.hex());checked+=1
ranges=[]
for a in range(0x5ffed0fc,0x5ffed10c,8):
 start,end=word(a),word(a+4);assert start<=end
 ranges.append(dict(start=hex(start),end_exclusive=hex(end),covers_gate=start<=0x5ffee452<end,covers_saved_cc=start<=0x5ffedfc4 and end>=0x5ffee044))
state={hex(a):hex(word(a)) for a in (0x5ffed0ec,0x5ffed0f8,0x5ffed974,0x5ffed150,0x5ffed158,0x5ffed118,0x5ffed124,0x5ffed130,0x5ffee65c,0x5ffee660,0x5ffee664,0x5ffed7bc,0x5ffed7c0,0x5ffed7c4)}
assert word(0x5ffed0ec)==0xffffffff
assert word(0x5ffed974)==0x5ffed0f8 and word(0x5ffed0f8)==0
for a in (0x5ffed150,0x5ffed158,0x5ffed118,0x5ffed124,0x5ffed130,0x5ffee65c):assert word(a)==0
report=dict(scope='Pinned initial DRAM values and byte-checked non-ENTRY startup slice. Conditional conclusions require these cells to retain initial values until tested.',firmware_sha256=sha,checked_instructions=checked,zero_ranges=ranges,initial_words=state,
 conclusion='Initial constructor/destructor lists and optional runtime hooks contribute no extra target; no new gate setter from these initial lists.',
 unresolved='External/engine modifications, runtime callback registration and hardware reset entry ordering are not proved absent.')
(root/'rlc-startup-state-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
