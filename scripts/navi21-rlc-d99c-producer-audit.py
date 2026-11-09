#!/usr/bin/env python3
"""Offline registered-handler paths to the alternative restore flag d99c."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560];rows={};inputs=[]
for name,ranges in {'03300':[(0x3300,0x3313)],'07d24':[(0x7d24,0x7d45),(0x7ef0,0x7f05)],'083fc':[(0x83fc,0x8439),(0x8757,0x876c)],'077cc':[(0x7864,0x7874),(0x7b59,0x7b68)],'02edc':[(0x2edc,0x2f18)]}.items():
 p=E/'rlc-iram-functions'/f'{name}.txt';selected=[]
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)',line)
  if m and any(a<=int(m[1],16)<z for a,z in ranges):
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw
   row={'pc':hex(pc),'bytes':raw.hex(),'operation':m[3],'operands':m[4]};rows[pc]=row;selected.append(row)
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'instructions':selected})
for pc,target in [(0x7871,0x83fc),(0x7b65,0x7d24),(0x7f02,0x3300),(0x8769,0x3300),(0x2f15,0x6944)]:assert rows[pc]['operation']=='call8' and f'target={hex(target)}' in rows[pc]['operands']
assert rows[0x330c]['operands']=='a2, a4, 0' and rows[0x330f]['operands']=='a3, a4, 4'
assert rows[0x7efc]['operands']=='a10, a15, 0, 1' and rows[0x8760]['operands']=='a10, a11, 0, 1'
assert rows[0x7eff]['operands']=='a11, a15, 8' and rows[0x8766]['operands']=='a11, a11, 8'
def word(address):return struct.unpack_from('<I',dram,address-0x5ffec000)[0]
assert word(0x5ffed27c)==0x5ffed99c and word(0x5ffed2e4)==10000 and word(0x5ffed204)==0x6803b200
assert word(0x5ffecc50+11*4)==0x5fff7ef0
assert word(0x5ffecd50+75*4)==0x5fff8757
r={'firmware_sha256':sha,'inputs':inputs,'table_routes':[{'table':'0x5ffecc50','index':11,'selector':'0x1b','target':'0x5fff7ef0'},{'table':'0x5ffecd50','index':75,'selector':'0x4b','target':'0x5fff8757'}],
'findings':[
 '3300 stores lowbyte(arg0) at5ffed99c and arg1 at5ffed9a0, substituting10000 whenarg1=0. It performs no save operation.',
 '7d24 reads selector from6803b2a4; subtracts16, requiresindex<21, then uses initialtablecc50. Selector1b ->7ef0 ->7f02 ->3300.',
 '83fc forms low16 command from6803b664 after its status-bit adjustments; requirescommand<102 and uses initialtablecd50. Selector4b ->8757 ->8769 ->3300.',
 'Both arms readV=DWORD[6803b2ac], passV&1 asarg0 andV>>8 asarg1. Thus local dataflow isd99c=V&1;d9a0=(V>>8) or10000 whenzero.',
 'Registered77cc contains calls7b65->7d24 and7871->83fc behind its existing event-bit conditions. This establishes linked static setter paths, not observed command delivery or a public host interface.',
 'Unlike db25 save-cycle producer, this setter does not itself saveCC. It supplies one condition for2edc, which also tests6803ed50bit1. Entry into2edc and changed saved-mask provenance remain unresolved.'
],
'limits':['Tables and literal placement are initial firmware evidence; runtime mutation/order not proved.','Outer77cc event delivery and actual register values not observed.','No inference thatd99c controls the registered e452 restore path; they are separate flags.','No hardware access or changes.']}
(E/'rlc-d99c-producer-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':len(rows),'setter':'0x3300','source':'0x6803b2ac bit0','selectors':['0x1b','0x4b']}))
