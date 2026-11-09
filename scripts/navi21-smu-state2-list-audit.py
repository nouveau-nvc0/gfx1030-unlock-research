#!/usr/bin/env python3
"""Trace the producer of the state2 callback list and its eight source entries."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
def u32(a):return struct.unpack_from('<I',b,512+a)[0]
targets=[u32(0x12110+4*i) for i in range(8)]
assert targets==[0x2d808,0x2d7e0,0x2d7b4,0x2d78c,0x2d760,0x2d734,0x2d708,0x2d6dc]
roots=['2ff84','1ebfc','1ebbc','2d8b8','2d860']+[f'{x:05x}' for x in targets];inputs=[];records={}
for root in roots:
 p=E/'all-entry-candidates'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;records[pc]=(m[2],m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n})
for pc,raw in {0x30199:'0c0f',0x3019b:'0c0e',0x3019d:'0c0d',0x301a5:'b20282',0x301a8:'a20283',0x301ab:'920281',0x301ae:'0c88',0x301b3:'62c720',0x301b6:'52c740',0x301d0:'42247f',0x301d3:'42687f',0x301ea:'42247f',0x301ed:'42687f',0x30201:'42247f',0x30204:'42687f',0x301b9:'76a852',0x1ec0b:'e00b00',0x1ebcb:'e00b00'}.items():assert records[pc][0]==raw
assert u32(0x140b8)==0x11f14 and u32(0x132b0)==0x157e4 and u32(0x140a0)==0x9ec4
assert all(u32(0x159e0+4*i)==0 for i in range(26))
mask_cases=[]
for mask in range(256):
 selected=[targets[i] for i in range(8) if mask&(1<<i)]
 assert len(selected)==mask.bit_count()
 mask_cases.append({'mask':mask,'count':len(selected),'targets':[hex(x) for x in selected]})
scanpath=E/'all-entry-store-scan.json';s=json.loads(scanpath.read_text());effects=[]
for r in s['reports']:
 root=int(pathlib.Path(r['listing']).stem,16)
 if root in targets:
  assert len(r['stores'])==1 and len(r['calls'])==1
  effects.append({'callback':hex(root),'store':r['stores'][0],'wait_helper':r['calls'][0]['target']})
assert len(effects)==8
out={'firmware_sha256':sha,'inputs':inputs,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),'source_table':'0x12110','source_callbacks':[hex(x) for x in targets],'list_bases':['0x159e0','0x15a00','0x15a20'],'selection_bytes':['0x9f45','0x9f47','0x9f46'],'mask_cases':mask_cases,'callback_effects':effects,'findings':['2ff84 at30199..3020f builds three compact lists from the same eight function pointers, using bits of bytes9f45/9f47/9f46. Each list receives at most8 DWORDs; masks select entries, not arbitrary pointer values on this producer path.','1ebfc walks first list with argument1;1ebbc walks it with argument0. Both stop at a zero pointer and use an8-bit cursor. The builder does not append a zero terminator or clear unused suffixes in this loop.','Consequently do not bound each consumer to8 calls without additional lifecycle evidence: a full first list can continue into the second; a reused list can retain prior entries. Initial26DWORDs arezero, which is image state only.','All eight local callback bodies perform one fixed-register read/modify/write after a read-only wait helper. Destinations are0125a000/004/01c/024/028/02c; helpers poll0125a000 or0125a01c bit31. No local15874/CC/saved-array store is established here.','Direct address coordinates and bit updates are known; their complete physical meanings and indirect effects remain unestablished. The list lifetime and caller/state delivery still constrain any actual chain.'],'next':'Keep the concrete eight callback endpoints and missing local termination condition explicit. Avoid treating initialzeros or source-table completeness as complete runtime callback coverage.','scope':'Offline producer/consumer structure and byte-checked callback bodies; no hardware access or broad no-CC conclusion.'}
(E/'smu-state2-list-audit.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'records':sum(x['records'] for x in inputs),'source_callbacks':8,'masks_checked':256,'local_terminator_write':False}))
