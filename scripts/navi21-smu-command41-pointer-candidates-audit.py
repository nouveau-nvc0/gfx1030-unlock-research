#!/usr/bin/env python3
"""Enumerate image-backed initial pointer selections for command41 byte store."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
start=0x12d10;count=min(65536,(len(b)-512-start)//4);hits=[]
bases=[0,0x1200000,0x60000000,0x68000000,0x70000000];offsets=[0x8924,0x89bc,0x98f4]
for index in range(count):
 a=start+4*index;v=struct.unpack_from('<I',b,512+a)[0]
 cc=any(base+off<=v<base+off+4 for base in bases for off in offsets)
 ram=0x5ffedfc4<=v<0x5ffee004 or v==0x5ffee452
 if cc or ram:hits.append({'index':index,'index_hex':hex(index),'cell':hex(a),'value':hex(v),'CC_coordinate_candidate':cc,'LX6_state_candidate':ram})
assert len(hits)==1 and hits[0]['value']=='0x89bc' and hits[0]['cell']=='0x13b94'
inputs=[];rows={}
for root in ['1d7a8','1d480','38b88','1f77c','2776c','36cfc']:
 p=E/'all-entry-candidates'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;rows[pc]=(m[2],m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n})
for pc,raw in {0x1d483:'1df0',0x1d7e2:'b24a00',0x27792:'a100b1',0x36cff:'a1a573',0x1f794:'2095f4',0x1f797:'e0e911',0x1f7ed:'20c044'}.items():assert rows[pc][0]==raw
assert struct.unpack_from('<I',b,512+0x12d2c)[0]==0x1d480
h=pathlib.Path('evidence/navi21-unlock/sources/gc_10_3_0_sh_mask.h');text=h.read_text();assert re.search(r'CC_GC_SHADER_ARRAY_CONFIG__INACTIVE_WGPS_MASK\s+0xFFFF0000L',text)
bit_coordinate=0x89bc;word_index=(bit_coordinate>>5)&65535;bit=bit_coordinate&31
assert word_index==0x44d and bit==28
out={'firmware_sha256':sha,'inputs':inputs,'header_sha256':hashlib.sha256(h.read_bytes()).hexdigest(),'selection_range_start':hex(start),'image_backed_entries':count,'other_selector_entries_not_covered':65536-count,'coordinate_bases_checked':[hex(x) for x in bases],'CC_byte_offsets_checked':[hex(x) for x in offsets],'hits':hits,'findings':['Known low selector3 chooses1d480, an immediate-return worker. Under normal return and stable global15874, final1d7e2 performs S8I value1 at the selected pointer. This isolates the direct byte-store candidate from nonempty worker callbacks.','The image-backed high-selector enumeration finds only89bc among the listed CC/state coordinate hypotheses. No reviewed full LX6 saved-mask/gate pointer appears in this subset. Remaining selector cells and runtime memory are not covered.','Literal89bc is consumed by2776c/36cfc through38b88 with width16.1f77c decomposes it into word index44d and bit28, and uses the separate0125d000-based read/cache mechanism. This is bit-coordinate usage, not proof that a direct S8I at89bc accesses CC.','Even if a direct byte-at-register-base alias existed, little-endian byte0 does not overlap documented INACTIVE_WGPS bits16..31. No claimed hardware behavior or accepted byte-write follows from this arithmetic.'],'next':'Retain runtime pointer/table mutation and unknown address relations as open. Do not treat the lone numeric89bc match as a changed-CC path.','scope':'Initial image-backed aligned pointer cells and known immediate-return worker only; command reachability, serialization, live table contents and other address aliases remain unproved. No hardware access.'}
(E/'smu-command41-pointer-candidates-audit.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'image_backed_entries':count,'uncovered_entries':65536-count,'coordinate_matches':len(hits),'byte_checked_records':sum(x['records'] for x in inputs)}))
