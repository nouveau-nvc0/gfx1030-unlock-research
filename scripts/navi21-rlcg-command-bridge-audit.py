#!/usr/bin/env python3
"""Offline RLCG word/operand consistency receipt, not a complete ISA decoder."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
words=struct.unpack('<6144I',b[0x200:0x6200])
def word(pc):return words[pc-0x2000]
def expect(pc,seq):assert [word(pc+i) for i in range(len(seq))]==seq
expect(0x2495,[0xc40beca9,0x2488001f,0x94800024,0x0490249a,0xc03c0001,0x85000000])
expect(0x2a03,[0xd84300fa,0xc03c0020,0xc0380001,0x8c0035e3,0x8c0035ec,0xd803ec07,0x80002230])
expect(0x2a0a,[0xd8030039,0xd80300fa,0xc03c0020,0xc0380000,0x8c0035e3,0x8c002f49,0x8c002f6f,0x8c0035ec,0xd803ec07,0x80002230])
expect(0x35e3,[0xc40bed80,0x24880001,0x98800006,0xc40bedcc,0x1488001f,0x948ffffe,0xcf83ed9a,0xcfc3ed99,0x90000000])
expect(0x35ec,[0xc43fed80,0x27fc0001,0x9bc00009,0xc03c0020,0x0bfc0001,0x9bcfffff,0xc43bed99,0x17bc001f,0x97cffffb,0x17b80010,0x27bc00ff,0x90000000])
driver=(S/'gfx_v10_0.c').read_text()
assert re.search(r'#define\s+RLCG_UCODE_LOADING_START_ADDRESS\s+0x00002000L',driver)
assert 'le32_to_cpup(fw_data++)' in driver
h=(S/'gc_10_3_0_offset.h').read_text()
defs=dict(re.findall(r'^#define\s+(mm\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*$',h,re.M))
coords={}
for n in ('mmRLC_SMU_COMMAND','mmSMU_RLC_RESPONSE'):
 assert defs[n+'_BASE_IDX']=='1';coords[n]=0xa000+int(defs[n],16)
assert coords=={'mmRLC_SMU_COMMAND':0xeca9,'mmSMU_RLC_RESPONSE':0xec07}
# A hypothesis about fields, checked against seven independent local call sites.
# c0: immediate destination at bits18..21; cc: source at bits22..25.
def imm_fields(w):
 assert w&0xffc30000==0xc0000000
 return (w>>18)&15,w&0xffff
assert imm_fields(word(0x2a04))==(15,32)
assert imm_fields(word(0x2a05))==(14,1)
assert imm_fields(word(0x2a0c))==(15,32)
assert imm_fields(word(0x2a0d))==(14,0)
assert (word(0x35e9)>>22)&15==14 and (word(0x35ea)>>22)&15==15
assert (word(0x35e9)&0xffff)*4==0x3b668
assert (word(0x35ea)&0xffff)*4==0x3b664
calls=[]
for i,w in enumerate(words):
 if w==0x8c0035e3:
  pc=i+0x2000;d1,v1=imm_fields(word(pc-2));d2,v2=imm_fields(word(pc-1))
  assert (d1,d2)==(15,14)
  calls.append({'pc':hex(pc),'command':v1,'argument':v2})
assert len(calls)==7
# Under inferred add and indirect-jump fields the table is indexed from249a,
# not249b. The zero branch targets24bb. Avoid an off-by-one command assignment.
table=[]
for command in range(1,32):
 pc=0x249a+command;w=word(pc);assert w&0xffff0000==0x80000000
 table.append({'command_low5':command,'pc':hex(pc),'target':hex(w&0xffff)})
assert table[4]['target']=='0x2a03' and table[5]['target']=='0x2a0a'
assert 0x2497+0x24==0x24bb
# Independent Xtensa-side literal and table evidence.
iram=b[0xb360:0x1b360];dram=b[0x1b560:0x1f560]
assert struct.unpack_from('<I',dram,0xd200-0xc000)[0]==0x6803b600
assert struct.unpack_from('<I',dram,0xcd50-0xc000+32*4)[0]==0x5fff8537
p=E/'rlc-iram-functions/083fc.txt';checked=0
for line in p.read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
 if m:
  pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert iram[pc:pc+len(raw)]==raw;checked+=1
# Raw annotated windows retain uninterpreted words, without assigning mnemonic
# semantics to the full program.
windows=[]
for start,end in ((0x2495,0x24bc),(0x2a03,0x2a14),(0x35e3,0x35f8)):
 windows.extend({'pc_inferred':hex(pc),'file_offset':hex(0x200+4*(pc-0x2000)),'word':f'{word(pc):08x}'} for pc in range(start,end))
result={'firmware_sha256':sha,'segment_file_interval':['0x200','0x6200'],'driver_loading_word_base':'0x2000','driver_sha256':hashlib.sha256(driver.encode()).hexdigest(),'word_windows':windows,
'header_sha256':hashlib.sha256(h.encode()).hexdigest(),'header_dword_coordinates':{k:hex(v) for k,v in coords.items()},
'dispatch_hypothesis':table,'paired_calls':calls,'sender_write_word_fields':{'35e9':{'source':14,'dword':'0xed9a','public_byte':'0x3b668'},'35ea':{'source':15,'dword':'0xed99','public_byte':'0x3b664'}},
'xtensa_listing':{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'checked_records':checked,'table32':'0x5fff8537','call':'8545 -> 1d10'},
'candidate_bridge':{'SMU5':{'RLC_command':32,'argument':1,'entry':'0x2a03'},'SMU6':{'RLC_command':32,'argument':0,'entry':'0x2a0a'}},
'scope':'Exact words and coordinate arithmetic verified. RLCG operand/opcode meanings are consistent inference, not a vendor ISA specification or runtime observation. Sender conditions, callback scheduling, physical scratch alias and all CC producers remain unproved.'}
(E/'rlcg-command-bridge-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'raw_window_words':len(windows),'dispatch_entries':len(table),'paired_calls':len(calls),'xtensa_records':checked,'candidate_bridge':result['candidate_bridge']}))
