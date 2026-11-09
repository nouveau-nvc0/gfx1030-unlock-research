#!/usr/bin/env python3
"""Offline SPM transfer constants and bounded direct-call inventory."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack('<6144I',b[0x200:0x6200])
def word(pc):return w[pc-0x2000]
def check(pc,values):assert [word(pc+i) for i in range(len(values))]==values
check(0x3614,[0xc0300000,0xc0280000,0xc03a4000,0xc036bc00,0x2b740004])
check(0x362a,[0xc0300000,0xc0280000,0xc03a4000,0xc036bc00,0x2b740004])
check(0x3637,[0x06200001,0x3e080004,0x948fffed,0xd80300eb,0xc02ee000,0x8c0035ce,0x90000000])
# Interpret only the three initialization forms used before3614. Retain their
# raw words, and reject anything outside this deliberately small subset.
r=[0]*16;mem={}
for pc in range(0x35f8,0x3614):
 v=word(pc)
 if v&0xffc30000==0xc0000000:r[(v>>18)&15]=v&65535
 elif v&0xfc030000==0xcc030000:
  source=(v>>22)&15;base=(v>>18)&15;mem[r[base]+(v&65535)]=r[source]
 else:raise AssertionError(hex(v))
assert [mem[0x300+i] for i in range(4)]==[13,21,16,23]
assert [mem[0x304+i] for i in range(4)]==[35,43,37,45]
assert [mem[0x308+i] for i in range(3)]==[50,56,75]
h=(S/'gc_10_3_0_offset.h').read_text();d=dict(re.findall(r'^#define\s+(mm\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*$',h,re.M))
entries=[]
for pc,name,addr,vals in [(0x361c,'mmRLC_SPM_GLOBALS_SAMPLE_SKEW',0xdc8c,[50]),(0x3620,'mmRLC_SPM_GLOBALS_MUXSEL_SKEW',0xdc8d,[56]),(0x3624,'mmRLC_SPM_DESER_START_SKEW',0xdc8b,[75]),(0x3632,'mmRLC_SPM_SE_SAMPLE_SKEW',0xdc8e,[13,21,16,23]),(0x3636,'mmRLC_SPM_SE_MUXSEL_SKEW',0xdc8f,[35,43,37,45])]:
 assert d[name+'_BASE_IDX']=='1' and int(d[name],0)+0xa000==addr
 assert word(pc)==0x8c0030ae and word(pc-2)==0xc0240000|addr and word(pc-1)==0x12640002
 entries.append({'call':hex(pc),'register':name,'dword':hex(addr),'public_byte':hex(addr*4),'values':vals,'byte_count':4})
callers=[i+0x2000 for i,v in enumerate(w) if v==0x8c0030ae]
expected=[0x3135,0x31c9,0x321b,0x35c6,0x35d5,0x361c,0x3620,0x3624,0x3632,0x3636]
assert callers==expected
sites={hex(addr):[{'pc':hex(i+0x2000),'word':f'{v:08x}'} for i,v in enumerate(w) if v&65535==addr] for addr in [0xc063,0xc064,0xc065,0xc066,0xc067,0xc0e8]}
assert all(len(s)==3 for s in sites.values())
roots=[hex(i+0x2000) for i,v in enumerate(w) if v==0x8c0035f8];assert roots==['0x30c3']
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'header_sha256':hashlib.sha256(h.encode()).hexdigest(),'root_callers':roots,'transfers':entries,'raw_words':[{'pc':hex(pc),'word':f'{word(pc):08x}'} for pc in range(0x35f8,0x363e)],'direct_30ae_callers':[hex(x) for x in callers],'engine_operand_literal_sites':sites,'command':'0xbc000004','control':'0x40000000','inferred_store_count':11,
'scope':'Small-subset initialization model and public coordinates verify constants. ISA execution, SE selection, actual scheduling and acceptance remain unobserved. Literal call/operand coverage does not cover computed addresses/calls or alternate entries.'}
(E/'rlcg-spm-transfer-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'raw_words':len(result['raw_words']),'transfer_sites':len(entries),'direct_calls':len(callers),'engine_literal_sites':sum(map(len,sites.values())),'values':[x['values'] for x in entries]}))
