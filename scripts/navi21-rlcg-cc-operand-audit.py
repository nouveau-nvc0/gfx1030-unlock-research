#!/usr/bin/env python3
"""Pinned RLCG operand inventory and explicitly conditional field interpretation."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack('<6144I',b[0x200:0x6200])
def word(pc):return w[pc-0x2000]
def seq(pc,values):assert [word(pc+i) for i in range(len(values))]==values
seq(0x3523,[0xc024226f,0xc0200000,0xc01c0000,0x8c00353e])
seq(0x352e,[0xc0242270,0xc01c0000,0x8c00353e])
seq(0x3545,[0x7dd2c001,0x9a000004,0xc6b10000,0xcf2f0000,0x8000354c,0xc6f30000,0xcf290000])
seq(0x354c,[0x05100001,0x04880001,0x30940002,0x954ffff2,0xc0080000,0x04cc0001,0x30d40004,0x954fffee,0x90000000])
expected={0x205d:(0xec4b,1),0x2061:(0xec6e,1),0x207b:(0x24d7,0),0x2083:(0x24d7,1),0x2087:(0xec6e,1),0x341b:(0xec6e,0),0x3423:(0xec6e,1),0x3427:(0x24d7,1),0x342e:(0x24d7,0),0x3436:(0x24d7,1),0x343a:(0xec6e,1),0x3442:(0xec53,0),0x349a:(0x24d7,0),0x349e:(0xec6e,0),0x34a6:(0x24d7,1),0x3526:(0x226f,0),0x3530:(0x2270,0)}
assert {i+0x2000 for i,v in enumerate(w) if v==0x8c00353e}==set(expected)
rows=[]
for pc,(reg,mode) in expected.items():
 # Local constant materializations in the preceding three words. The second
 # WGP call inherits r8=0; intervening words do not assign that register under
 # the same inferred fields. This is a named assumption, not a global CFG.
 last={}
 for p in range(pc-3,pc):
  v=word(p)
  if v&0xffc30000==0xc0000000:last[(v>>18)&15]=(p,v&0xffff)
 assert last[9][1]==reg
 if pc!=0x3530:assert last[8][1]==mode
 rows.append({'call_pc':hex(pc),'hardware_dword':hex(reg),'r8':mode,'mode_source':'inherited from3524;353e and3527..352d preserve r8 under inferred fields' if pc==0x3530 else hex(last[8][0])})
h=(S/'gc_10_3_0_offset.h').read_text();defs=dict(re.findall(r'^#define\s+(mm\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*$',h,re.M))
coords={}
for name,base in [('mmCC_GC_SHADER_ARRAY_CONFIG',0x1260),('mmGC_USER_SHADER_ARRAY_CONFIG',0x1260),('mmCC_GC_SA_UNIT_DISABLE',0x1260),('mmGC_USER_SA_UNIT_DISABLE',0x1260),('mmCC_RB_BACKEND_DISABLE',0x1260),('mmGC_USER_RB_BACKEND_DISABLE',0x1260),('mmRLC_GPM_SCRATCH_ADDR',0xa000),('mmRLC_GPM_SCRATCH_DATA',0xa000)]:
 coords[name]=base+int(defs[name],16)
hits={name:[{'pc':hex(i+0x2000),'word':f'{v:08x}'} for i,v in enumerate(w) if v&0xffff==a] for name,a in coords.items()}
# Address arithmetic of inferred 2x4 loop, without asserting ISA semantics.
instances=[{'sa':sa,'se':se,'scratch_word':2*se+sa,'cc_dword':hex(0x226f|(sa<<25)|(se<<27)),'user_dword':hex(0x2270|(sa<<25)|(se<<27))} for se in range(4) for sa in range(2)]
assert len({x['cc_dword'] for x in instances})==8
windows=[]
for start,end in [(0x3523,0x3555),(0x212e,0x2136),(0x2201,0x2207),(0x313f,0x3157)]:
 windows.extend({'pc':hex(pc),'file_offset':hex(0x200+4*(pc-0x2000)),'word':f'{word(pc):08x}'} for pc in range(start,end))
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'header_sha256':hashlib.sha256(h.encode()).hexdigest(),'coordinates':{k:hex(v) for k,v in coords.items()},'low16_hits':hits,'direct_calls_353e':rows,'inferred_instances':instances,'raw_windows':windows,
'conditional_conclusion':'Under the partial RLCG interpretation,3523 reads CC and USER through353e(r8=0); no known direct353e call selects CC with r8=1. Reverse mode does exist for other registers. This does not close indirect calls, alternate entries, other address encodings, or other firmware segments.',
'next_candidate':'313f programs GPM scratch address0200 and a transfer engine, reached at30bd/3160; trace destination and direction separately.'}
(E/'rlcg-cc-operand-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'direct_calls':len(rows),'raw_words':len(windows),'instances':len(instances),'reverse_mode_registers':sorted({x['hardware_dword'] for x in rows if x['r8']==1})}))
