#!/usr/bin/env python3
"""Bounded RLCG LX6-control inspection; retain generation/ISA limits."""
import hashlib,json,lzma,pathlib,struct,tarfile
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack('<6144I',b[0x200:0x6200]);word=lambda pc:w[pc-0x2000]
hits=[{'word_pc':hex(i+0x2000),'word':hex(v)} for i,v in enumerate(w) if v&65535==0xed80]
assert [x['word_pc'] for x in hits]==['0x2a58','0x2a8b','0x35e3','0x35ec']
for pc in [0x2a58,0x2a8b]:assert [word(pc-1),word(pc),word(pc+1)]==[0xc0080011,0xcc83ed80,0x8c0031e5]
windows={hex(a):[{'pc':hex(pc),'word':f'{word(pc):08x}'} for pc in range(a,z)] for a,z in [(0x2a53,0x2a5b),(0x2a86,0x2a8e),(0x35e3,0x35fa)]}
entry_immediate_candidates={hex(v):[hex(i+0x2000) for i,x in enumerate(w) if x&65535==v] for v in [0x630,0x2edc,0x6f70,0x70d4,0x5fff]}
archive=pathlib.Path('/workspace/gfx1030-unlock-research/inputs/research/umr-058a7045-source.tar.gz')
with tarfile.open(archive) as t:
 raw10=t.extractfile('database/ip/gc_10_3_0.reg').read();raw11=t.extractfile('database/ip/gc_11_0_0.reg').read()
lines=raw11.decode().splitlines();i=next(i for i,l in enumerate(lines) if l.startswith('regRLC_LX6_CNTL '));comparison=lines[i:i+5]
assert comparison[0]=='regRLC_LX6_CNTL 0 0x4d80 4 0 1'
assert not any(l.startswith(('mmRLC_LX6_CNTL ','regRLC_LX6_CNTL ')) for l in raw10.decode().splitlines())
r={'firmware_sha256':sha,'main_RLCG_words':len(w),'literal_ed80_hits':hits,'windows':windows,'entry_low16_candidate_matches':entry_immediate_candidates,
'other_generation_comparison':{'member':'database/ip/gc_11_0_0.reg','sha256':hashlib.sha256(raw11).hexdigest(),'exact_control_record':comparison,'gc10_3_member_sha256':hashlib.sha256(raw10).hexdigest(),'gc10_3_control_name_present':False},
'findings':[
 'Under existing partial RLCG immediate/store interpretation,2a58 and2a8b writeconstant11hex toDWORDed80, immediately before31e5 whole-state save. They do not directly provide an arbitrary LX6 instruction address.',
 'The only other literal low16ed80 matches in6144 main words are reads35e3/35ec in the known command-send/wait helper, each followed by bit0 examination. Computed-address references remain possible.',
 'No low16 immediate-shaped candidates for630,2edc,6f70,70d4 or5fff occur in the main word array. This narrowly excludes these literal fields, not computed execution targets or reset-vector entry.',
 'GC11 names offset4d80/base-index1 RLC_LX6_CNTL withBRESET/RUNSTALL/PDEBUG_ENABLE/STAT_VECTOR_SEL bits0..3. GC10.3 retained database omits that definition. GC11 names are comparison evidence only;11hex includesbit4 not described by that record and must not be assigned a GC10.3 meaning from it.'
],
'next':'Determine actual LX6 reset/vector entry from pinned vector layout or matching-generation definitions; do not treat fixeded80 values as evidence of callable2edc/70d4.',
'limits':'Exact words and candidate fields only; partial RLCG ISA, actual register identity/semantics and hardware behavior remain unconfirmed. No hardware access.'}
(E/'rlcg-lx6-control-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'literal_control_references':len(hits),'fixed_write_value':'0x11','arbitrary_entry_address_demonstrated':False}))
