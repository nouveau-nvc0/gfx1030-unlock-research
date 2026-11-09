#!/usr/bin/env python3
"""Offline GPM transfer comparison; retains unproved ISA/address correspondences."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack('<6144I',b[0x200:0x6200])
def word(pc):return w[pc-0x2000]
def seq(pc,values):assert [word(pc+i) for i in range(len(values))]==values
seq(0x313f,[0xc0080200,0xcc83fb75,0xc00cfb76,0x10cc0002,0xccc1c066,0xd801c067,0xcc01c063,0xc0081800,0x10880002,0xc40ffb5e,0x50cc0020,0xc413fb5d,0x7cd0c01a,0x7cc8c011,0x54d00020,0xccc1c064,0xcd01c065,0xc0162800,0x29540400,0xcd41c0e8,0xc433eeec,0x2b300002,0xcf03eeec,0x90000000])
seq(0x35bd,[0xd803ec29,0xc0300000,0xc02c0001,0xc0280000,0xc024ec29,0x12640002,0xc03a4000,0xc036bc00,0x2b740004,0x8c0030ae,0x90000000])
seq(0x30ae,[0x8c0030a6,0xcf01c065,0xcec1c064,0xce81c067,0xce41c066,0xcf81c063,0xcf41c0e8,0x90000000])
seq(0x35c8,[0xc417ec29,0x99400004,0xc0240020,0x8c002872,0x800035c8,0x90000000])
headers={n:(S/n).read_text() for n in ['gc_10_3_0_offset.h','gc_10_3_0_sh_mask.h','gfx_v10_0.c']}
defs=dict(re.findall(r'^#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)L?\s*$',headers['gc_10_3_0_sh_mask.h'],re.M))
def fields(value):
 out={}
 for name in ['BYTE_COUNT','SAS','DAS','SAIC','DAIC','RAW_WAIT','DIS_WC']:
  pre='CP_DMA_ME_COMMAND__'+name
  out[name]=(value&int(defs[pre+'_MASK'],0))>>int(defs[pre+'__SHIFT'],0)
 return out
transfer=(0x2800<<16)|0x400;marker=(0xbc00<<16)|4
assert fields(transfer)=={'BYTE_COUNT':1024,'SAS':0,'DAS':1,'SAIC':0,'DAIC':1,'RAW_WAIT':0,'DIS_WC':0}
assert fields(marker)=={'BYTE_COUNT':4,'SAS':1,'DAS':1,'SAIC':1,'DAIC':1,'RAW_WAIT':0,'DIS_WC':1}
assert ((0x40000000&int(defs['CP_DMA_ME_CONTROL__SRC_SELECT_MASK'],0))>>int(defs['CP_DMA_ME_CONTROL__SRC_SELECT__SHIFT'],0))==2
coords={}
off=dict(re.findall(r'^#define\s+(mm\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*$',headers['gc_10_3_0_offset.h'],re.M))
for name in ['mmRLC_GPM_SCRATCH_ADDR','mmRLC_GPM_SCRATCH_DATA','mmRLC_HYP_BOOTLOAD_ADDR_LO','mmRLC_HYP_BOOTLOAD_ADDR_HI','mmRLC_HYP_BOOTLOAD_SIZE']:
 assert off[name+'_BASE_IDX']=='1';coords[name]=hex(0xa000+int(off[name],0))
callers=[hex(i+0x2000) for i,v in enumerate(w) if v==0x8c00313f];assert callers==['0x30bd','0x3160']
raw=[]
for start,end in [(0x313f,0x3157),(0x35bd,0x35ce),(0x30a6,0x30b6),(0x30b6,0x30c6),(0x3157,0x3169)]:
 raw.extend({'pc':hex(pc),'word':f'{word(pc):08x}','file_offset':hex(0x200+4*(pc-0x2000))} for pc in range(start,end))
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'source_hashes':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in headers.items()},'coordinates':coords,'raw_words':raw,'direct_callers':callers,'comparison_CP_DMA_ME_fields':{'transfer':{'word':hex(transfer),'fields':fields(transfer)},'completion_marker':{'word':hex(marker),'fields':fields(marker),'control':'0x40000000','SRC_SELECT':2}},
'candidate_register_roles':{'c064/c065':'source low/high','c066/c067':'destination low/high','c063':'control','c0e8':'command'},
'candidate_gpm_transfer':{'scratch_start_word':'0x200','port_byte':hex(0xfb76*4),'size_bytes':1024,'scratch_end_word_exclusive':'0x300','source':'bootload HI/LO combined then operation lowcode11 with0x6000; exact arithmetic not independently proved'},
'scope':'CP_DMA_ME field comparison is corroboration, not proof that undocumented c063..c067/c0e8 share every field. Mode/address meanings and runtime delivery remain unobserved. Driver has a matching bootload-address preparation path; current load path not established.'}
(E/'rlcg-gpm-transfer-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'raw_words':len(raw),'callers':callers,'transfer_fields':fields(transfer),'marker_fields':fields(marker)}))
