#!/usr/bin/env python3
"""Audit the concrete RLCG descriptor save path, retaining inferred ISA limits."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack('<6144I',b[0x200:0x6200])
def word(pc):return w[pc-0x2000]
def seq(pc,v):assert [word(pc+i) for i in range(len(v))]==v
seq(0x31e5,[0xc43ffb5c,0x97c0003f,0xd80300eb,0xc0140000,0xc54b0208,0x94800039,0xc54b0209,0x248c0400,0x94c00034])
seq(0x3202,[0xc0361400,0x7f53400a,0xc54b020b,0xc02cffff,0x7ecac009,0x12ec0002,0xc0300000,0xc54b0208,0xc02701ff,0x7e4a4009,0x12640002])
seq(0x3216,[0x53b80020,0x7faa801a,0x7e6a4011,0x56680020,0xc0380000,0x8c0030ae])
seq(0x3221,[0x05540004,0x800031e9,0x8c0035bd,0x8c0035c8,0x90000000])
callers=[hex(i+0x2000) for i,v in enumerate(w) if v==0x8c0031e5];assert callers==['0x2a59','0x2a8c']
p=E/'rlcg-toc-audit.json';toc=json.loads(p.read_text());assert toc['rlc_sha256']==hashlib.sha256(b).hexdigest()
selected=[r for r in toc['entries'] if r['fields']['save_for_vddgfx']]
assert [r['id'] for r in selected]==[23,24,25,26,27,35,36]
h=(S/'gc_10_3_0_sh_mask.h').read_text();defs=dict(re.findall(r'^#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)L?\s*$',h,re.M))
fields={}
command=0x14000000|0x4000
for name in ['BYTE_COUNT','SAS','DAS','SAIC','DAIC','RAW_WAIT','DIS_WC']:
 prefix='CP_DMA_ME_COMMAND__'+name;fields[name]=(command&int(defs[prefix+'_MASK'],0))>>int(defs[prefix+'__SHIFT'],0)
assert fields=={'BYTE_COUNT':16384,'SAS':1,'DAS':0,'SAIC':1,'DAIC':0,'RAW_WAIT':0,'DIS_WC':0}
r=next(r for r in selected if r['id']==27)
assert r['data_register']=='0xfb56' and r['offset_bytes']==0x545000 and not r['fields']['reserved']
raw=[]
for start,end in [(0x31e5,0x3226),(0x3226,0x3234),(0x3247,0x3269),(0x3269,0x3285),(0x3291,0x3297),(0x32b6,0x32c0)]:
 raw.extend({'pc':hex(pc),'word':f'{word(pc):08x}'} for pc in range(start,end))
# Independent exact TOC tail verifies that294 is the two-word table, not0208.
sos=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
assert hashlib.sha256(sos).hexdigest()==toc['sos_sha256']
tail_offset=0x35cd0+(0x294-0x200)*4
pairs=[]
for i in range((0x400-0x250)//8):
 a,v=struct.unpack_from('<II',sos,tail_offset+8*i)
 if a==0:break
 pairs.append({'file_offset':hex(tail_offset+8*i),'word0':hex(a),'word1':hex(v),'register_field':hex((a>>8)&65535),'operation_field':(a>>5)&7})
assert pairs[0]['word0']=='0x24f84047'
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'toc_receipt_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'header_sha256':hashlib.sha256(h.encode()).hexdigest(),'save_entry':'0x31e5','direct_callers':callers,'selected_toc_ids':[r['id'] for r in selected],'id27_candidate':{'source_port_byte':hex(0xfb56*4),'destination_relative':'0x545000','byte_count':16384,'command':hex(command),'public_CP_DMA_ME_field_comparison':fields},'raw_words':raw,'post_toc_pairs':pairs,
'correction':'3226/3269 process two-word register initialization records atGPM294, not four-word snapshot descriptors atGPM208. The actual snapshot producer is31e5.',
'scope':'Direction, address construction and port behavior still depend on partial RLCG ISA interpretation. This path copies existing port data; no transformation of CC masks or gate is visible in the transfer setup. Other producers and runtime buffer contents remain open.'}
(E/'rlcg-dram-save-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'words':len(raw),'save_ids':result['selected_toc_ids'],'callers':callers,'post_toc_pairs':len(pairs),'id27':result['id27_candidate']}))
