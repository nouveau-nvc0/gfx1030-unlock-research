#!/usr/bin/env python3
"""Compare the unidentified indexed port with same-generation RTAVFS metadata."""
import hashlib,json,pathlib,re,tarfile
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
paths=[S/'gc_10_3_0_offset.h',S/'gc_10_3_0_sh_mask.h',S/'sienna_cichlid_ip_offset.h']
texts=[p.read_text() for p in paths]
def defs(s):return {k:int(v.rstrip('ULul'),0) for k,v in re.findall(r'^#define\s+(\w+)\s+(0x[0-9a-fA-F]+[ULul]*|[0-9]+)\s*$',s,re.M)}
o,m,base=map(defs,texts);segment=base['GC_BASE__INST0_SEG1'];assert segment==0xa000
names=['REG_ADDR','WR_DATA','RD_DATA','REG_CTRL','REG_STATUS'];offsets=[0,1,3,4,5];ports=[]
for name,off in zip(names,offsets):
 key='mmGRTAVFS_RTAVFS_'+name
 assert o[key+'_BASE_IDX']==1
 public=segment+o[key];assert public==0xeb00+off
 ports.append({'name':key,'public_dword':hex(public),'firmware_operand':hex(0xe800+off),'difference_dwords':public-(0xe800+off)})
fields=['GRTAVFS_RTAVFS_REG_CTRL__SET_WR_EN_MASK','GRTAVFS_RTAVFS_REG_CTRL__SET_RD_EN_MASK','GRTAVFS_RTAVFS_REG_STATUS__RTAVFS_WR_ACK_MASK','GRTAVFS_RTAVFS_REG_STATUS__RTAVFS_RD_DATA_VALID_MASK']
assert [m[x] for x in fields]==[1,2,1,2]
archive=pathlib.Path('/workspace/gfx1030-unlock-research/inputs/research/umr-058a7045-source.tar.gz')
with tarfile.open(archive) as t: data=t.extractfile('database/ip/gc_10_3_0.reg').read()
lines=data.decode().splitlines();selected={}
for i,line in enumerate(lines):
 if line.startswith(('ixRTAVFS_REG2 ','ixRTAVFS_REG33 ','ixRTAVFS_REG97 ')):
  selected[line.split()[0]]=[line]+lines[i+1:i+3]
assert len(selected)==3
r={'source_hashes':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},'umr_member':'database/ip/gc_10_3_0.reg','umr_member_sha256':hashlib.sha256(data).hexdigest(),'ports':ports,'handshake_masks':{x:hex(m[x]) for x in fields},'sample_index_metadata':selected,'findings':['Same-generation RTAVFS has identical relative port positions0/1/3/4/5 and write/read control and status masks1/2.','Public address calculation is unambiguously eb00..eb05 for the selected GC segment, not e800..e805. Structural similarity does not supply the missing address relation.','Selected indexed RTAVFS definitions describe oscillator counters. Do not apply those semantics to e800 indices until a matching address relation is established.','The previous statement that the physical index map is unresolved remains valid. A concrete comparison target now exists, but neither a CC relation nor exclusion is proved.'],'next':'Look for an explicit e800/eb00 address relation or independent same-chip description. Do not broaden this into an assumed RTAVFS identification.','scope':'Offline comparison of pinned same-generation public metadata and prior helper structure; no hardware access.'}
(E/'rlcg-e800-map-comparison.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'ports':len(ports),'matching_control_status_masks':4,'address_difference_dwords':0x300,'identified':False}))
