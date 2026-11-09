#!/usr/bin/env python3
"""Match the SYS record-address endpoint to the local register database."""
import hashlib,json,lzma,pathlib,re,struct,tarfile
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
archive=pathlib.Path('/workspace/gfx1030-unlock-research/inputs/research/umr-058a7045-source.tar.gz')
member='database/ip/vcn_3_0_0.reg'
with tarfile.open(archive) as t: raw=t.extractfile(member).read()
(E/'vcn_3_0_0.reg').write_bytes(raw)
s=raw.decode();regs={}
for line in s.splitlines():
 p=line.split()
 if len(p)==6 and p[0].startswith('mm'):
  regs[p[0]]={'type':int(p[1]),'offset':int(p[2],0),'base_index':int(p[5]),'line':line}
h=(S/'sienna_cichlid_ip_offset.h').read_text()
base=int(re.search(r'#define VCN_BASE__INST0_SEG0\s+(0x[0-9a-fA-F]+)',h)[1],16)
assert base==0x7800
expected={'mmMMSCH_VF_MAILBOX1_DATA':0x1e130,'mmMMSCH_VF_MAILBOX_1':0x1e058,'mmMMSCH_VF_MAILBOX_1_RESP':0x1e05c}
rows=[]
for name,address in expected.items():
 r=regs[name];assert r['type']==0 and r['base_index']==0
 assert (base+r['offset'])*4==address
 rows.append({'name':name,'public_byte_coordinate':hex(address),**r})
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
lits={hex(a):hex(struct.unpack_from('<I',b,a)[0]) for a in [0x14064,0x14068,0x1406c,0x141cc]}
assert lits=={'0x14064':'0x1e05c','0x14068':'0x80000001','0x1406c':'0x80000302','0x141cc':'0x1e130'}
r={'firmware_sha256':sha,'database_archive':str(archive),'database_archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'database_member':member,'database_member_sha256':hashlib.sha256(raw).hexdigest(),'ip_base_source_sha256':hashlib.sha256((S/'sienna_cichlid_ip_offset.h').read_bytes()).hexdigest(),'register_matches':rows,'SYS_literal_words':lits,
'findings':[
 '14190 uses1e130 for high then low words and1e058 for commands1 then2;14018 clears1e05c and polls it for80000001 when writing command register1e058. These three addresses exactly match VCN segment0 MMSCH names, including base-index0.',
 'Do not use UVD_SCRATCH2(offset16,base-index1) or UVD_GPCNT2_TARGET_LOWER(offset4c,base-index1): matching offsets alone selects the wrong segment.',
 'This identifies a VCN/MMSCH register endpoint for the record address. It does not identify the processor-side consumer code or prove command1/2 semantics beyond the observed high/low-word sequence.',
 'The existing SMU channel-table coordinates do not supply this endpoint. A speculative SMU alias based on low-address similarity is unnecessary and unsupported.',
 'Combined with conditional record/snapshot non-overlap, this path is not a demonstrated direct CC producer. Any proposed indirect relationship now requires concrete VCN/MMSCH consumer evidence.'
], 'limits':['Public coordinate match assumes the audited SVC window represents those coordinates; hardware completion was not observed.','A VCN endpoint does not prove all downstream effects are confined to VCN.','No hardware access or configuration changes.'], 'next':'Prioritize known LX6 saved-CC/gate producer gaps; inspect MMSCH only if a concrete record consumer lead emerges.'}
(E/'sys-record-endpoint-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'endpoint':'VCN/MMSCH','register_matches':len(rows),'response':'0x80000001'}))
