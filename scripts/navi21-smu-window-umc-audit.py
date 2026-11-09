#!/usr/bin/env python3
"""Offline correspondence of SMU window tables to UMC register coordinates."""
import hashlib
import json
import lzma
import pathlib
import re
import struct

E = pathlib.Path('evidence/navi21-unlock/disassembly-v1')
S = pathlib.Path('evidence/navi21-unlock/sources')
blob = lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes())
sha = hashlib.sha256(blob).hexdigest()
assert sha == '0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
b = blob[512:]
inputs = []
def record(p):
    data = p.read_bytes()
    inputs.append({'path':str(p),'sha256':hashlib.sha256(data).hexdigest()})
    return data.decode()
def define(text, key):
    m = re.search(r'^#define\s+'+re.escape(key)+r'\s+(0x[0-9a-fA-F]+|[0-9]+)(?:[uUlL]*)\b',text,re.M)
    assert m, key
    return int(m[1],0)
off = record(E/'umc_8_7_0_offset.h')
mask = record(E/'umc_8_7_0_sh_mask.h')
ip = record(S/'sienna_cichlid_ip_offset.h')
driver = record(S/'umc_v8_7.c.v6.12')
hdr = record(S/'umc_v8_7.h.v6.12')
base = define(ip,'UMC_BASE__INST0_SEG0')
stride = define(driver,'UMC_8_INST_DIST')
chstride = define(hdr,'UMC_V8_7_PER_CHANNEL_OFFSET_SIENNA')
instances = define(hdr,'UMC_V8_7_UMC_INSTANCE_NUM')
channels = define(hdr,'UMC_V8_7_CHANNEL_INSTANCE_NUM')
assert instances*channels == 16
rows=[]
for table,name in ((0x11f10,'mmUMCCH0_0_GeccErrCntSel'),(0x11f50,'mmUMCCH0_0_GeccErrCnt'),(0x11f90,'mmMCA_UMC_UMC0_MCUMC_STATUST0'),(0x11fd0,'mmMCA_UMC_UMC0_MCUMC_ADDRT0')):
    offset=define(off,name)
    assert define(off,name+'_BASE_IDX')==0
    for i in range(instances):
        for c in range(channels):
            cell=table+4*(i*channels+c)
            actual=struct.unpack_from('<I',b,cell)[0]
            expected=4*(base+offset+stride*i+chstride*c)
            assert actual==expected,(hex(cell),hex(actual),hex(expected))
            rows.append({'table_cell':hex(cell),'register':name,'umc':i,'channel':c,'window_argument':hex(actual),'public_byte_coordinate':hex(expected)})
assert define(mask,'UMCCH0_0_GeccErrCnt__GeccErrCnt_MASK')==0xffff
assert define(mask,'UMCCH0_0_GeccErrCntSel__GeccErrCntCsSel_MASK')==0xf
assert define(mask,'MCA_UMC_UMC0_MCUMC_STATUST0__UECC__SHIFT')==45
assert define(mask,'MCA_UMC_UMC0_MCUMC_STATUST0__CECC__SHIFT')==46
checks=[]
for root in ('018d8','01920','30f50','01fcc','21540','38d10'):
    p=E/'all-entry-candidates'/(root+'.txt')
    text=record(p);n=0
    for line in text.splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
        if m:
            pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[pc:pc+len(raw)]==raw;n+=1
    checks.append({'root':root,'byte_checked_records':n})
scan=json.loads(record(E/'all-entry-store-scan-rsync.json'))
condition_hits=[]
for r in scan['reports']:
    for s in r['stores']:
        if s.get('address') in ('0x69cc','0x3210064'):
            condition_hits.append({'listing':r['listing'],**s})
result={'firmware_sha256':sha,'inputs':inputs,'table_matches':rows,'listing_checks':checks,
        'condition_fixed_stores':condition_hits,
        'scope':'64 initial table coordinates and inspected caller semantics support UMC identity. No universal window map, GC alias, live-state observation, or all-writer closure.',
        'field_correspondence':{'counter_low16':'30f87/30fd6','chip_select_bit0':'30f74..30f7c and30fc4..30fce','status_high_word_mask':'31026/3102e:6000 = UECC45/CECC46'}}
(E/'smu-window-umc-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'matched_coordinates':len(rows),'byte_checked_records':sum(x['byte_checked_records'] for x in checks),'condition_fixed_stores':len(condition_hits)}))
