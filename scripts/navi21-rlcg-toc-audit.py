#!/usr/bin/env python3
"""Extract local SOS TOC and compare its fields with RLCG descriptor operands."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
sos=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
assert hashlib.sha256(sos).hexdigest()=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
assert struct.unpack_from('<HH',sos,8)==(1,3)
payload=struct.unpack_from('<I',sos,24)[0]
ver,off,size=struct.unpack_from('<III',sos,44)
assert (payload,ver,off,size)==(0x100,9,0x35ad0,0x600)
wrapper=payload+off;body=wrapper+0x100
assert sos[wrapper+16:wrapper+20]==b'$PS1'
assert struct.unpack_from('<I',sos,wrapper+20)[0]==0x400
toc=sos[body:body+0x400]
fields=[('load_at_boot',1),('load_at_vddgfx',1),('load_at_reset',1),('memory_destination',2),('vfflr_image_code',4),('load_mode_direct',1),('save_for_vddgfx',1),('save_for_vfflr',1),('reserved',1),('signed_source',1),('size',18)]
h=(S/'amdgpu_rlc.h.v6.12').read_text();part=h[h.index('typedef struct _RLC_TABLE_OF_CONTENT {'):h.index('} RLC_TABLE_OF_CONTENT;')]
for name,width in fields:assert re.search(r'unsigned int\s+'+name+r'\s*:\s*'+str(width)+r'\s*;',part)
rows=[]
for i in range(64):
 a,b,c,d=struct.unpack_from('<4I',toc,16*i)
 if not a:break
 flags={};shift=0
 for name,width in fields:flags[name]=(b>>shift)&((1<<width)-1);shift+=width
 assert shift==32
 rows.append({'id':a>>25,'file_offset':hex(body+i*16),'raw_words':[f'{x:08x}' for x in (a,b,c,d)],'offset_bytes':(a&0x1ffffff)*4,'size_bytes_base_units':flags['size']*4,'fields':flags,'address_register':hex(c&65535),'index':c>>16,'data_register':hex(d&65535),'start_word':d>>16})
assert [r['id'] for r in rows]==list(range(1,37))
assert rows[1]['offset_bytes']==0x6000 and rows[1]['size_bytes_base_units']==0x400
assert rows[1]['address_register']=='0xfb75' and rows[1]['data_register']=='0xfb76' and rows[1]['start_word']==0x200
assert [(rows[i-1]['data_register'],rows[i-1]['size_bytes_base_units']) for i in (10,27)]==[('0xfb56',0x4000)]*2
rlc=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(rlc).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack('<6144I',rlc[0x200:0x6200])
raw=[]
for start,end in [(0x3101,0x313e),(0x3173,0x318a),(0x31a2,0x31d2)]:
 raw.extend({'pc':hex(pc),'word':f'{w[pc-0x2000]:08x}'} for pc in range(start,end))
initial={}
for name,o,n in [('CC_WGP',0x1fc4,32),('CC_RB',0x1fe4,32),('restore_gate',0x2452,1)]:
 value=rlc[0x1b560+o:0x1b560+o+n];assert len(value)==n and not any(value)
 initial[name]={'dram_offset':hex(o),'initial_bytes':value.hex(),'candidate_snapshot_offset':hex(rows[26]['offset_bytes']+o)}
sourcepaths=[S/'amdgpu_rlc.h.v6.12',S/'amdgpu_psp.c.v6.12',S/'gfx_v10_0.c',pathlib.Path('evidence/navi21-unlock/cc-access-v1/amdgpu_ucode.h')]
result={'sos_sha256':hashlib.sha256(sos).hexdigest(),'rlc_sha256':hashlib.sha256(rlc).hexdigest(),'toc_wrapper_file_offset':hex(wrapper),'toc_body_file_interval':[hex(body),hex(body+len(toc))],'toc_body_sha256':hashlib.sha256(toc).hexdigest(),'sources':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sourcepaths},'entries':rows,'raw_rlcg_words':raw,'initial_dram_regions':initial,
'interpretation_limits':['Entries use36 numbered IDs. Linuxv6.12 enum after first10 is not a reliable name map for this Sienna table; keep numeric IDs.','Bit12 is reserved in older struct but firmware uses it for an extra leftshift4 of size: base size units above are not final transfer length for every row.','TOC offset6000 positively corroborates inferred addition in313f but is not an independent proof of all RLCG arithmetic opcodes.','Samefb55/fb56 ports and4000 size identify boot/snapshot descriptor pair by correspondence. Physical LX6 DRAM mapping and actual snapshot contents are not observed.','Initial zero masks with gatezero are not evidence of enabling hardware units.']}
(E/'rlcg-toc-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'toc_body':hex(body),'entries':len(rows),'rlcg_words':len(raw),'dram_entries':[rows[i-1] for i in (10,27)]}))
