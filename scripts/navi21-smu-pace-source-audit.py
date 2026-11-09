#!/usr/bin/env python3
"""Offline provenance of the final sixteen words in the SMU/RLC block."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
S=pathlib.Path('evidence/navi21-unlock/sources')
b= lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
code=b[512:];inputs=[]
for name in ('26748','20768','20820','37110','37750','37098','35448','2c2b0','36fc0','2b1b4'):
 p=E/'all-entry-candidates'/(name+'.txt');data=p.read_bytes();n=0
 for line in data.decode().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(data).hexdigest(),'byte_checked_records':n})
p=S/'smu11_driver_if_sienna_cichlid.h';h=p.read_text()
assert re.search(r'#define\s+TABLE_PACE\s+10\b',h)
assert re.search(r'#define\s+RLC_PACE_TABLE_NUM_LEVELS\s+16\b',h)
assert 'float FlopsPerByteTable[RLC_PACE_TABLE_NUM_LEVELS]' in h
assert 'uint16_t        FlopsPerByteTable[RLC_PACE_TABLE_NUM_LEVELS]; // Q8.8' in h
assert struct.unpack_from('<II',code,0x9ee0)==(0x20820,0x20768)
assert struct.unpack_from('<f',code,0x139fc)[0]==1/256
assert struct.unpack_from('<5I',code,0xcd4c)==(0x2b640,0x2b46c,0x2b1b4,0x2aea0,0xc958)
# Addresses derived from the bounded loops, correlated to the prior RLC copy.
prior=E/'rlc-scratch-consumer-audit.json';copies=json.loads(prior.read_text())['copies']
rows=[]
for i in range(16):
 dst=0xfb38+0x1fc+4*i
 assert dst==0xfd34+4*i
 assert copies[19+i]['candidate_smu_source']==hex(dst)
 rows.append({'entry':i,'main_table_u16_address':hex(0xa1dc+252+2*i),'smu_float_destination':hex(dst),
              'external_table_byte_offset':4*i,'rlc_candidate_destination':copies[19+i]['destination']})
# FP32 representation is lossless for every uint16 scaled by2^-8.
for value in range(65536):
 expected=1.0 if value==0 else value/256
 assert struct.unpack('<f',struct.pack('<f',expected))[0]==expected
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'inputs':inputs,
'public_header':{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()},
'prior_receipt_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),
'callback_table':{'id':10,'record':'0x9ee0','import':'0x20820','export':'0x20768'},
'update_record':{'slot':0,'registration_call':'0x2c37c','record':'0xcd4c','callbacks':['0x2b640','0x2b46c','0x2b1b4','0x2aea0'],'initial_slot_pointer':hex(struct.unpack_from('<I',code,0x15450)[0])},
'rows':rows,'main_table_conversion':'zero ->1.0; nonzero uint16 ->float(value)/256',
'import_size':96,'imported_float_bytes':64,'external_padding_bytes':32,
'quantization_cases_checked':65536,
'scope':'Fixed loop destinations and retained initial callback table; runtime transfer success, complete producer coverage, command32 sender, and later state effects remain open.'}
(E/'smu-pace-source-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'source_rows':len(rows),'byte_checked_records':sum(x['byte_checked_records'] for x in inputs),'conversion_cases':65536,'table_id':10}))
