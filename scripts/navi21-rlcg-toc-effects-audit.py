#!/usr/bin/env python3
"""Bounded table-effect and memory-base selection audit, no runtime assertions."""
import hashlib,json,lzma,pathlib,re,struct
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');S=pathlib.Path('evidence/navi21-unlock/sources')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes())
assert hashlib.sha256(b).hexdigest()=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
w=struct.unpack('<6144I',b[0x200:0x6200])
def word(pc):return w[pc-0x2000]
# Three base selectors share exact shift/mask/equality/branch patterns.
selectors=[]
for pc in (0x3129,0x31bd,0x320f):
 seq=[word(pc+i) for i in range(5)]
 assert seq==[0xc54b0209,0x14880003,0x24880003,0x30880003,0x94800003]
 selectors.append({'pc':hex(pc),'words':[f'{v:08x}' for v in seq],'candidate_condition':'((DW1 >>3)&3)==3 selects011e/011f; otherwise bootloadbase'})
tocp=E/'rlcg-toc-audit.json';toc=json.loads(tocp.read_text())
assert toc['rlc_sha256']==hashlib.sha256(b).hexdigest()
row27=next(r for r in toc['entries'] if r['id']==27)
assert row27['fields']['memory_destination']==2
savep=E/'rlcg-dram-save-audit.json';save=json.loads(savep.read_text())
h=(S/'gc_10_3_0_offset.h').read_text();d=dict(re.findall(r'^#define\s+(mm\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*$',h,re.M));names={}
for k,v in d.items():
 if '_BASE_IDX' not in k and d.get(k+'_BASE_IDX') in ('0','1'):
  names.setdefault(int(v,0)+{'0':0x1260,'1':0xa000}[d[k+'_BASE_IDX']],[]).append(k)
cc={0x2249,0x224a,0x226f,0x2270,0x263d,0x26df}
rows=[]
for r in save['post_toc_pairs']:
 raw=int(r['word0'],0);a=(raw>>8)&65535
 assert a==int(r['register_field'],0) and a not in cc
 rows.append({**r,'names':names.get(a,[]),'value_kind':'literal' if r['operation_field'] in (0,1) else 'base-relative low/high address','select_high_half':bool(raw&16)})
assert len(rows)==40 and sum(bool(r['names']) for r in rows)==39
assert [r for r in rows if r['register_field']=='0xec80'][0]['word1']=='0x3'
hits=[{'pc':hex(i+0x2000),'word':f'{v:08x}'} for i,v in enumerate(w) if v&65535 in (0x11e,0x11f)]
assert len(hits)==6 and all(int(r['word'],16)>>26==0x31 for r in hits)
# Local helper table-source extraction and step are checked as bytes.
anchors={0x3247:0x148c0008,0x3248:0x24ccffff,0x3249:0xc55b0295,0x324a:0x14900005,0x324b:0x25100007,0x3266:0x05540002,0x327e:0x148c0008,0x327f:0x24ccffff,0x3280:0xc55b0295,0x32bd:0x05540002}
for pc,v in anchors.items():assert word(pc)==v
result={'firmware_sha256':hashlib.sha256(b).hexdigest(),'header_sha256':hashlib.sha256(h.encode()).hexdigest(),'input_receipts':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (tocp,savep)},'base_selectors':selectors,'id27_base':'HYP_BOOTLOAD_ADDR_HI/LO under partial ISA reading, not011e/011f','alternate_base_literal_hits':hits,'post_toc_effects':rows,'checked_anchors':{hex(k):hex(v) for k,v in anchors.items()},
'scope':'Known fixed SOS table only. No CC/USER register targets among40pairs. ec80=3 controls SRM but does not supply register-list payload. Ed80 has no retained public name. No proof of all computed writers, live buffer location, table replacement, or hardware acceptance.'}
(E/'rlcg-toc-effects-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'pairs':len(rows),'named_pairs':sum(bool(r['names']) for r in rows),'base_selectors':len(selectors),'alternate_base_literal_reads':len(hits),'id27_class':row27['fields']['memory_destination']}))
