#!/usr/bin/env python3
"""Tie the scheduled callback to concrete ff8c transition definitions."""
import hashlib,json,lzma,pathlib,re,struct,collections
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1');b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_smc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest();assert sha=='0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d'
def u32(a):return struct.unpack_from('<I',b,512+a)[0]
roots=['26798','1efa0','1ed28','28b50','25b68','1d554','1ded8','1ddec'];inputs=[];records={}
for root in roots:
 p=E/'all-entry-candidates'/(root+'.txt');n=0
 for line in p.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(.*)',line)
  if m:
   pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert b[512+pc:512+pc+len(raw)]==raw;records[pc]=(m[2],m[3]);n+=1
 inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'records':n})
scanpath=E/'all-entry-store-scan.json';s=json.loads(scanpath.read_text());r=next(x for x in s['reports'] if x['listing'].endswith('/26798.txt'));transitions=[];groups=collections.defaultdict(set)
for c in r['calls']:
 if c.get('target')!='0x25b68':continue
 k=c['integer_constants'];assert k['a10']=='0xff8c'
 group,source,dest=[int(k[a],16) for a in ['a11','a12','a13']]
 assert 'target=0x25b68' in records[int(c['pc'],16)][1]
 groups[group].add((source,dest));transitions.append({'call':c['pc'],'group':group,'source_state':source,'destination_state':dest})
assert len(transitions)==18 and groups[9]=={(0,8)} and groups[1]=={(1,2)}
base=0xff8c;table=u32(base+0x22c);assert table==0x12c50
state_rows=[]
for state in range(9):
 first,last,backfirst,backlast=b[512+base+36*state+32:512+base+36*state+36]
 state_rows.append({'state':state,'forward':[hex(u32(table+4*j)) for j in range(first,last+1)],'reverse':[hex(u32(table+4*j)) for j in range(backfirst,backlast+1)]})
initial=[{'group':g,'mask':hex(u32(base+0x1dc+8*g)),'enabled':b[512+base+0x1e0+8*g]} for g in [9,1]]
assert all(x['mask']=='0x0' and x['enabled']==0 for x in initial)
for pc,raw in {0x1efab:'0c9b',0x1efad:'0c1c',0x1efb6:'0c1b',0x1efb8:'0c1c',0x1ed2d:'324201',0x28b5c:'66181e'}.items():assert records[pc][0]==raw
out={'firmware_sha256':sha,'inputs':inputs,'scan_sha256':hashlib.sha256(scanpath.read_bytes()).hexdigest(),'transition_definitions':transitions,'groups':{str(g):[list(pair) for pair in sorted(pairs)] for g,pairs in groups.items()},'initial_groups_used_by_1efa0':initial,'initial_state_callbacks':state_rows,'findings':['26798 configuresff8c through18 calls to25b68, defining nine distinct state pairs across ten group indices. It does not by itself establish that the group-enable bytes are1 at command time.','Scheduled1efa0 invokes28b50(ff8c,9,1) then28b50(ff8c,1,1). These groups correspond to configured pairs0->8 and1->2.28b50 first requires group-enable byte==1, and only drives state machinery when the requested mask changes.','State8 initial forward callback is1ded8, reverse1ddec. State2 forward callbacks1ed48/1ecb4/1dd54, reverse1ebe0/1ead8/1dd48. These are concrete destinations for further analysis, not proof that a given call reaches them.','1ed28 is a local state signal: writes2 toP+1. It does not itself write CC or change global15874.','Initial group masks/enables arezero. Runtime26798 execution and later enable changes must not be inferred from the presence of the definitions.'],'next':'Trace group9/1 enable producers and the concrete state8/state2 register operations; retain delivery and mask-change conditions.','scope':'Offline transition metadata and local calls only. Other writers, callback completion, hardware address aliases and acceptedCC writes remain unresolved.'}
assert len({(x['source_state'],x['destination_state']) for x in transitions})==9
(E/'smu-ff8c-transition-audit.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'records':sum(x['records'] for x in inputs),'configuration_calls':18,'unique_state_pairs':9,'groups':len(groups)}))
