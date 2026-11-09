#!/usr/bin/env python3
"""Reproduce resolved LX6 stores after conservative MOVT/MOVF handling."""
import hashlib,json,lzma,pathlib,re,subprocess,tempfile
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
scanner=pathlib.Path('scripts/navi21-smu-cfg-scan.py')
listing=E/'rlc-iram-functions/027cc.txt'
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_rlc.bin.xz').read_bytes());sha=hashlib.sha256(b).hexdigest()
assert sha=='19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0'
code=b[0xb360:0x1b360];n=0
for line in listing.read_text().splitlines():
 m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s',line)
 if m:
  pc=int(m[1],16);raw=bytes.fromhex(m[2]);assert code[pc:pc+len(raw)]==raw;n+=1
assert code[0x2887:0x288a].hex()=='00dfd3'
out=E/'rlc-27cc-movt-scan.json'
subprocess.run(['python3',str(scanner),str(listing),'--output',str(out)],check=True)
a=json.loads(out.read_text())['reports'][0]
oldpath=E/'rlc-iram-store-scan.json';old=next(x for x in json.loads(oldpath.read_text())['reports'] if x['listing']==str(listing))
assert a['reachable_in_window']==old['reachable_in_window']==171
assert not a['unknown_operations'] and not a['unresolved_or_external_edges']
expected={'0x28c7':'0x5ffee272','0x28d6':'0x5ffee3c5','0x2903':'0x5ffee272','0x2927':'0x5ffee272','0x292c':'0x5ffee272','0x2947':'0x5ffee3c4','0x299b':'0x5ffee3c5'}
previous={x['pc']:x for x in old['stores']};current={x['pc']:x for x in a['stores']}
for pc,address in expected.items():
 assert previous[pc]['address'] is None and current[pc]['address']==address
 assert current[pc]['operation']=='s8i' and int(address,16)!=0x5ffee452
# Synthetic parsed-instruction fixtures test the analysis rule, not firmware.
checks=[]
with tempfile.TemporaryDirectory() as tmp:
 for op in ['movt','movf']:
  for agree in [False,True]:
   source=0x2000 if agree else 0x3000
   text=f'''0000: 000000 movi a2, 0x1000
0003: 000000 movi a3, 0x2000
0006: 000000 movi a4, {hex(source)}
0009: 000000 {op} a3, a4, b0
000c: 000000 s32i a5, a2, 0
000f: 000000 s32i a5, a3, 0
0012: 000000 ret.n
'''
   p=pathlib.Path(tmp)/'fixture.txt';q=pathlib.Path(tmp)/'result.json';p.write_text(text)
   subprocess.run(['python3',str(scanner),str(p),'--output',str(q)],check=True)
   stores=json.loads(q.read_text())['reports'][0]['stores']
   assert stores[0]['address']=='0x1000'
   assert stores[1]['address']==('0x2000' if agree else None)
   checks.append({'operation':op,'alternatives_agree':agree,'unrelated_base_preserved':True,'destination_result':'known' if agree else 'unknown'})
r={'firmware_sha256':sha,'listing_sha256':hashlib.sha256(listing.read_bytes()).hexdigest(),'byte_checked_records':n,'scanner_sha256':hashlib.sha256(scanner.read_bytes()).hexdigest(),'prior_scan_sha256':hashlib.sha256(oldpath.read_bytes()).hexdigest(),'analysis_rule_checks':checks,'resolved_byte_stores':expected,
'finding':'MOVT at2887 changesa13 only; preservea2=5ffee264 anda3=5ffee2e8 across it. Seven stores previously reported unknown resolve to e272/e3c4/e3c5, all outside savedCC and gate.',
'correction':'Branch28dd was already appended to the original listing. This work fixes constant propagation, not a missing decoded branch. Original aggregate scan is retained as historical evidence; new result is separate.',
'limits':'171 locally reached instructions and initial literal mapping do not prove global entry/runtime behavior or all possible writers. Conditional destination remains unknown unless alternatives agree. No hardware access.'}
(E/'rlc-movt-store-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'resolved_byte_stores':len(expected),'rule_checks':len(checks),'locally_reached':a['reachable_in_window']}))
