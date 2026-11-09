#!/usr/bin/env python3
"""Offline decode of missing internal branch targets; preserve alternate starts."""
import json, os, pathlib, re, subprocess, tempfile, argparse
parser=argparse.ArgumentParser()
parser.add_argument('--scan',default='closure-cfg-store-scan.json')
parser.add_argument('--allow-backward', action='store_true', help='Append shared branch bodies before entry; does not change entry')
args=parser.parse_args()
root = pathlib.Path('evidence/navi21-unlock/disassembly-v1')
rx = re.compile(r'\s*([0-9a-f]+):\s+([0-9a-f]{4,6})\s+(\S+)\s*(.*)')
changes = []
for row in json.loads((root/args.scan).read_text())['reports']:
    path = pathlib.Path(row['listing'])
    meta = json.loads(pathlib.Path(str(path)+'.json').read_text())
    start, end = int(meta['start'],16), int(meta['stop'],16)
    known = {int(m[1],16) for line in path.read_text().splitlines() if (m:=rx.match(line))}
    for source, target in row['unresolved_or_external_edges']:
        if not target.startswith('0x'): continue
        target = int(target,16)
        lower = 0 if args.allow_backward else start
        if not lower <= target < end or target in known: continue
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)/'branch.txt'
            kind=meta.get('kind','smu')
            firmware='/usr/lib/firmware/amdgpu/sienna_cichlid_'+('rlc' if kind=='rlc-iram' else 'smc')+'.bin.xz'
            subprocess.run(['python3','scripts/navi21-smu-disassemble.py','--kind',kind,'--firmware',firmware,'--objdump','/tmp/navi21-disasm/binutils/usr/bin/xtensa-lx106-elf-objdump','--start',hex(target),'--stop',hex(end),'--output',str(out)],env=dict(os.environ,PYTHONPATH='/tmp/navi21-disasm/python'),check=True)
            added=[]
            for line in out.read_text().splitlines():
                m=rx.match(line)
                if not m: continue
                pc=int(m[1],16)
                if pc in known: break
                known.add(pc);added.append(line)
            with path.open('a') as f: f.write('\n; Alternate branch-target decode\n'+'\n'.join(added)+'\n')
            changes.append({'listing':str(path),'source':source,'target':hex(target),'added':added})
receipt=root/'branch-target-repairs.json'
old=json.loads(receipt.read_text()) if receipt.exists() else []
receipt.write_text(json.dumps(old+changes,indent=2)+'\n')
print('Repaired',len(changes),'target windows')
