from pathlib import Path
import json,subprocess
root=Path('/lab');analysis=root/'analysis';db=json.loads((analysis/'module-inventory.json').read_text())
output=analysis/'disassembly';output.mkdir(exist_ok=True)
for variant,names in [('nobeep',['CsmDxe','PciBus','PciPlatform','Bds','Platform','Setup','PlatformEarlyInit']),('mod',['Bds'])]:
 for name in names:
  entry=next(v for v in db[variant].values() if v['name']==name)
  binary=root/Path(entry['file']).relative_to(Path('/workspace/gfx1030-unlock-research/inputs/research/bios-reference'))
  with (output/f'{variant}-{name}.asm').open('w') as f:
   subprocess.run(['objdump','-d','-Mintel',str(binary)],stdout=f,check=True)
  with (output/f'{variant}-{name}.headers').open('w') as f:
   subprocess.run(['objdump','-x',str(binary)],stdout=f,check=True)
print('Disassembled 8 PE modules without executing firmware')
