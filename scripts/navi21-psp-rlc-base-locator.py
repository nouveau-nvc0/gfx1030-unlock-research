#!/usr/bin/env python3
"""Locate the concrete RLC base setup candidate in the offline SYS image."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
assert struct.unpack_from('<HH',b,8)==(1,3)
base=struct.unpack_from('<I',b,24)[0];sos_offset,sos_size=struct.unpack_from('<II',b,36)
assert (base,sos_offset,sos_size)==(0x100,0x21770,0x14360)
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def listing(start,end):
 rows=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[start:end],start)]
 assert sum(len(bytes.fromhex(r['bytes'])) for r in rows)==end-start
 return rows
rows=listing(0x1d158,0x1d1a8);size_rows=listing(0xa808,0xa82c)
by={int(r['file_offset'],0):r for r in rows}
assert by[0x1d164]['operands']=='r2, #0x400000'
assert by[0x1d168]['mnemonic']=='ldrd'
assert by[0x1d16c]['operands']=='r6, r1, r2'
assert by[0x1d170]['operands']=='r1, r0, #0'
assert [r['file_offset'] for r in rows if r['mnemonic']=='svc']==['0x1d176','0x1d18c','0x1d19e']
assert all(by[a]['operands']=='#0x7c' for a in (0x1d176,0x1d18c,0x1d19e))
literals={hex(a):hex(struct.unpack_from('<I',b,a)[0]) for a in range(0x1d1a8,0x1d1b8,4)}
assert list(literals.values())==['0xe5c978','0xe1fbe8','0x3ed78','0xffff0000']
result={'sos_container_sha256':sha,'capstone_version':capstone.__version__,'sys_file_interval':[hex(base),hex(base+sos_offset)],'sos_file_interval':[hex(base+sos_offset),hex(base+sos_offset+sos_size)],'listing_address_convention':'File offsets, not established runtime PCs','procedure':rows,'size_helper':size_rows,'literal_pool':literals,
 'local_dataflow':[
 'Byte at literal-address e5c978+18 gates entry; zero returns a local error value.',
 'Read 64-bit value from literal-address e1fbe8; add400000 with low ADD and high ADC.',
 'SVC7c receives r0=3ed78,r1=high32(base+400000),r2=4.',
 'If prior result is zero, SVC7c receives r0=3ed74,r1=low32(base+400000),r2=4.',
 'If prior result is zero, helpera808 receives1; its result goes to r1 for SVC7c at address3ed70,size4.',
 'Helpera808 extracts a TOC-shaped size field shifted14 then multiplied4, with optional extra shift4 from bit12.'
 ],
 'register_correspondence':{'0x3ed78':'HYP_BOOTLOAD_ADDR_HI (fb5e*4)','0x3ed74':'HYP_BOOTLOAD_ADDR_LO (fb5d*4)','0x3ed70':'HYP_BOOTLOAD_SIZE (fb5c*4)'},
 'conditional_snapshot_expression':'If SVC7c writes these registers and this path executes, ID27 snapshot is relative to (value_at_e1fbe8+400000)+545000 = value_at_e1fbe8+945000.',
 'open':['SVC7c implementation/argument semantics','runtime placement of SYS code and its global data','producer/meaning of64-bit value at e1fbe8 and enable byte','callable entry and execution ordering','relationship to driver allocation and firmware response','changed snapshot producer and CC acceptance'],
 'scope':'Local Thumb decode/dataflow candidate, not runtime or complete call-path proof. No hardware access.'}
(E/'psp-rlc-base-locator.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'procedure_instructions':len(rows),'size_helper_instructions':len(size_rows),'candidate_base_delta':'0x400000','candidate_snapshot_delta':'0x945000'}))
