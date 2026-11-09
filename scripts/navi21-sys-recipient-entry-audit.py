#!/usr/bin/env python3
"""Connect recipient entry installation with a concrete SYS entry candidate."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
def rows(a,z,mode=16):
 c=capstone.Cs(capstone.CS_ARCH_ARM,mode)
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
windows={hex(a):rows(a,z,m) for a,z,m in [(0x26592,0x265c2,16),(0x2514c,0x251b6,16),(0x1fb0,0x1fc0,0),(0x7804,0x786c,16)]}
assert struct.unpack_from('<I',b,0x210)[0]==0xe01eb0
assert struct.unpack_from('<I',b,0x1fcc)[0]==0xe07705
assert struct.unpack_from('<I',b,0x251b8)[0]==0x6054
assert 0x260d0+struct.unpack_from('<I',b,0x26150)[0]==0x26592
assert (0x26150-0x260d0)//4+0x51==0x71
entry=0xe01eb0;delta=0xe00000-0x100
assert entry-delta==0x1fb0 and (0xe07705&~1)-delta==0x7804
r={'firmware_sha256':sha,'windows':windows,
 'entry_installation':'SVC71 checks caller record kind1 and descriptor pointer, then2514c(ID,descriptor). After2310c returns0, it copiesdescriptorDWORD0 torecord[6054]+92*ID+4. Other fields copied separately; kind2 also calls245e8 and recordsID in a globalbyte.',
 'candidate_SYS_mapping':{'runtime_minus_file':hex(delta),'header_entry':'0xe01eb0','candidate_file_entry':'0x1fb0','entry_literal':'0xe07705','candidate_Thumb_entry':'0x7804','basis':'One affine mapping aligns header entry with ARM wrapper and wrapper absolute pointer with coherent Thumb packet handler. Actual image mapping not yet established independently.'},
 'entry_chain':['ARM1fb0 MOVr0,r2;LDRr12literal e07705;BLXr12;SVC75','Thumb7804reads packetselector, copies/initializes0x78-byte local packet subject to state, and forselector>=1000 callsdf94at7854','Selectors1059/1070 therefore reach known SYS dispatcher if entry mapping, state and delivery assumptions hold'],
 'limits':['Producerofimagepointer2060d4 and actual loadedimageidentityremainunproved','Mappinge00000<->file100 is a coherent candidate, not direct runtime observation','Wrapper state atglobal+0c must equal1 for these selectors; its producer remains open','SVC75/frame return and full startup CFG not closed','No changedCCpayload or hardware acceptance'],
 'scope':'Offline exact bytes and conditional linkage only.'}
(E/'sys-recipient-entry-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'instructions':sum(map(len,windows.values())),'candidate_entry':'0xe01eb0','candidate_dispatch_call':'file0x7854 ->0xdf94'}))
