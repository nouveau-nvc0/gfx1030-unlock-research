#!/usr/bin/env python3
"""Record the conditional producer of the SYS RLC base value."""
import hashlib,json,lzma,pathlib,struct
import capstone
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
b=lzma.decompress(pathlib.Path('/usr/lib/firmware/amdgpu/sienna_cichlid_sos.bin.xz').read_bytes())
sha=hashlib.sha256(b).hexdigest();assert sha=='67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37'
c=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
def rows(a,z):
 r=[{'file_offset':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in c.disasm(b[a:z],a)]
 assert sum(len(bytes.fromhex(x['bytes'])) for x in r)==z-a
 return r
producer=rows(0x14cf8,0x14d8e);convert=rows(0x14808,0x14858)
d={int(x['file_offset'],0):x for x in producer+convert}
for a,op in [(0x14d0e,'0x14d5a'),(0x14d52,'0x14808'),(0x14810,'r7, r2'),(0x14850,'r1, r0, [r7]')]:assert d[a]['operands']==op
literals={hex(a):hex(struct.unpack_from('<I',b,a)[0]) for a in (0x14858,0x14d90,0x14d94,0x14d98)}
assert list(literals.values())==['0x6a1b0','0xff800000','0xe1fbe8','0xe1fca0']
hits=[hex(i) for i in range(len(b)-3) if b[i:i+4]==struct.pack('<I',0xe1fbe8)]
assert hits==['0xdb98','0x14188','0x14d94','0x16a9c','0x1d1ac']
r={'firmware_sha256':sha,'capstone_version':capstone.__version__,'address_convention':'File offsets for code; decoded absolute literal addresses for globals','producer':producer,'conversion_helper':convert,'literals':literals,'all_byte_global_literal_occurrences':hits,
'conditional_dataflow':[
 'At14cf8 r0 points to an incoming64-bit address. Nonzero address branches14d5a and skips the producer.',
 'Zero case initializes two64-bit stack slots to zero; SVC7b called with addressesa570/378c, stack output pointers,size4.',
 'Assuming4-byte results A/B, T=((A<<4)+B)<<20. Add signed64-bit constant -800000 to form X; write X to incoming address storage.',
 'Call14808(Xlow,Xhigh,e1fbe8). It keeps output pointer inr7.',
 'Helper calls SVC7b with6a1b0 and6a15c. Its stack output slot is initialized once; no return-status tests separate these reads.',
 'With values C/D at those read points, output G=X-((C&ffffff)<<24)+((D&ffffff)<<24), modulo2^64; STRD14850 writes G to e1fbe8.',
 'Caller then uses G+200000 as a separate address passed to10f7c; this is not the RLC base+400000 path.'
 ],
'conditional_RLC_expression':'If reads/writes and later base procedure execute as inferred: HYP base=G+400000; ID27 snapshot=G+945000. In this zero-input construction, snapshot=T+145000-((C&ffffff)<<24)+((D&ffffff)<<24), modulo2^64.',
'limits':['SVC7b/7c implementations still untraced','Register identities and units beyond observed arithmetic not independently established','This is one conditional producer, not exhaustive global-write closure','Invocation/order and relationship to driver-provided address remain unproved','No changed mask payload producer or CC acceptance demonstrated'],
'scope':'Offline exact-byte decode and local dataflow. No hardware accesses.'}
# Numeric branch operands avoid dependence on disassembler text formatting.
call_candidates=[]
for mode,step in [(capstone.CS_MODE_THUMB,2),(capstone.CS_MODE_ARM,4)]:
    decoder=capstone.Cs(capstone.CS_ARCH_ARM,mode);decoder.detail=True
    for a in range(0x1000,0x21870-3,step):
        ins=next(decoder.disasm(b[a:a+4],a,count=1),None)
        if ins and ins.mnemonic in ('bl','blx','b.w','b') and ins.operands and ins.operands[0].type==capstone.arm.ARM_OP_IMM and ins.operands[0].imm in (0x1d158,0x14cf8):
            call_candidates.append({'file_offset':hex(a),'mode':mode,'target':hex(ins.operands[0].imm),'bytes':ins.bytes.hex()})
r['numeric_branch_candidates']=call_candidates
r['locator_correction']='Earlier textual comparison expected a leading # on branch targets and missed references. Superseded by numeric operand scan; candidate call sites still require contextual validation.'
(E/'psp-base-producer-audit.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'producer_instructions':len(producer),'conversion_instructions':len(convert),'global_literal_occurrences':len(hits),'output_store':'0x14850'}))
