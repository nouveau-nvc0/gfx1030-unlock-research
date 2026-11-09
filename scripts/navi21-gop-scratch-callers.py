#!/usr/bin/env python3
"""Conservative per-function x64 constant flow for direct scratch-write callers."""
import argparse,hashlib,json,sys
from collections import deque
from pathlib import Path
sys.path.insert(0,'/workspace/gfx1030-unlock-research/inputs/research/bios-reference/tools/python')
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
parser=argparse.ArgumentParser()
parser.add_argument('--variant',choices=('baseline','candidate'),default='baseline')
variant=parser.parse_args().variant
writer=0x2cb8 if variant=='baseline' else 0x2ccc
root=Path('evidence/navi21-unlock/disassembly-v1')
inv=json.loads((root/'gop-inventory.json').read_text())
im=next(x for x in inv['images'] if x['variant']==variant and x['machine']=='0x8664')
raw=Path(im['extracted']).read_bytes();assert hashlib.sha256(raw).hexdigest()==im['sha256']
pe=pefile.PE(data=raw);mapped=pe.get_memory_mapped_image()
cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
aliases={}
for group in ('rax eax ax al ah','rbx ebx bx bl bh','rcx ecx cx cl ch','rdx edx dx dl dh','rsi esi si sil','rdi edi di dil','rbp ebp bp bpl','rsp esp sp spl'):
    names=group.split()
    for name in names:aliases[name]=names[0]
for n in range(8,16):
    for suf in ('','d','w','b'):aliases[f'r{n}{suf}']=f'r{n}'
def reg(i,r):return aliases.get(i.reg_name(r),i.reg_name(r))
def transfer(i,state):
    out=dict(state);ops=i.operands
    for r in i.regs_access()[1]:out.pop(reg(i,r),None)
    if i.mnemonic=='call':
        for r in ('rax','rcx','rdx','r8','r9','r10','r11'):out.pop(r,None)
        return out
    if len(ops)>=2 and ops[0].type==X86_OP_REG:
        d,s=ops[:2];v=None
        if i.mnemonic in ('mov','movzx'):
            if s.type==X86_OP_IMM:v=s.imm
            elif s.type==X86_OP_REG:
                v=state.get(reg(i,s.reg))
                if v is not None:v &= (1<<(s.size*8))-1
        elif i.mnemonic=='lea' and s.type==X86_OP_MEM:
            b=state.get(reg(i,s.mem.base)) if s.mem.base else 0
            x=state.get(reg(i,s.mem.index)) if s.mem.index else 0
            if b is not None and x is not None:v=b+x*s.mem.scale+s.mem.disp
        elif i.mnemonic in ('xor','sub') and s.type==X86_OP_REG and d.reg==s.reg:v=0
        # Only full/zero-extending writes create a constant. Partial writes kill it.
        if v is not None and d.size>=4:out[reg(i,d.reg)]=v&((1<<(d.size*8))-1)
    return out
# Guard the transfer rules used by the provenance result with real encodings.
fixtures=[
    ('33db8d73088bce',{},'rcx',8),
    ('b908000000b101',{},'rcx',None),
    ('b908000000e800000000',{},'rcx',None),
    ('be08000000e8000000008bce',{},'rcx',8),
    ('b9080000008b09',{},'rcx',None),
    ('b90800000083c101',{},'rcx',None),
]
for code,initial,target,expected in fixtures:
    state=initial.copy()
    for insn in cs.disasm(bytes.fromhex(code),0x1000):state=transfer(insn,state)
    assert state.get(target)==expected,(code,state)
records=[];function_reports=[];covered=set()
for f in pe.DIRECTORY_ENTRY_EXCEPTION:
    begin,end=f.struct.BeginAddress,f.struct.EndAddress
    ins=list(cs.disasm(mapped[begin:end],begin));by={i.address:i for i in ins}
    sites=[i.address for i in ins if i.mnemonic in ('call','jmp') and i.operands[0].type==X86_OP_IMM and i.operands[0].imm==writer]
    if not sites:continue
    assert sum(i.size for i in ins)==end-begin
    states={begin:{}};q=deque([begin]);gaps=set();steps=0
    while q:
        pc=q.popleft();i=by[pc];st=transfer(i,states[pc]);steps+=1
        nxt=pc+i.size;edges=[]
        if i.group(CS_GRP_RET):pass
        elif i.group(CS_GRP_JUMP):
            if i.operands[0].type==X86_OP_IMM:
                target=i.operands[0].imm
                if begin<=target<end:edges.append(target)
                elif i.mnemonic!='jmp':gaps.add((pc,'conditional exit',target))
            else:gaps.add((pc,'indirect jump',None))
            if i.mnemonic!='jmp':edges.append(nxt)
        else:edges.append(nxt)
        for target in edges:
            if target not in by:
                gaps.add((pc,'missing target',target));continue
            if target not in states:new=st.copy()
            else:new={k:v for k,v in states[target].items() if st.get(k)==v}
            if target not in states or new!=states[target]:states[target]=new;q.append(target)
    for pc in sites:
        value=states.get(pc,{}).get('rcx')
        records.append(dict(site=hex(pc),function=hex(begin),reachable=pc in states,input_index=None if value is None else value&0xffff,
            register_index=None if value is None else (value&0xffff)+0x4c,flow_gaps=len(gaps)))
        covered.add(pc)
    function_reports.append(dict(begin=hex(begin),end=hex(end),instructions=len(ins),iterations=steps,gaps=[(hex(p),s,None if t is None else hex(t)) for p,s,t in sorted(gaps)]))
text=(root/f'gop-{variant}-8664.txt').read_text()
linear_sites={int(line.split(':')[0],16) for line in text.splitlines() if line.endswith((f'call {writer:#x}',f'jmp {writer:#x}'))}
assert covered==linear_sites,(covered^linear_sites)
report=dict(scope='Reference x64 direct references in linear listing, PE runtime-function entry CFG. Calls conservatively kill Microsoft x64 volatile registers; preserved registers assumed ABI compliant. No runtime ROM immutability or alternate-entry proof.',
 variant=variant,writer=hex(writer),image_sha256=im['sha256'],transfer_fixtures_passed=len(fixtures),callers=records,functions=function_reports,
 unresolved=[r for r in records if r['input_index'] is None or r['flow_gaps']],
 cc_matches=[r for r in records if r['register_index'] in (0x2249,0x226f)])
(root/('gop-scratch-callers.json' if variant=='baseline' else 'gop-scratch-callers-candidate.json')).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(sites=len(records),functions=len(function_reports),indices=sorted({r['input_index'] for r in records if r['input_index'] is not None}),unresolved=report['unresolved'],cc_matches=report['cc_matches']),indent=2))
