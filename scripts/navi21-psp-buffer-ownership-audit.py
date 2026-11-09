#!/usr/bin/env python3
"""Record offline driver evidence separating staging, allocation and RLC base."""
import hashlib,json,pathlib
S=pathlib.Path('evidence/navi21-unlock/sources')
E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
p=S/'amdgpu_psp.c.v6.12'; s=p.read_text(); lines=s.splitlines()
def region(first,last,need):
    text='\n'.join(lines[first-1:last])
    for token in need: assert token in text, (first,last,token)
    return {'first_line':first,'last_line':last,'sha256':hashlib.sha256(text.encode()).hexdigest()}
checks={
 'mp0_11_0_7_configuration':region(162,200,['psp->autoload_supported = true;','case IP_VERSION(11, 0, 7):','psp->boot_time_tmr = false;']),
 'toc_size_return':region(798,816,['psp_copy_fw(psp, psp->toc.start_addr, psp->toc.size_bytes);','*tmr_size = psp->cmd_buf_mem->resp.tmr_size;']),
 'allocation':region(819,860,['!psp->tmr_bo && !psp->boot_time_tmr','pptr = amdgpu_sriov_vf(psp->adev) ? &tmr_buf : NULL;','AMDGPU_HAS_VRAM(psp->adev) ?','AMDGPU_GEM_DOMAIN_VRAM','&psp->tmr_bo, &psp->tmr_mc_addr,']),
 'setup_command':region(762,785,['GFX_CMD_ID_SETUP_TMR','lower_32_bits(tmr_mc)','upper_32_bits(tmr_mc)','buf_size = size']),
 'source_command':region(2663,2680,['fw_mem_mc_addr = ucode->mc_addr','fw_phy_addr_lo = lower_32_bits(fw_mem_mc_addr)','fw_size = ucode->ucode_size','psp_get_fw_type']),
 'returned_destination':region(737,740,['ucode->tmr_mc_addr_lo = psp->cmd_buf_mem->resp.fw_addr_lo;','ucode->tmr_mc_addr_hi = psp->cmd_buf_mem->resp.fw_addr_hi;']),
 'autoload_trigger':region(2856,2865,['AMDGPU_UCODE_ID_RLC_G','psp_rlc_autoload_start(psp)']),
 'autoload_command':region(3176,3190,['GFX_CMD_ID_AUTOLOAD_RLC','psp_cmd_submit_buf(psp, NULL, cmd'])}
command='\n'.join(lines[3175:3190]);assert 'fw_phy_addr' not in command and 'tmr_mc_addr' not in command
assert 'HYP_BOOTLOAD_ADDR' not in s
result={'source':str(p),'source_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'checked_regions':checks,
 'conditional_model':{'assumptions':['retained Linuxv6.12 source path','MP0 11.0.7','ordinary device rather than VF','VRAM present','successful allocation and command completion'],
 'facts':['autoload enabled and boot_time_tmr false in this branch','TOC can determine requested allocation size','driver allocates VRAM and stores GPU address; CPU mapping output is NULL','LOAD_IP_FW names source bytes and type','response supplies a separate per-firmware destination address','AUTOLOAD_RLC command builder supplies no new destination address']},
 'not_established':['active driver load mode or actual addresses','relationship between returned firmware address, allocation base and RLC HYP_BOOTLOAD base','snapshot ID27 ownership within the allocation','CPU access behavior merely from lack of a mapped pointer','a producer of changed saved CC values'],
 'next_code_edge':'PSP placement/initialization that connects per-firmware destination or allocation base to HYP_BOOTLOAD_ADDR. Do not treat staging buffer as live RLC snapshot.',
 'scope':'Offline source analysis. No driver, memory, register or firmware changes.'}
(E/'psp-buffer-ownership-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'source_regions':len(checks),'source_sha256':result['source_sha256'],'direct_HYP_BOOTLOAD_ADDR_references':0}))
