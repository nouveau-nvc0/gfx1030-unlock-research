#!/usr/bin/env python3
"""Check matched-version source ordering and reuse of the SYS staging buffer."""
import hashlib,json,pathlib
S=pathlib.Path('evidence/navi21-unlock/sources');E=pathlib.Path('evidence/navi21-unlock/disassembly-v1')
p=S/'amdgpu_psp.c.v6.12';q=S/'psp_v11_0.c.v6.12';s=p.read_text();v=q.read_text()
start=s.index('static int psp_hw_start(');end=s.index('static int ',start+20)
flow=s[start:end]
assert flow.index('psp_bootloader_load_sysdrv(psp)')<flow.index('psp_bootloader_load_sos(psp)')
assert 'memset(psp->fw_pri_buf, 0, PSP_1_MEG);' in s[s.index('void psp_copy_fw('):]
assert 'memcpy(psp->fw_pri_buf, start_addr, bin_size);' in s[s.index('void psp_copy_fw('):]
assert 'psp_copy_fw(psp, bin_desc->start_addr, bin_desc->size_bytes);' in v
assert 'psp_copy_fw(psp, psp->sos.start_addr, psp->sos.size_bytes);' in v
assert v.count('(uint32_t)(psp->fw_pri_mc_addr >> 20)')>=2
r={'sources':{str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in (p,q)},'version':'Linuxv6.12 for both files',
 'source_sequence':['On ordinary initialization path, SYS component loading precedes SOS loading','SYS andSOS loaders both supply fw_pri_mc_addr>>20 inC2PMSG36 and their respective command inC2PMSG35','psp_copy_fw clears first1MiB of fw_pri_buf and copies the selected component into that same buffer'],
 'conditional_consequence':'When both loads perform their copies, the driver staging location holdingSYS is reused forSOS. It cannot be assumed to remain a persistentSYS image backing the later fixed-selector loader. Earlier-stage retention/placement is a missing edge, not a proved alias.',
 'guards':['Both loaders may return early ifSOSalreadyalive','Waits and source validity conditions precede submission','psp_copy_fw in retainedv6.12returnsvoid and may return before copying when drm_dev_enter fails; successfulcopy is an explicit assumption'],
 'source_consistency':'Previously retained unversionedpsp_v11_0.c has different copy-return handling. This audit pins v6.12 matchingamdgpu_psp.c; do not combine signatures acrossversions.',
 'open':['Earlier-stage image placement and fielda023c producer','Relationship between retainedSYS bytes and candidateentrymapping','ChangedCCpayload producer/invocation/acceptance'],
 'scope':'Offline source analysis only; no claims about active driver version or execution.'}
(E/'sys-staging-lifetime-audit.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'matched_version':r['version'],'same_staging_buffer':True,'persistent_SYS_alias_proved':False}))
