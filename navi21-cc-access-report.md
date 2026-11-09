# Navi21 CC access policy audit

9 November 2026. Offline/source investigation; no new GPU register accesses, mailbox commands, resets, firmware changes or operational changes. Objective: improve the hypotheses about whether CC can be written at any stage, not claim a demonstrated unlock.

## Conclusion

The strongest supported statement is that the tested initialized Navi21 devices do not accept the tested CPU-MMIO CC changes. No ordinary software blacklist explains those results in the audited access path. The evidence does not distinguish an intrinsically read-only fuse view from a protected shadow loaded by hardware or privileged firmware. No CC-specific lock, unlock sequence, reset domain or writable-before-lock interval has been identified.

An internal producer is not necessarily a software writer. A reset-loaded latch or combinational fuse view can acquire its value without any CPU-writable interval. Even a firmware-writable shadow need never be writable by the host. Conversely, immutable fuse storage does not by itself rule out an override elsewhere. These distinctions prevent both an unjustified impossibility claim and an unjustified promise of an early window.

## Verified access chain

The prior [invasive experiment](navi21-invasive-report.md) performed 15 ignored CC writes and working USER controls on three boards. Both enabling and additional disabling through CC failed; USER WGP manipulation changed actual execution 60→58→60 CU. These controls support correct addressing and functioning writes, not the health of disabled silicon. Readback cannot distinguish a discarded transaction from an immediately reasserted value; the experiment did not capture an internal bus transaction trace.

`amdgpu_debugfs_regs2_op()` calls `amdgpu_mm_wreg_mmio_rlc()`. On a non-VF, an in-aperture write reaches `writel`; there is no CC-address blacklist in that function. Global skip-hardware-access is not a CC-specific explanation, and the accepted USER controls argue against a persistent global skip. Access/virtualization C and header files were compared byte-for-byte with the signed installed-kernel source RPM base; all packaged patch archives were searched for those paths, with no hits. [Audit](evidence/navi21-unlock/cc-access-v1/rpm-access-audit.json), [access implementation](evidence/navi21-unlock/cc-access-v1/amdgpu_reg_access.c).

The name `mmio_rlc` therefore does not mean that the prior CC trials exercised an internal RLC writer. Direct BAR access would not automatically confer different hardware privileges. A different transport or indirect aperture must be shown to change the relevant access policy before being considered an override.

## RLCG: real transport, unproven CC permission

GC10.3.0 initializes scratch register addresses and a Sienna Cichlid-specific spare interrupt for RLCG. However, the normal indirect-access selection depends on SR-IOV VF state and feature permissions supplied by virtualization infrastructure. `amdgpu_sriov_fullaccess` means VF outside runtime; it is not a root-user permission. Ordinary PCI passthrough is not SR-IOV VF creation.

The `gfx_v10_0_rlc_funcs_sriov` table is assigned by IP version to GC10.3.0, including physical cards. Its name/presence alone is not operational support for the mailbox on a consumer RX6800. `is_rlcg_access_range()` currently passes a NULL table and returns false; this is a host routing predicate, not a recovered firmware whitelist.

The common RLCG implementation defines errors for disabled VFGATE, wrong operation and out-of-range registers. Their interpretation/reporting is also conditional on virtualization features. It is not an unrestricted arbitrary-register API. Physical non-VFs load the regular RLC file; VFs skip that load in this function. Consumer firmware mailbox support and accepted CC addresses remain unverified. [Virtualization implementation](evidence/navi21-unlock/cc-access-v1/amdgpu_virt.c), [gates](evidence/navi21-unlock/cc-access-v1/amdgpu_virt.h), [gfx source](evidence/navi21-unlock/sources/gfx_v10_0.c).

RLC safe-mode handshakes and CPC/CPG `GPA_OVERRIDE` are present in initialization/power-management code. No inspected code connects either to CC write permission. Their names are not grounds for trying a CC unlock sequence.

## Register metadata and remapping

Both kernel GC10.3 definitions and UMR describe SA bits15:8 and WGP bits31:16, but do not name bit0. Bit0 must not be labelled a lock, valid or fuse-enable bit from these materials.

UMR's six database columns are name, register type, address, number of bit-field definitions, 64-bit flag and SOC15 segment index. They contain no per-register RO/RW/access-owner classification. Thus `... 1 0 0` is not evidence of write permission or a protection flag. [Metadata](evidence/navi21-unlock/cc-access-v1/umr-cc-metadata.json), [parser](evidence/navi21-unlock/cc-access-v1/umr-read_ip.c).

The Navi21 GRBM CAM initialization maps seven VGT/SPI addresses; none targets CC SA/WGP. No alternate writable CC alias follows from that code. This does not exclude undocumented aliases.

## Firmware evidence and its limits

The on-disk `sienna_cichlid_rlc.bin.xz` decompresses to132960 bytes, header2.4/IP10.3/ucode96, SHA256 `19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0`. This is a disk artifact, not a new attestation of firmware running on each GPU.

Public external register-format/list byte lengths are zero. Separate CNTL/GPM/SRM sections are592/1536/18192 bytes; IRAM/DRAM are66048/16896 bytes. Section bounds were checked against the container. The public header consequently supplies no ready-made list proving CC restoration. `reg_restore_list_size=95` must not be treated as95 decoded host entries. Internal lists/instructions have not been decoded. No searched aligned full32-bit CC/USER address literal occurred; this is only a locator result and cannot exclude encoded operands or indirect addressing. [Container audit](evidence/navi21-unlock/cc-access-v1/rlc-container-audit.json), [format](evidence/navi21-unlock/cc-access-v1/amdgpu_ucode.h).

Linux ATOM MMIO operations call `cail_reg_write()` → `WREG32`. ATOM indirect-I/O bytecode also ultimately uses register callbacks, although an addressed hardware index/data portal could have its own semantics. Executing a command from VBIOS does not inherently provide a privileged internal writer. This traces the Linux interpreter, not all preboot GOP or PSP execution. [Callbacks](evidence/navi21-unlock/cc-access-v1/amdgpu_atombios.c), [interpreter](evidence/navi21-unlock/sources/amdgpu_atom.c).

The inspected Sienna Cichlid SMU message map exposes no identified CC-harvest setter. `AvfsFuseOverride_t` contains voltage/frequency/temperature model coefficients and AVFS module controls; it is not a demonstrated shader fuse override. Absence from this public map does not prove absence of private commands. [Interface](evidence/navi21-unlock/sources/smu11_driver_if_sienna_cichlid.h), [message map](evidence/navi21-unlock/sources/sienna_cichlid_ppt.c).

The earlier [XL/XT comparison](navi21-unlock-report.md#5a-user-supplied-phantom-gaming-xt-rom-comparison-9-november) found identical ASIC_Init and29/31 PSP-directory payloads, but different GFX_INFO descriptors and untraced GOP images. It did not identify a CC writer. Same firmware can branch on chip-specific fuse state; different descriptors can report rather than cause topology. BC-250 and historical Southern Islands writes establish that the CC name is not a universal guarantee of immutability, but do not specify Navi21 access rights.

## Ranked hypotheses and discriminators

| Hypothesis | Evidence assessment | Evidence needed to advance it |
|---|---|---|
| Hardware/fuse-derived CC view, not CPU-writable | Leading conservative model: per-board masks, ignored changes in both directions, functioning USER path; fits all observations | Navi21 access specification or identified hardware producer; current results alone cannot prove permanent fusing |
| Protected shadow, internal writer only | Plausible; common architecture permits it, and RLCG transport exists, but no CC-specific internal write is identified | Decode a genuine CC write and its permissions in relevant firmware, or obtain documented internal access metadata |
| Host-writable shadow before a lock | Possible but currently weaker: no named lock, transition or early accepted write | Identify actual lock/producer and reset domain, then correlate stage-specific observations with that mechanism |
| Firmware continually reasserts CC | Compatible with sampled readback, without positive evidence | Trace an identified rewrite path or demonstrate a transient change; repeated ordinary writes alone do not discriminate |
| VBIOS topology descriptor programs CC | Weak: differing descriptors but identical ASIC_Init; board masks differ under same selected BIOS | Trace descriptor consumer all the way to CC hardware state |
| Linux/debugfs prevents only CC writes | Not supported by the audited path; no such filter found | A missed address-specific layer would have to be demonstrated |

No numerical probabilities are assigned: the observations do not discriminate the first two models sufficiently. “Most conservative” is a choice of working model, not proof of highest physical probability.

## Consequence for future experiments

Do not make motherboard CSM changes, XT ROM delivery or moving a WREG32 earlier prerequisites for a promised unlock. They control some initialization stages but do not establish an accessible pre-lock state. PSP/SMU or reset hardware may establish CC before host PCIe access is possible. A guest boundary, bus reset, MODE1 reset and real power-on are different boundaries.

The next mechanism-led work would require a documented Navi21 CC access/reset specification or decoded relevant firmware producer/permission check. A later authorized stage trace could test whether CC changes during initialization; unchanged values would not distinguish fuse view from early protected shadow. Successful readback would establish only register mutability; new physical SE/WGP execution with correct results would still be required for an unlock claim.

This audit completes the requested evidence-based hypothesis assessment. It does not complete firmware reverse engineering, identify a working override or prove universal physical impossibility. Those are unresolved technical questions, stated explicitly rather than inferred from missing documentation.
