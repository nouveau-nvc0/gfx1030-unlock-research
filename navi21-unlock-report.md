# RX 6800 / Navi21 XL CU-unlock investigation

9 November 2026. Initial read-only investigation, followed by explicitly authorized transient MMIO experiments. [Invasive results and reset/recovery](navi21-invasive-report.md) · [inventory and maps](gpu-inventory.md) · [VFCT audit](vfct-audit.md) · [next experiments](next-experiments.md) · [raw evidence](evidence/navi21-unlock/README.md).

## Findings

**No software unlock has been demonstrated on any of these three cards.** The measured 60-CU limit is at the **outer Shader Array disable gate**, not an additional two-WGP restriction within each surviving array. PowerColor disables both arrays of physical SE1; the two ASRock boards disable both arrays of SE0. Every other array contains five executing WGP / ten CU. These are three-SE configurations, despite APIs reporting a physical maximum of four SE.

`CC_GC_SA_UNIT_DISABLE` supplies the nonzero mask; `GC_USER_SA_UNIT_DISABLE` is zero. The kernel calls the CC setting `efuse_setting`, but a register name and read-only mask are **not proof of irreversible physical fusing**. Later writeability tests on all three boards found normal CC SA/WGP writes ignored while USER positive controls worked. No OTP interpretation, disabled-engine execution or physical defect test has established the missing SE's health. It remains unresolved whether an overrideable initialization shadow, a protected firmware setting, irreversible fuses, defective silicon or several of those determine this CC-side mask.

There is also a **confirmed upstream VFCT selection regression**: the driver uses the first board's BIOS/PowerPlay tables for all three cards, despite having a distinct exact-BDF VFCT image for each. This explains wrong selected power limits on two boards; it does not prove a CU-unlock mechanism. Physical SPI contents were not independently read. The VFCT audit applied no changes; the later user instruction separately authorized the transient register experiments below. BIOS selection remains unfixed.

The invasive follow-up completed **23 trials**. PowerColor's USER WGP control gave real **60→58→60 CU**, with zero errors. A hot whole-SA disable caused one automatic GPU reset; the original masks/maps were restored and fresh all-card integer/GEMM checks passed. No added CU or performance gain was obtained. The failed active-SA experiment is blocked from repetition. Full details and limits are in [navi21-invasive-report.md](navi21-invasive-report.md).

## 1. Hardware evidence and iterations

### Initial inventory

The host is openSUSE MicroOS `20261107`, kernel `7.3.1-1-default`, with three `1002:73bf`, revision `c3`, GC `10.3.0` cards. HIP order is `04:00.0`, `07:00.0`, `0a:00.0`; DRM order is `07`, `04`, `0a`. Each has 17,163,091,968 driver-visible VRAM bytes. Host links are respectively Gen3 x4/x16/x8 behind Gen4 x16 endpoints. All three expose 60 CU, 120 SIMD, four maximum SE, two SH per SE and ten maximum CU per SH.

The first source review identified `gfx_v10_3_get_disabled_sa()` as a separate gate preceding WGP enumeration. Actual unbanked MMIO values were `0xc01` on `07:00.0` and `0x301` on `04`/`0a`, with zero USER mask. Decoding bits 15:8 predicted a completely disabled SE1 or SE0. Cached DRM CU bitmaps and RB masks agreed. This changed the investigation from “find extra WGP inside surviving arrays” to “identify whether a whole missing SE can be enabled.”

### Banked reads, independent reader and execution

After authorization for selector-only writes, all eight SE/SH combinations on each GPU were addressed through `amdgpu_regs2`, which serializes bank selection with the driver's `grbm_idx_mutex` and restores broadcast selection. No CC/USER/SPI/RLC value was written during this initial read phase. A separate build of upstream UMR confirmed the register values with exact-name reads.

Within the valid five-WGP span, the CC and USER WGP disable fields are zero everywhere requested; SPI static WGP enable is already `0xffff`. RLC always-on is `3`. It would be incorrect to interpret that last value as only two available WGP: normal computation runs on all five WGP positions per enabled array.

An ordinary HIP shader then read `HW_REG_HW_ID1` while doing exact integer arithmetic. Three launch shapes per board produced 638,976 wave observations and 20,447,232 CPU-checked outputs, with zero errors. All expected WGP and SIMD IDs were seen; none were seen on the disabled SE. Therefore the missing engine is absent from actual dispatch under the current configuration, not just hidden in a printed count. Absence of dispatch does not determine whether its silicon could work after a different initialization.

`GRBM_GFX_INDEX` reads back zero in both readers, including banked reads. The later USER WGP write-isolation test independently confirmed addressing of the selected bank on each GPU. Identical values requested from a disabled bank are still not proof that its physical datapaths work. The global SA mask and actual shader SE IDs provide independent topology evidence. Full maps and addresses are in [gpu-inventory.md](gpu-inventory.md).

### Firmware and VBIOS follow-up

Initially all cached BIOS hashes appeared identical. Returning to the BIOS selection source, then extracting the entire ACPI VFCT, showed that the driver had selected the **wrong record** for two devices. Exact per-BDF images are A/B/C, while actual loaded images and live PowerPlay tables are A/A/A. Source-RPM verification and October–November upstream patches confirm the same first-identity-match bug locally. This finding invalidates treating debugfs BIOS dumps as physical-ROM identity, and makes correcting selection a prerequisite for clean future performance comparisons.

The three proper VFCT images have identical `GFX_INFO` and 99-byte `ASIC_Init` tables, but different PowerPlay tables. `GFX_INFO` is format 2/content 6, with maximum layout 4 SE × 2 SH × 10 CU. Its bytes 44–47 are `0a 04 03 00`; in the later public v3.0 common layout these correspond to 10 WGP/SE, 4 RB/SE and 3 active SE. **That interpretation is provisional:** this kernel does not provide a complete named v2.6 structure and does not use those bytes to populate its CU bitmap. It is a firmware clue, not proof that editing one BIOS byte would activate an engine. The per-card choice of disabled SE still differs under the same selected BIOS. See [the complete VFCT audit](vfct-audit.md).

### Diagnostic incidents and scope

An initial post-stop read on sleeping GPUs returned `0xffffffff` and generated PCIe completion-abort AER. Those values were excluded; the reader now requires the existing balanced operational GFXOFF hold and rejects inaccessible values. An early unanchored UMR name also matched unsupported GRBM save/restore aliases; those reads generated AER and were replaced by anchored exact names. The final exact-register UMR pass produced no kernel messages. No GPU reset occurred in that initial read-only phase. The later invasive whole-SA experiment caused one automatic reset, documented separately; fresh subsequent computation passed on all three boards. These incidents are retained rather than reported as an entirely error-free diagnostic session.

## 2. BC-250 precedent and limits of transfer

The primary [BC-250 repository](https://github.com/duggasco/bc250-40cu-unlock) and its [technical report](https://github.com/duggasco/bc250-40cu-unlock/blob/main/docs/technical-report.md) describe increasing Cyan Skillfish/gfx1013 from 24 to 40 CU. Their controlled workload scales from about 230 to 372 tokens/s at a stated fixed clock. This is reported first-party experimental evidence, not a local replication.

The relevant distinction is between configuration/enumeration and actual dispatch. Their patch clears CC WGP harvesting and enables SPI WGP dispatch; it also writes RLC always-on policy. Independently reported [runtime results](https://github.com/duggasco/bc250-40cu-unlock/issues/9) show that driver enumeration can remain stale while performance increases, and question whether the always-on write is necessary. [Issue 18](https://github.com/duggasco/bc250-40cu-unlock/issues/18) reports 38 usable CU on another specimen. Disabled units are not universally healthy. [bc250-hub](https://github.com/GonzaloLombardi/bc250-hub) provides additional tested procedures and references.

For these Navi21 cards:

| Mechanism | BC-250 evidence | Measured Navi21 state / implication |
|---|---|---|
| Inner WGP harvesting | Three of five WGP positions enabled per array on the reported stock boards | All five eligible within each surviving array; clearing this field exposes no additional positions there |
| Outer SA/SE harvesting | Not the demonstrated bottleneck in that unlock | Both SAs of one SE disabled in `CC_GC_SA_UNIT_DISABLE`; this must be understood first |
| SPI static WGP mask | Reported stock low mask `0x7`, changed to `0x1f` | Already `0xffff`; copying the BC value would not establish an unlock |
| RLC always-on | Written by the patch; necessity disputed by runtime reports | Reads `3`, while all five WGP execute; it is not a CU-count register |
| Driver topology | Can differ from actual runtime dispatch after register changes | DRM/KFD/rocminfo report 60 CU; HIP multiProcessorCount reports 30 WGP. The later USER control changed actual execution to 29 WGP while the HIP property stayed 30 |

The BC report mixes an absolute register index for CC with a relative GC offset for SPI. Here all MMIO addresses were recomputed from actual Navi21 segment bases and public gfx10.3 definitions. No BC unlock script was executed. Its supplied “probe” modes also write RLC unconditionally without restoring that register in the probe branch; they must not be mistaken for a harmless read-only probe.

## 3. Current Linux initialization and dependency chain

The five main implementation files were extracted from the signed source RPM for the installed kernel and matched the inspected downloaded files byte for byte; see [kernel-source-audit.json](evidence/navi21-unlock/kernel-source-audit.json). This avoids assuming that current Linux `master` is the running driver.

1. **Maximum layout and register bases.** IP discovery supplies GC version/base addresses and the GFX-info maximum configuration. [`amdgpu_discovery_get_gfx_info()`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c#L1995) reads maximum SE, WGP/SA, SA/SE and resource limits. A maximum of four SE is an addressable design capability, not a functional test of all four.
2. **Outer gate.** [`gfx_v10_3_get_disabled_sa()`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/amdgpu/gfx_v10_0.c#L10181) ORs the CC and USER SA-disable fields. `gfx_v10_0_get_cu_info()` skips those arrays before selecting their bank and counting WGP. `gfx_v10_0_setup_rb()` skips them too. On this host the CC side alone supplies all missing arrays.
3. **Inner gate.** [`gfx_v10_0_get_wgp_active_bitmap_per_sh()`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/amdgpu/gfx_v10_0.c#L10083) ORs CC and USER inactive-WGP bits and bounds the result by `max_cu_per_sh / 2`. Each enabled WGP expands to two CU bits. `disable_cu` supplies extra USER disables; it is not a supported inverse/unlock parameter. Zero USER bits cannot undo CC bits because the driver combines them with OR.
4. **Initialization order.** [`gfx_v10_0_hw_init()`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/amdgpu/gfx_v10_0.c#L7489) applies golden registers, sets up GRBM remapping, caches CU/RB/TCC configuration, resumes RLC and then CP. Its direct-load path requires SMU firmware before RLC. The observed system loads firmware through PSP paths. There is no ordinary `enable_cu=80` path.
5. **Whole-engine dependencies.** [`gfx_v10_3_program_pbb_mode()`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/amdgpu/gfx_v10_0.c#L10201) changes graphics behavior when both arrays of an SE are disabled. Power-brake sequencing, RLC power gating, CP, RB enumeration and scheduling have separate state. `gfx_v10_cntl_power_gating()` updates RLC power-gating policy. Normal GFXOFF controls only the operational sleep state and does not remove harvesting. Changing a CU bitmap does not establish correct SE clocks, power, cache targets or dispatch.
6. **Cache harvesting.** `gfx_v10_0_tcp_harvest()` programs TCP/SQC targets for certain gfx10.1 revisions. Crucially, the inspected hardware-init call condition **does not include Navi21 gfx10.3.0**. Its existence should not be used to prescribe those writes on this ASIC. TCC masks are separately handled and decode to no disabled TCCs on these cards.
7. **Firmware boundary.** Public driver code exposes CC-side settings as `efuse_setting`; USER settings are additive software masks. It does not document the complete pre-OS producer of CC SA bits, their write protection, or an OTP override protocol. PSP, SMU and RLC firmware participate in initialization/power management. Reading their version numbers and public interface code does not reverse engineer their signed firmware internals. Straps or physical fuse state were not independently decoded, and no claim that VBIOS alone controls CC bits is established.

Relevant register definitions: [`gc_10_3_0_offset.h`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/include/asic_reg/gc/gc_10_3_0_offset.h), [`gc_10_3_0_sh_mask.h`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/include/asic_reg/gc/gc_10_3_0_sh_mask.h), and [`sienna_cichlid_ip_offset.h`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/include/sienna_cichlid_ip_offset.h). Local copies and hashes are in `evidence/navi21-unlock/sources/`.

## 4. API consistency and XL versus XT/XTX

RX 6800/6800 XT/6900 XT use the same Navi21 GC10.3 path; the local PCI ID `73bf` does not uniquely identify the CU bin. The [AMD RDNA2 product comparison](https://gpuopen.com/rdna2/) lists 30/36/40 WGP respectively. Linux selects common Sienna Cichlid ME/PFP/CE/MEC/RLC firmware names for this family rather than an XL-specific 60-CU compute image. The inspected golden-register selection is based on GC IP/ASIC variant, not a public “convert XL to XTX” switch. Board VBIOS/PowerPlay differences matter for limits and initialization but do not demonstrate identical fuse state or healthy disabled blocks.

DRM/KFD/rocminfo and actual baseline execution agree on 60 CU. The probe JSON's legacy `reported_cu` field is HIP `multiProcessorCount`, which reports 30 WGP in this runtime. The later USER control demonstrated that actual execution can change while that cached property remains unchanged:

- DRM returns the cached `cu_info` and derived RB mask. The reader's banked access does not rebuild those caches.
- KFD topology is created from the cached CU information. [`kfd_mqd_manager_v10.c`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/amdkfd/kfd_mqd_manager_v10.c) initializes default static SE masks to all ones; custom CU masks instead pass through the cached-bitmap mapping in [`mqd_symmetrically_map_cu_mask()`](https://github.com/gregkh/linux/blob/v7.3.1/drivers/gpu/drm/amd/amdkfd/kfd_mqd_manager.c#L100). A default queue might therefore behave differently from a supposedly equivalent explicit CU mask after a runtime override.
- HIP/HSA occupancy and launch heuristics use reported properties. Mesa/RADV [`ac_gpu_info.c`](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.5/src/amd/common/ac_gpu_info.c) derives enabled SE and resource sizes from the CU bitmap; scratch sizing and scheduling depend on this data. Merely inflating enumeration can mis-size resources without adding functioning execution units.

A production-capable change would require coherent hardware initialization, kernel/KFD topology and fresh userspace processes/queues, plus correctness tests tied to the newly executing WGP. It is not established whether Navi21 can be changed safely after microcode initialization; an initialization-time change/reprobe may be necessary.

## 5. Other claimed precedents and search result quality

English, Russian and Chinese queries covered Navi21/22/23, RX 6800/XT/6900 XT, Radeon Pro, CC/SA masks, fuse and shader-unlock terms, GitHub issues and modding forums. No reproducible Navi21 XL 60→72/80-CU software unlock was found in the inspected public sources as of 9 November. That is a bounded search result, not proof that no private or obscure method exists.

- [PConline's original RX 6800/XT experiment](https://diy.pconline.com.cn/1386/13862785_all.html) reports a forced XT cross-flash leaving its tested RX 6800 without display. This is a concrete unsuccessful attempt, not a fuse-level analysis. The original Chinese page is saved locally.
- [Hardwareluxx's 2022 discussion](https://www.hardwareluxx.de/community/threads/offizieller-amd-rx6700-rx-6700xt-6750xt-x6800-6800xt-6900xt-6950xt-overclocking-und-modding-thread-wak%C3%BC-luk%C3%BC-ln2.1282285/page-812) discusses firmware restrictions and explicitly lacks a working Navi21 unlock to compare. This is author discussion, not a demonstrated CU gain.
- [Radeon Pro V620 soft unlock](https://github.com/Tamalero/amd-v620-soft-unlock) demonstrates clock/power controls through a patched virtual ROM. It preserves the existing 72 CU; it does not unlock CU. Its warnings about firmware wedges also make it unsuitable as a script to try on these production cards.
- Chinese “unlock” material for RX 6800 and Navi22/6750 GRE frequently concerns power limits or a vendor SKU release. Navi23/W6600 OC-control reports likewise do not establish added working CU. None supplies a validated transferable CC SA bypass here.
- A BIOS version/model-name change, higher clocks, a changed reported CU count, or speculation that all units are fused is insufficient evidence in either direction. BC-250 supplies a real counterexample to the general claim that every CC harvesting setting must be physically irreversible; it does not determine Navi21's behavior.

No XT/XTX card is available locally. The subsequent comparison below adds hash-verified public ROM references; these remain downloaded images, not physical-ROM reads or observed XT hardware behavior.

### 5a. User-supplied Phantom Gaming XT ROM comparison, 9 November

The supplied [TechPowerUp 230822 ROM](https://www.techpowerup.com/vgabios/230822/asrock-rx6800xt-16384-201111-1) is ASRock Phantom Gaming D RX 6800 XT, `113-EXT48025-001`, `020.001.000.042.048025`, subsystem `1849:5202`, build 11 November 2020. Its 1-MiB download matches the page's MD5 `eb1a2335af17acfb6fae15b668436bf9` and SHA1 `ea68adba4a33acbaf27d56e126390e4ae9a8b37b`; computed SHA256 is `ec4674da8cd311a3871b8ca565c5545caabcd359c54796c5f9752d71e9b65331`. These hashes establish the downloaded file's match to that collection entry, not independent vendor authentication.

The primary local baseline is the `04:00.0`/Phantom Gaming RX 6800 VFCT POST copy, also equal to the driver's loaded image, SHA256 `e258121695fd5ae029132cdcc328e5c34065876a5612e3a2260487ac196a5b5e`. Its physical flash remains unread. For complete-ROM comparisons, [TechPowerUp 233900](https://www.techpowerup.com/vgabios/233900/asrock-rx6800-16384-210505) supplies the same non-XT identifier/version `113-EXT800240-L04`/`020.001.000.060.800240`, subsystem `1849:5204`. This second 1-MiB file matches its published MD5 `6f53902fd1d0371bc8808b7b3ad464b7` and SHA1 `7f5860c15d993dc1a856487fd3bc5780a4e133d3`; SHA256 is `6ffb1d8b93b75f9ef3e411b7fafeeca41764edea05aecf010f11ed9423158f40`.

The full non-XT reference's first 45,056 bytes differ from the local POST copy at only four positions: checksum byte `0x21` (`cd→4a`), firmware capability byte `0x880` (`00→01`, POSTED), memory-module ID `0x894` (`00→02`), and MC base high byte `0x898` (`00→80`). Those fields are compatible with POST-time updates; this still does not prove the contents of the card's SPI flash. All other prefix bytes, including GFX_INFO and all seven command tables, match exactly.

| Item | Local RX 6800 POST copy | RX 6800 XT reference |
|---|---|---|
| Board/configuration string | D414 PGD XL | D412 XT |
| GFX_INFO version/size | 2.6 / 88 bytes | 2.6 / 88 bytes |
| GFX_INFO bytes 44–47 | `0a 04 03 00` | `09 04 04 00` |
| Common-layout interpretation, provisional | 10 WGP/SE × 3 SE × 2 = 60 CU | 9 WGP/SE × 4 SE × 2 = 72 CU |
| ASIC_Init | 99 bytes, SHA256 `e38686d6f7b6093da2f9a7c11f929717a5912cc99317bdcb04cd66f5a8f1c45b` | Identical |
| PowerPlay socket limits AC/DC | 227 / 227 W | 272 / 272 W |
| GFX fine-grained table endpoints | 500–2475 MHz | 500–2577 MHz |
| UCLK table | 97/457/674/1000 MHz | Identical |
| VRAM_INFO | 3756 bytes; Micron and Samsung part-number strings | 2676 bytes; Samsung K4ZAF325BM string |

The GFX table differs at **only two bytes**, offsets 44 (`10→9`) and 46 (`3→4`). The active-count interpretation follows the public v3.0 common layout and matches product totals; a complete named v2.6 structure/consumer has not been established. This is evidence of a bin-description difference, not proof that editing it changes CC hardware masks. The inspected generic Linux GFX_INFO reader handles v2.4/v2.7/v3.0 and rejects v2.6; Navi21's actual SA/WGP harvesting is read from CC/USER registers. The frequency endpoints above are DPM limits, not marketed or measured boost clocks. The 45-W higher XT socket limit is independent of CU availability.

All 23 present data tables and seven present command tables were compared by indexed table content rather than absolute ROM offsets. Six command tables are identical, including ASIC_Init, display power gating and SMU clock query. The only differing command, internal index66 (1057 bytes), has ten changed bytes within six instructions: they select WS `0x40`/`0x41` in comparisons, subtraction and a move from FB scratch. No opcode, branch target or explicit MMIO destination is changed in those six instructions. This is not a demonstrated CC-unlock command. Data-dependent effects of common code remain possible. Linear decoding frames 314 instructions per ROM and validates in-table branch targets; it does not execute those instructions or emulate the GPU.

The two complete downloaded ROMs each have 31 `$PSP` directory entries. **29 referenced payloads are byte-identical by size and SHA256**. The two differences are type`0x04`, pointing at the legacy VBIOS at offset0, and type`0x05`, a 256-byte payload. Their identity does not show that common firmware takes the same path with different straps, fuses or tables. Both ROMs also contain x86-64 and AArch64 EFI images; their compressed image bytes differ and their instructions were not disassembled here. Thus identical ASIC_Init/PSP payloads must not be generalized to identical entire preboot code.

**Implication for the early-write hypothesis:** this comparison supplies no identified writable-before-lock window or XT-specific CC-mask write. Combined with the 15 ignored CC writes and working USER controls, the current evidence supports investigating the producer/protection of the outer SA mask before selecting any early-write experiment. It establishes neither physical irreversibility nor healthy disabled engines. BIOS/CSM policy research is an optional initialization control, not an established prerequisite or unlock mechanism. No basis for flashing the XT ROM or motherboard firmware follows from this comparison.

Reproduction: [offline comparator](scripts/navi21-compare-roms.py), [local-copy comparison](evidence/navi21-unlock/xt-rom-comparison-v1/comparison.json), [full-reference comparison](evidence/navi21-unlock/xt-rom-comparison-v1/full-reference-comparison.json), [provenance and checks](evidence/navi21-unlock/xt-rom-comparison-v1/provenance.json). Full public ROMs and collection pages are under `/workspace/gfx1030-unlock-research/inputs/research/xt-rom-comparison-v1/`. No ROM code, register experiment, firmware/NVRAM/driver/boot change or service action was performed during this comparison.

## 6. Hypothesis assessment

| Hypothesis | Supporting evidence | Limiting / contrary evidence | Next discriminator |
|---|---|---|---|
| A. Healthy blocks hidden by software | VFCT selection is demonstrably wrong; CC registers need not be universally irreversible, as BC-250 shows | USER masks already zero; SPI low five bits already enabled; no extra-SE execution; selection correction has not been tested | Approved corrected-selection boot, then compare physical masks and HW_ID dispatch |
| B. Some extra WGP recoverable | One disabled SE contains ten nominal WGP positions; boards disable different engines | Surviving arrays are full; all tested CC writes were ignored; disabled-bank reads do not prove health | Identify a credible initialization/protection path before any new-unit test |
| C. Whole SE disabled | CC SA masks, RB masks, cached CU maps and physical wave IDs agree across all three boards | They establish current disablement, not missing-engine physical functionality or its power state | Coherent initialization/dispatch probe after a demonstrably restorable override |
| D. Irreversible fuse or defective blocks | Nonzero CC mask, zero baseline USER mask, per-board SE choice; tested CC writes ignored | USER controls prove a working write path, but no OTP/protection decode or hidden-engine defect test exists | Documented protection/initialization evidence; ignored normal writes alone do not prove universal impossibility |

## 7. LLM benefit and short baselines

At constant measured clocks and memory speed, ideal arithmetic scaling is 64/60 = **1.0667**, 72/60 = **1.20**, 80/60 = **1.3333**. These are compute ceilings, not predicted token-rate gains. For a fraction `f` of original elapsed time that scales perfectly with CU, Amdahl's bound is `S = 1 / (1 - f + f * 60 / C)`.

| Total CU on one GPU | Ideal compute-only gain | `f=0.8` example | `f=0.5` example | `f=0.1` example |
|---|---:|---:|---:|---:|
| 64 | 6.67% | 5.26% | 3.23% | 0.63% |
| 72 | 20.00% | 15.38% | 9.09% | 1.69% |
| 80 | 33.33% | 25.00% | 14.29% | 2.56% |

These `f` values are illustrative, not measured fractions for an application workload. Compute-bound, sufficiently large GEMM/prefill is the most plausible beneficiary. Small GEMM, dispatch latency, dequantization, CPU work, expert transfers and PCIe bottlenecks reduce gains. Quantized GEMV/decode that streams weights remains bounded by unchanged GDDR6 bandwidth, so extra ALUs alone may give little gain. MTP acceptance and workload differences can change token rates independently.

Navi21's published 256-bit/16-Gbps memory interface gives 512 GB/s; adding CU does not widen it. Infinity Cache capacity is published as 128 MB on XL, XT and XTX and is not automatically increased by enabling an SE. Enabling additional WGP might make more local LDS/VGPR/SQC/TCP resources usable, but per-workgroup LDS limits and per-SIMD occupancy limits do not automatically rise. New engine-local cache and power dependencies remain to be qualified. At the same power cap, more active units can lower clocks and erase an arithmetic advantage.

The short local controls used stock rocBLAS, FP16 inputs with FP32 accumulation/output, five warm-ups and seven timed samples per arm. No topology/clock/power change was applied. GEMM was `4096×512×4096`; GEMV was `16384×1×8192`, with a 256-MiB weight matrix larger than published Infinity Cache. Each arm checked 64 sampled output values against an exact small-integer CPU reference.

| BDF / HIP | GEMM median | GEMM rate | GEMV median | GEMV weight traffic rate | CPU check errors |
|---|---:|---:|---:|---:|---:|
| `04:00.0` / 0 | 1.943819 ms | 8.838 TFLOP/s | 1.522347 ms | 176.330 GB/s | 0 |
| `07:00.0` / 1 | 1.885327 ms | 9.112 TFLOP/s | 1.472715 ms | 182.273 GB/s | 0 |
| `0a:00.0` / 2 | 1.979611 ms | 8.678 TFLOP/s | 1.552838 ms | 172.868 GB/s | 0 |

These brief, automatically clocked diagnostic controls are not a full-model benchmark, peak-bandwidth measurement or proof of a compute bottleneck. The GEMV figure counts matrix bytes per call rather than measured memory-controller traffic. All six arms were run under the currently misselected PowerPlay tables. Existing production qualifications remain historical separate workloads; they were not presented as fresh CU-unlock comparisons.

If only one of three equally loaded GPUs gained CU, aggregate ideal arithmetic capacity would increase by 2.22% / 6.67% / 11.11% for 64/72/80 on that card. This equal-work example is not the actual asymmetric application split. A faster main GPU could matter more for one stage, while the x4 host link could dominate another. A gain on any card is useful evidence and should be evaluated with that board's actual role.

## Answers and stopping boundary

**What currently limits these RX 6800s to 60 CU?** Two disabled SAs forming one entire SE, selected by the CC-side SA mask before WGP enumeration; actual dispatch and RB masks agree.

**Are the disabled blocks demonstrably healthy?** No. Full inner WGP eligibility is a clue about the hierarchy, not a functional test of the missing SE.

**Can software alone remove the restriction?** Not established. Clearing USER masks or copying BC-250 SPI writes has no identified opportunity in the measured state. A protected/possibly fused outer gate and firmware initialization need a different investigation.

**Most promising implementation path?** Establish correct per-board VFCT selection in a coherent kernel maintenance comparison, then investigate a documented initialization/protection path. Runtime CC writeability is now tested and negative on all three boards. Hot whole-SA changes are not a useful next step after the observed reset. Correcting VFCT alone is not an unlock mechanism.

**What was actually executed?** The initial inventory/register/source/VFCT study, nine baseline HW_ID dispatches and six stock rocBLAS arms were followed by 23 transient CC/USER register trials. Fifteen CC writes were ignored; eight USER writes accepted and restored. One WGP control demonstrated real 60→58→60 CU; the whole-SA control timed out and triggered one automatic reset. Recovery verified original masks/maps, 20,447,232 exact integer outputs and 384 GEMM/GEMV spot checks without errors on all three boards. No physical firmware, kernel, clock or power-profile changes were made.

**Current state and remaining limitation?** No CU unlock. Diagnostic holds were released after the trials. Complete-model qualification was not repeated after the reset. Hidden-engine health and the producer/protection of CC masks remain unresolved. See [the invasive report](navi21-invasive-report.md) and [next experiments](next-experiments.md) for the supported boundary.
