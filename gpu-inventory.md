# GPU inventory and CU maps — 9 November 2026

Measured on the host, with original maps reconfirmed after the invasive phase. [Invasive results/reset/recovery](navi21-invasive-report.md). [Raw inventory](evidence/navi21-unlock/initial/inventory.json), [registers](evidence/navi21-unlock/banked-held-v2.json), [actual wave observations](evidence/navi21-unlock/wave-map.json).

## Platform and software

- openSUSE MicroOS snapshot `20261107`; kernel `7.3.1-1-default`, package `kernel-default-7.3.1-1.1`; AMDGPU is the distribution module. The signed source RPM matches the five inspected kernel implementation files byte for byte; package verification is clean.
- Xeon E5-2696 v4, 44 logical CPUs. Three PCI `1002:73bf`, revision `c3`, GC IP `10.3.0` GPUs; internal ASIC revision `1`, external revision `0x29`, family `0x8f`.
- Host Mesa/RADV `26.2.5-1.1`, libdrm `2.4.134-2.2`, Vulkan loader `1.4.363-1.1`, AMDGPU firmware package `20261031-1.1`.
- The HIP measurement runtime was Ubuntu `26.04.1`, HIP `7.16.26385-0000000`, AMD clang `24.0.0git` at `d6f6cb691863e9258034ab48c1dfce21689d5606`. These versions identify the measurement toolchain.
- UMR was cloned from its actual upstream [repository](https://gitlab.freedesktop.org/tomstdenis/umr) at `058a7045b600886d3cdd46b191886eb8db6a3746` and built in a disposable build workspace, without GUI/LLVM disassembly. The requested `github.com/ROCm/UMR` URL returned 404. No host package installation occurred.

## Board and PCIe identities

| BDF | DRM primary / render | HIP | Subsystem | Board identified by PCI / corresponding VFCT image | Effective host uplink |
|---|---|---:|---|---|---|
| `0000:04:00.0` | card1 / renderD128 | 0 | `1849:5204` | ASRock, PGD XL (`68XL16GPGDO_`) | PCIe Gen3 x4 |
| `0000:07:00.0` | card0 / renderD129 | 1 | `148c:2407` | TUL/PowerColor XL (`L3B16OAM.SMG`) | PCIe Gen3 x16 |
| `0000:0a:00.0` | card2 / renderD130 | 2 | `1849:5203` | ASRock, CLP XL (`68XL16GCLPO_`) | PCIe Gen3 x8 |

All GPU endpoints themselves negotiate **Gen4 x16** to their local bridge. That endpoint reading does not describe the CPU uplink:

| GPU | Upstream path, GPU towards CPU | Narrowest host link |
|---|---|---|
| `04:00.0` | `03:00.0` → `02:00.0` → `00:01.1` | `02:00.0` / root: 8.0 GT/s x4 |
| `07:00.0` | `06:00.0` → `05:00.0` → `00:02.0` | `05:00.0` / root: 8.0 GT/s x16 |
| `0a:00.0` | `09:00.0` → `08:00.0` → `00:03.0` | `08:00.0` / root: 8.0 GT/s x8 |

`rocminfo` BDFIDs are respectively 1024, 1792, 2560, corresponding to these BDFs. All three `rocminfo` agents report Radeon RX 6800, gfx1030, 60 CU, wave32, four **maximum** SE and two SH per SE. HIP `multiProcessorCount` instead reports 30 WGP in this runtime; the wave probe JSON stores it under the legacy name `reported_cu`. KFD exposes 120 SIMD per GPU, two SIMD per CU, eight maximum arrays, ten maximum CU per array, and 64 KiB LDS per CU. Advertised 16 GB VRAM is retained; exact driver-visible byte totals are in the sysfs snapshots.

## VBIOS provenance

The driver-loaded version is `113-EXT800240-L04` on **all three cards**, because of confirmed VFCT misselection. This is not a physical-ROM inventory. The BDF-specific POST copies are:

| BDF | Its VFCT image | Its VFCT image SHA256 prefix | Cached driver image SHA256 prefix | Its table's PPT limit / selected limit |
|---|---|---|---|---|
| `04:00.0` | `113-EXT800240-L04` | `e258121695fd5ae0` | `e258121695fd5ae0` | 227 / 227 W |
| `07:00.0` | `113-D4140EXL-XL` | `0ac0bf87efde17a9` | `e258121695fd5ae0` | 203 / 227 W |
| `0a:00.0` | `113-EXT800241-L04` | `94ccebfe9c30cb23` | `e258121695fd5ae0` | 211 / 227 W |

Full hashes, all VFCT records, boot messages, October–November upstream patches, and clock interpretation are in [vfct-audit.md](vfct-audit.md). Physical SPI ROM contents were not independently read. No claim that the cards were physically cross-flashed follows from debugfs.

## Actual CU/WGP maps

One WGP contains two CU. In the following table each five-character string represents WGP 0–4, left to right. `11111` means all five dispatched work and are present in the cached driver CU map. `00000` means the entire array is disabled and no waves were observed there.

| BDF / card | SE0 SH0 | SE0 SH1 | SE1 SH0 | SE1 SH1 | SE2 SH0 | SE2 SH1 | SE3 SH0 | SE3 SH1 |
|---|---|---|---|---|---|---|---|---|
| `07:00.0` / card0 | `11111` | `11111` | `00000` | `00000` | `11111` | `11111` | `11111` | `11111` |
| `04:00.0` / card1 | `00000` | `00000` | `11111` | `11111` | `11111` | `11111` | `11111` | `11111` |
| `0a:00.0` / card2 | `00000` | `00000` | `11111` | `11111` | `11111` | `11111` | `11111` | `11111` |

Each enabled SH has driver CU bitmap `0x3ff`; each disabled SH has `0x000`. Totals are **3 executing SE × 2 SH × 5 WGP × 2 CU = 60 CU**, on each board. SE3 executes on all cards: the “fourth SE disabled” description means one of four engines, not necessarily physical index 3.

The wave kernel reads shader `HW_REG_HW_ID1` (ID 23), not legacy GCN `HW_ID` (ID 4). Decoding uses public gfx10.3 fields: SIMD bits 9:8, WGP 13:10, SA bit 16, SE 19:18. Three different launch shapes per GPU produced **638,976 wave observations** and **20,447,232 exact CPU-checked integer outputs**, with zero errors and no out-of-range WGP IDs. Every enabled WGP and all four of its SIMD IDs were observed. This confirms execution on the enabled engines; it does not exercise the disabled engine.

## Registers and interpretation

Addresses are byte offsets in AMDGPU's MMIO debugfs aperture. GC segment bases were independently read from each device's IP-discovery sysfs: DWORD bases `0x1260`, `0xa000`, `0x1c000`, `0x2402c00`. The relevant addresses agree with the public Sienna Cichlid definitions.

| Register | Byte offset | card0 `07:00.0` | card1 `04:00.0` | card2 `0a:00.0` |
|---|---:|---:|---:|---:|
| `CC_GC_SA_UNIT_DISABLE` | `0x8924` | `0x00000c01` | `0x00000301` | `0x00000301` |
| `GC_USER_SA_UNIT_DISABLE` | `0x8928` | `0` | `0` | `0` |
| Decoded effective SA-disable bits 15:8 | — | `0x0c` → SE1 SH0/1 | `0x03` → SE0 SH0/1 | `0x03` → SE0 SH0/1 |
| `GB_ADDR_CONFIG` | `0x98f8` | `0x444` | `0x444` | `0x444` |
| `CGTS_TCC_DISABLE` | `0x3c018` | `1` | `1` | `1` |
| `CGTS_USER_TCC_DISABLE` | `0x3c01c` | `0` | `0` | `0` |
| Cached RB mask | — | `0xff0f` | `0xfff0` | `0xfff0` |

TCC disable fields are bits 23:8, **not bit 0**. Therefore value `1` does not mean TCC0 is disabled. The driver-visible TCC disable mask is zero. Each RB mask contains 12 enabled backend pipes out of the physical maximum 16; its missing group agrees with the missing SE.

For every requested bank SE0–3 / SH0–1, on each of the three cards, both the allowlisted reader and the exact-name UMR pass returned:

| Register | Byte offset | Raw value | Correct bounded interpretation |
|---|---:|---:|---|
| `CC_GC_SHADER_ARRAY_CONFIG` | `0x89bc` | `0xffe00001` | WGP disable field `0xffe0`; bits 0–4 of that field are zero, so all five physical WGP positions are eligible before the outer SA gate |
| `GC_USER_SHADER_ARRAY_CONFIG` | `0x89c0` | `0` | No additional user WGP harvesting |
| `SPI_PG_ENABLE_STATIC_WGP_MASK` | `0x935c` | `0x0000ffff` | Low five dispatch bits already enabled; upper bits do not create additional physical WGPs |
| `RLC_PG_ALWAYS_ON_WGP_MASK` | `0x3b14c` | `3` | Always-on policy, not a count of usable WGPs; normal kernels execute on all five WGP positions |
| `CC_RB_BACKEND_DISABLE` | `0x98f4` | `1` | Relevant backend-disable field decodes to zero within the surviving SA |
| `GC_USER_RB_BACKEND_DISABLE` | `0x9b7c` | `0` | No additional user backend mask |

The complete 24-row per-card/per-bank dump is [banked-held-v2.json](evidence/navi21-unlock/banked-held-v2.json); the independent exact-register UMR output is [umr-banked-exact.json](evidence/navi21-unlock/umr-banked-exact.json). Duplicate bank values on disabled SAs do not prove their datapaths are powered or functional. `GRBM_GFX_INDEX` reads back zero even during the banked reads in both tools, so selector readback is not an independent bank-identity proof. The later accepted USER WGP write changed only the targeted bank on each of the three cards, independently confirming bank selection. Actual physical SE identity is established by the wave kernel and global SA mask; PowerColor additionally passed a real 30→29→30-WGP dispatch control.

## Power, firmware, and diagnostic limits

All cards are in automatic DPM with `BOOTUP_DEFAULT`; no manual clocks or fan changes were made. Firmware reports ME `0x40`, PFP `0x6d`, CE `0x25`, RLC `0x60`, MEC/MEC2 `0x86`, SDMA `0x58`, PSP SOS `0x00211164`, SMU `58.91.0`, VCN `0x04121022`, DMCUB `0x02020023`. Per-card full reports are in `initial/cardN/amdgpu_firmware_info.txt`.

AMDGPU reports fine/medium/coarse graphics clock gating, CGCG and relevant memory/ATHUB gating enabled, among other flags; the complete per-card `amdgpu_pm_info` snapshots retain the exact mask. Those flags describe power management capability/state, not a way around SA harvesting. The ordinary operational GFXOFF hold was required for valid register access.

Two diagnostic problems are retained in the evidence. The initial post-stop read lacked that hold on sleeping cards and returned `0xffffffff` with PCIe completion-abort AER. An early UMR register-name pattern also matched `GRBM_GFX_INDEX_SR_*` aliases and produced AER at an unsupported address. Neither is accepted as a harvest mask. Subsequent reads used the hold and anchored exact register names, with no new kernel messages. No reset occurred in that initial read phase. The later hot whole-SA control caused one automatic MODE1 reset on PowerColor; all original global/banked values and executing WGP/SIMD maps were then reconfirmed. Fresh recovery probes on all cards checked 20,447,232 exact integer values and 384 GEMM/GEMV samples with zero errors. This is not complete-model requalification. See [evidence notes](evidence/navi21-unlock/README.md).
