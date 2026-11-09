# VFCT VBIOS selection audit — 9 November 2026

**Confirmed:** this boot loads the `04:00.0` ASRock VBIOS into the driver's BIOS buffer for all three GPUs. The PowerColor at `07:00.0` and ASRock at `0a:00.0` have different, exactly addressed images in VFCT. Their live PowerPlay tables also match the wrong, first image. This is the upstream soft-filter regression discussed in October–November 2026. No flash, driver replacement, boot change, PowerPlay write or frequency adjustment was performed.

## Devices, all VFCT entries, and loaded images

All GPUs are PCI `1002:73bf`, revision `c3`, slot/function `00.0`. Thus vendor/device/slot/function alone cannot distinguish them. DRM card order differs from HIP order.

| Runtime BDF | DRM / HIP | PCI subsystem | VFCT entry offset | VBIOS identified inside that BDF's VFCT image | Image SHA256 alias | Driver actually loaded |
|---|---|---|---:|---|---|---|
| `0000:04:00.0` | card1 / HIP0 | `1849:5204` | 76 / `0x4c` | `113-EXT800240-L04`, ASRock PGD, `020.001.000.060.800240` | A | A, correct entry |
| `0000:07:00.0` | card0 / HIP1 | `148c:2407` | 45160 / `0xb068` | `113-D4140EXL-XL`, TUL/PowerColor, `020.001.000.044.000000` | B | A, wrong entry |
| `0000:0a:00.0` | card2 / HIP2 | `1849:5203` | 90244 / `0x16084` | `113-EXT800241-L04`, ASRock CLP, `020.001.000.060.800241` | C | A, wrong entry |

Full hashes, each over a 45,056-byte ATOM image:

```text
A e258121695fd5ae029132cdcc328e5c34065876a5612e3a2260487ac196a5b5e
B 0ac0bf87efde17a956bd7015667d0eb7689546d75d0a5534c902867fac01b32d
C 94ccebfe9c30cb2377596b5db4d6642cb2e35fd1091aef4382f36530e9418253
```

The ACPI table is 135,356 bytes; its checksum passes. `VBIOSImageOffset=76`, `Lib1ImageOffset=0`. It contains the three nonempty records above, in that order, followed at offset 135,328 by a 28-byte all-zero record with zero image length. This final record is not a fourth GPU image. The VFCT record subsystem fields are zero; the subsystem IDs embedded in the respective ATOM ROM headers match the physical PCI subsystem IDs in the table above.

The cached debugfs `amdgpu_vbios` blobs on **all three cards** hash to A. The read-only offline replay of the installed driver's selection algorithm chooses A for every device. An exact-BDF-first replay instead chooses A/B/C. The independent match between the replay, actual cached blobs, and boot messages makes this a demonstrated selection error, rather than an inference from matching version strings.

Evidence: [selection audit](evidence/navi21-unlock/vfct-selection-audit.json), [VFCT records](evidence/navi21-unlock/vfct-inventory.json), [raw VFCT](evidence/navi21-unlock/acpi-VFCT.bin), [initial inventory and journal](evidence/navi21-unlock/initial/inventory.json). Reproduce offline with:

```bash
python3 scripts/navi21-analyze-vfct.py evidence/navi21-unlock
```

## Boot messages and selection mechanism

Times below are the journal's original `+03:00` timestamps on 9 November:

| BDF | Time | Observed messages |
|---|---|---|
| `04:00.0` | 04:09:21 | `Fetched VBIOS from VFCT`; ATOM version `113-EXT800240-L04` |
| `07:00.0` | 04:09:23 | `VFCT bus number mismatch: table 4 != runtime 7`; then `Fetched VBIOS from VFCT`; ATOM version `113-EXT800240-L04` |
| `0a:00.0` | 04:09:25 | `VFCT bus number mismatch: table 4 != runtime 10`; then `Fetched VBIOS from VFCT`; ATOM version `113-EXT800240-L04` |

The installed code's helper returns success for both an exact bus match and an identity match on a different bus. Its caller copies the first successful entry and exits immediately. The comment says that an exact match is preferred, but the loop does not implement a table-wide preference. It never reaches the later exact entries for buses 7 and 10. The current kernel command line has `pci=disable_acs_redir=...`, with no `pci=realloc` or `assign-busses`. All three current BDFs already have exact VFCT counterparts; bus renumbering is unnecessary to explain this failure.

Running kernel: `7.3.1-1-default`, RPM `kernel-default-7.3.1-1.1`. The downloaded signed openSUSE `kernel-source-7.3.1-1.1.src.rpm` verifies, and its `amdgpu_bios.c` is byte-identical to the inspected source. No packaged patch touching this file was found. Installed kernel package verification produced no differences. See [source audit](evidence/navi21-unlock/kernel-source-audit.json) and [actual source](evidence/navi21-unlock/sources/rpm-amdgpu_bios.c).

## Upstream history and current status

| Date | Upstream evidence | Meaning here |
|---|---|---|
| July 2026 | Commit [`11c141672045ffc0187aa604f2c0f597bc334fb2`](https://github.com/torvalds/linux/commit/11c141672045ffc0187aa604f2c0f597bc334fb2), “Fix VFCT bus number matching with soft filter” | Introduces the permissive match and first-entry failure present locally. Other trees carry a different hash for the corresponding patch; use code and subject as well as hash. |
| 14–15 October | [Original multi-GPU regression discussion](https://mail-archive.com/amd-gfx%40lists.freedesktop.org/msg153318.html) | Describes another board's VBIOS being selected when identical PCI IDs coexist. A proposed restriction of fallback to `pci=realloc` was discussed. |
| 19–27 October | [v4 2/3: Match VFCT using initial PCI bus number](https://lists.openwall.net/linux-kernel/2026/10/27/2266), [full series 176969](https://patchwork.freedesktop.org/series/176969/) | Preserves the firmware-assigned bus number in PCI core, then requires that number in AMDGPU/Radeon. This handles renumbering without accepting an unrelated identical-ID GPU. It depends on the PCI-core patch. |
| 1 November | [Alternative v3: prefer exact bus match](https://lists.openwall.net/linux-kernel/2026/11/01/308) | Scans for an exact current-bus match before using an identity-only fallback. Offline replay selects A/B/C on this host. |
| 2 November | [Alex Deucher's reply](https://lists.openwall.net/linux-kernel/2026/11/02/2165) | Points the alternative patch author to series 176969 as the proper fix. A posted patch is not proof that a running distribution includes it. |
| 9 November, inspected | [Linus tree `7475ea8b5861`, Linux 7.4-rc2](https://github.com/torvalds/linux/blob/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/drivers/gpu/drm/amd/amdgpu/amdgpu_bios.c) | Still contains the permissive first-match path. The checked local source and this pinned upstream source do not contain either correction. Patchwork reports v4 as `New`; that tracker status alone is not the merge audit. |

The API history for October–9 November lists an unrelated A+A SR-IOV VBIOS change; it does not show either VFCT correction. The pinned source inspection is the stronger evidence. Saved messages and API responses are under [sources](evidence/navi21-unlock/sources/).

## Driver buffer versus physical ROM

`/sys/kernel/debug/dri/N/amdgpu_vbios`, `vbios_version` and `amdgpu_firmware_info` describe the image **selected by the driver**. On this boot they cannot establish which firmware is stored in a card's SPI flash.

The three distinct BDF-associated VFCT images are firmware POST copies, with matching board identifiers and plausible vendor strings. They identify the appropriate records for selection. **No independent physical SPI/ROM dump was taken.** Neither equality nor inequality between today's physical flash contents and those POST copies has been proved. Enabling a PCI ROM BAR, accessing indirect ROM-index registers, flash tools and reprobe were outside the requested unchanged-state audit. The evidence does not support saying that all three cards were physically cross-flashed to the ASRock BIOS.

## Clock and power profile explanation

All three live `pp_table` files are 2,470 bytes and hash to:

```text
14be9b474a0a50d5a8e20421b5fece954c39ccd7d3e2b79d9daab8d29cb4b679
```

That is exactly A's PowerPlay table. B's own table hashes to `8c06a2e78a49a180e6d58fbf6a382c34b60ddba26cf1d3af7faae54ee849086c`; C's to `b8ffa94ae79ab19070a8ced6710f47733e527c718113b8c62b6ac61383a3dfd7`.

| BDF | Its VFCT table's AC/DC socket limit | Live driver table / hwmon default | GFX limits in its VFCT table | UCLK levels in its VFCT table |
|---|---:|---:|---|---|
| `04:00.0` | 227 / 227 W | 227 W | 500–2475 MHz | 97, 457, 674, 1000 MHz |
| `07:00.0` | 203 / 203 W | **227 W** | 500–2475 MHz | 97, 457, 674, 1000 MHz |
| `0a:00.0` | 211 / 211 W | **227 W** | 500–2475 MHz | 97, 457, 674, 1000 MHz |

These are socket/PPT limits, not a measurement of total board input power. The wrong profile raises the selected nominal limit by 24 W / 11.82% on PowerColor and 16 W / 7.58% on the CLP relative to their VFCT records. No before/after performance or stability effect was measured.

Frequency distinctions:

- `pp_dpm_sclk` currently shows 500 and 2475 MHz on every card. 2475 is a fine-grained DPM ceiling, not a claim that each RX 6800 sustains that clock or has a 2475 MHz advertised boost. The DPM descriptor explicitly represents a fine-grained range with two endpoints.
- The three **native VFCT tables also have identical frequency arrays**. Misselection explains the shared PowerPlay blob and wrong power limits; it does not establish a difference between their programmed GFX/UCLK endpoints. Different vendor marketing game/boost clocks are a separate quantity.
- Debugfs `PSTATE_SCLK=1825 MHz`, `PSTATE_MCLK=1000 MHz` come from the driver's fixed Sienna Cichlid profiling constants, not the card's measured instantaneous clocks or its marketed game frequency. See [`sienna_cichlid_ppt.h`](evidence/navi21-unlock/sources/sienna_cichlid_ppt.h) and `sienna_cichlid_populate_umd_state_clk()`.
- At idle the SMU reported about 3 MHz SCLK and 96 MHz MCLK. Sysfs presents memory states as 96/456/673/1000 MHz while the firmware table contains 97/457/674/1000; requested table values and SMU-reported clock values differ. These readings do not indicate a CU unlock or a manually selected low clock. All cards remain in `auto`, `BOOTUP_DEFAULT`.

Decoded values, full arrays and source-derived structure offsets: [profiles](evidence/navi21-unlock/power-table-profiles.json), [live clock state](evidence/navi21-unlock/clock-profiles.json), [offset derivation](evidence/navi21-unlock/pptable-offsets.cpp). The SMU table starts at byte 802; its size and the complete PowerPlay size agree with the public Navi21 structures.

## Relation to the CU investigation

This is a separate software initialization defect worth correcting in a future approved maintenance window. It is **not evidence that 20 hidden CUs work**, nor proof that VFCT misselection causes the 60-CU limit. All three BDF-specific VFCT `GFX_INFO` tables and `ASIC_Init` bytecode tables are identical, while the measured SA-disable register differs by card. The active CU maps agree with actual wave execution. A corrected VBIOS selection would be a prerequisite for clean future clock/power comparisons; its effect on CU topology remains untested.
