# Navi21 investigation evidence

Initial read-only phase collected 9 November 2026, approximately 09:39–10:13 UTC; authorized invasive follow-up approximately 10:50–11:06 UTC. Reports: [CU investigation](../../navi21-unlock-report.md), [inventory](../../gpu-inventory.md), [VFCT audit](../../vfct-audit.md), [future experiments](../../next-experiments.md).

## Current invasive follow-up

The later user instruction authorized transient MMIO experiments. [Full report](../../navi21-invasive-report.md), [summary](invasive-v1/summary.json), [completion audit](invasive-v1/completion-audit.json) are the current authority. Twenty-three trials, all original register values restored; 15 CC writes ignored on all three boards, eight USER writes accepted. A WGP control demonstrated real 60→58→60 CU. A hot whole-SA control hung and caused **one automatic GPU reset**; do not repeat it. All-card fresh recovery probes passed 20,447,232 exact integer checks and 384 GEMM/GEMV spot checks. Complete-model qualification was not repeated.


## Initial read-only measurements

| Artifact | What it establishes |
|---|---|
| `initial/inventory.json`, `initial/cardN/`, `initial/kfd/` | Live PCI/software inventory, cached topology ioctl bytes, boot GPU journal, driver-selected BIOS, firmware and power snapshots before the active diagnostic phase |
| `global-registers.json` | Valid first global reads while production still owned its normal GFXOFF hold |
| `banked-held-registers.json`, `banked-held-v2.json` | Allowlisted register values with GFXOFF held, all 24 requested banks; v2 includes the selector-readback observation |
| `ip-discovery-gc.json` | Actual GC IP version and register segment bases for all GPUs |
| `cached-cu-maps.json` | Decoded cached DRM CU and RB masks |
| `umr-banked-exact.json` | Independent UMR, 24 banks, **anchored exact register names**; `kernel-after-exact-umr.txt` records no new messages |
| `wave-map.json`, `wave-map/hipN-runN-hwid.bin` | Nine ordinary HIP dispatches, raw HW_ID1 samples, exact integer output counts/errors and full physical WGP/SIMD coverage |
| `gemm-baseline.json`, `gemm-baseline.stderr` | Six short stock rocBLAS baseline arms, seven timings each, 384 sampled CPU-reference output checks; empty stderr |
| `acpi-VFCT.bin`, `vfct-*.bin` | Raw ACPI table and all extracted POST-image entries/subtables; not physical SPI flash dumps |
| `vfct-selection-audit.json` | Offline replay against observed hashes; all VFCT entries including the empty tail, boot messages and explicit physical-ROM limitation |
| `vbios-table-comparison.json` | Per-image ATOM table offsets, revisions, hashes and carefully bounded GFX_INFO interpretation |
| `cardN-pp_table.bin`, `runtime-power-tables.json` | Live selected PowerPlay table bytes/hashes |
| `power-table-profiles.json`, `clock-profiles.json`, `pptable-offsets.{cpp,json}` | Decoded native-versus-selected clock/PPT profiles and structure-offset derivation using public kernel headers |
| `kernel-source-audit.json` | Five implementation files match the signed openSUSE source RPM; packaged patch archives do not alter them |
| `kernel-package-verification.txt` | Empty `rpm -V kernel-default` output |
| `sources/` | Pinned Linux/register sources, upstream messages/API responses, BC-250 primary reports, V620 reports and downloaded original Chinese experiment page |
| `validation.json` | Cross-method consistency checks, numerical totals, final service/hold state, and explicit AER count |
| `sa-readback-poc.json` | Unapplied future plan; no executor and no authorization to change harvesting |

## Initial-phase excluded or limited evidence

`banked-registers.json` was the initial read immediately after stopping production, before acquiring the diagnostic GFXOFF hold. Sleeping cards returned inaccessible `0xffffffff`; these are not harvest masks. `kernel-after-first-mmio.txt` retains the resulting completion-abort AER.

`umr-first-read.txt` / `umr-banked.json` used a register-name expression without anchors. UMR interprets names as regular expressions; the GRBM name also matched `GRBM_GFX_INDEX_SR_DATA` / `SR_SELECT`, producing unsupported reads and additional AER. These aliases are excluded. `sources/umr-scan.c` explains the matching behavior. The subsequent exact-name pass used `^mmNAME$` and produced no new kernel messages. Do not rerun the broad GRBM pattern.

`kernel-final.txt` retains **48 PCIe Bus Error report lines** across those diagnostic episodes. No GPU reset, GPU recovery, GPU-fault or ring-timeout line occurred in the audited research interval. Computation subsequently passed on every GPU. This is not a claim that the entire session produced no hardware error messages.

The first GEMM compilation failed because a local macro variable shadowed an event name; `build-gemm.log` preserves it. `build-gemm-v2.log` is the successful build of the corrected source. No failed binary was run. The baseline rates use automatic clocks/fans, a short warm-up and the currently selected wrong BIOS on two cards; they do not establish peak performance, an unlock gain or a corrected-firmware comparison.

`sources/gfx_v10_0-suse.c` is an exploratory historical openSUSE Git commit, **not** the verified installed source. Use `sources/rpm-*.c` plus `kernel-source-audit.json` for the running distribution. The raw files named `gfx_v10_0.c`, `amdgpu_bios.c` etc. match those extracted RPM files. Moving Linux `master` is not evidence of installed fixes; `amdgpu_bios-7.4-rc2.c` is pinned to `7475ea8b58616b33c04afb976cf0fbaad9dd63fb`.

## Initial read-phase reproduction and scope

Read-only cached inventory:

```bash
sudo python3 scripts/navi21-readonly-inventory.py --output /tmp/navi21-new-inventory
```

This opens no register, ROM-enable or power controls for writing. Hardware register reading is a separate script. It now requires an existing balanced operational GFXOFF hold; `--banked` uses the kernel's normal temporary GRBM selector writes and requires the explicit authorization given in this session. The VFCT-specific no-change instruction was respected; the subsequent invasive authorization is recorded separately above. Do not borrow production's hold and release it while production is active.

Offline audit against this retained evidence:

```bash
python3 scripts/navi21-analyze-vfct.py evidence/navi21-unlock
```


UMR source commit is `058a7045b600886d3cdd46b191886eb8db6a3746`. The tool and its required private Ubuntu ncurses libraries are retained in `tools/`; no system libraries were replaced. A source archive including its register database is retained at `/workspace/gfx1030-unlock-research/inputs/research/umr-058a7045-source.tar.gz`. Runtime needs an extracted database path via `UMR_DATABASE_PATH`, and the private library directory via scoped `LD_LIBRARY_PATH`. No setuid bit was installed. Saved UMR command arguments show the exact reads used.

The 181-MiB signed distribution source RPM and extracted source/patch archives are under `/workspace/gfx1030-unlock-research/inputs/research/`, preserving space in the deployment checkout. `kernel-source-audit.json` records its SHA256 and signature result. No modules were compiled, installed or loaded.


## Public export

This tree contains GPU measurements and firmware-analysis inputs. Unrelated operational records and identifying metadata are excluded. Hash manifests describe this published form. Some original external binaries and tool inputs are represented only by their provenance and digests.
