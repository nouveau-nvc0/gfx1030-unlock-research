# Navi21 invasive experiments — 9 November 2026

**No CU unlock on any of the three boards.** Twenty-three transient register trials were completed: 15 CC writes were ignored, eight USER writes were accepted, and all saved register values were restored. One whole-SA functional control caused a queue hang and an automatic GPU reset. Fresh recovery probes pass on all three cards. [Machine summary](evidence/navi21-unlock/invasive-v1/summary.json) · [final audit](evidence/navi21-unlock/invasive-v1/completion-audit.json).

The user's later instruction, “continue with further invasive experiments” (translated from Russian), authorized this bounded MMIO phase after the earlier read-only/VFCT investigation. It did not cause a firmware flash, OTP programming, kernel replacement or power/clock tuning. Normal balanced GFXOFF holds kept the register aperture accessible; the campaign released its holds at completion.

## CC versus USER: controlled writes on every board

All addresses below are byte offsets in `amdgpu_regs2`. Banked writes use the kernel's locked GRBM selection path. Original values were required before each trial; restoration was verified afterwards. The 21 trials in this table dispatched no compute work.

| Trial, repeated on all three GPUs | PowerColor `07:00.0` target → readback | ASRock `04:00.0`, `0a:00.0` target → readback | Result |
|---|---|---|---|
| CC SA: clear one disabled SA bit, `0x8924` | `0xc01→0x801`, reads `0xc01` | `0x301→0x201`, reads `0x301` | Ignored |
| CC SA: clear low bit0 only | `0xc00→0xc01` | `0x300→0x301` | Ignored |
| CC SA: clear entire SA field and bit0 | `0→0xc01` | `0→0x301` | Ignored |
| USER SA: redundantly disable an already CC-disabled SA, `0x8928` | `0x400→0x400` | `0x100→0x100` | Accepted; effective topology unchanged |
| CC WGP: disable WGP0 in a known active SA, `0x89bc` | `0xffe10001→0xffe00001` | same | Ignored |
| CC WGP: clear low bit0 only | `0xffe00000→0xffe00001` | same | Ignored |
| USER WGP: disable WGP0 in that SA, `0x89c0` | `0x10000→0x10000` in SE0.SH0 only | same in SE1.SH0 only | Accepted; other seven banks remain zero |

The USER positive controls distinguish a working write path from ignored CC writes. The USER bank-isolation controls also establish correct bank addressing on all three cards, despite `GRBM_GFX_INDEX` reading zero. Identical readback from a disabled bank still does not prove that bank's execution units are functional.

The evidence establishes that **these CC fields cannot be changed through the tested ordinary host-MMIO path in the current initialized state**. It does not establish whether OTP, protected firmware, a privileged access mechanism or initialization-time locking supplies that restriction. A failed write is not a universal proof of irreversible fusing. No access-control, SMU, PSP, SPI or RLC bypass was attempted.

## Functional WGP control: actual 60 → 58 → 60 CU

On PowerColor `07:00.0`, a new HIP process ran the existing integer/HW_ID probe before, during and after setting `GC_USER_SHADER_ARRAY_CONFIG=0x10000` in SE0.SH0.

| Phase | Executing WGP | Equivalent CU | SE0.SH0 WGP mask | Exact CPU-checked values | Errors |
|---|---:|---:|---:|---:|---:|
| Before | 30 | 60 | `0x1f` | 6,815,744 | 0 |
| USER WGP0 disabled | 29 | 58 | `0x1e` | 6,815,744 | 0 |
| Restored | 30 | 60 | `0x1f` | 6,815,744 | 0 |

Each phase used three launch shapes and sampled 212,992 waves. Only the selected physical WGP disappeared. No wave appeared on the CC-disabled SE1. [During-control result](evidence/navi21-unlock/invasive-v1/powercolor-user-functional/result.json), [before](evidence/navi21-unlock/invasive-v1/powercolor-functional-before/wave-map.json), [after](evidence/navi21-unlock/invasive-v1/powercolor-functional-after/wave-map.json).

This proves a functioning additive USER mask and real hardware dispatch control; it is a down-harvest control, not an unlock or speed gain. The JSON probe's legacy field `reported_cu` stores `hipDeviceProp_t.multiProcessorCount`, which this runtime reports as **30 WGP**. It remains 30 while actual execution drops to 29 WGP. DRM/KFD/rocminfo report 60 CU. Raw evidence is preserved with its original field name; counts must be interpreted in the right units.

## Whole-SA control: hang, automatic reset and restoration

Only PowerColor was tested. Setting USER SA bit `0x100` disables the previously working SE0.SH0; it does **not** enable or test the missing SE1. The register accepted the value, but the fresh HIP process produced no completed samples within its 30-second bound. During termination of the timed-out probe, queue preemption/quiescence failed and AMDGPU initiated a MODE1 reset.

| Event | UTC |
|---|---|
| USER SA write/readback `0x100` | 11:00:32.613029 |
| Automatic GPU reset begins | 11:01:08.667847 |
| Executor verifies USER restored to zero, CC remains `0xc01` | 11:01:08.753485 |
| Driver reports `GPU reset(1) succeeded!` | 11:01:09.620077 |

The restore occurred after reset initiation and before reset completion. This is not an incident-free rollback. The reset lost that GPU's VRAM contents; no production engine was running. Four `PCIe Bus Error` report lines occurred during the reset's IP-state capture. The final kernel line says `device wedged, but no recovery needed`; subsequent fresh processes nevertheless completed all the recovery checks below. [Events](evidence/navi21-unlock/invasive-v1/powercolor-user-sa-functional/events.jsonl), [precise kernel log](evidence/navi21-unlock/invasive-v1/kernel-final.txt), [rollback result](evidence/navi21-unlock/invasive-v1/powercolor-user-sa-functional/result.json).

The complete 139,171-byte devcoredump was preserved at `/workspace/gfx1030-unlock-research/inputs/research/powercolor-user-sa-devcoredump.bin`, SHA256 `20465938ca797dda4496f4bfaa0854b8b626ba3531ec3273dabf1f4ec01304ec`. [Receipt](evidence/navi21-unlock/invasive-v1/devcoredump.json).

No further topology writes followed this failure. The active-SA executor is now blocked before device access; its end-of-campaign source snapshot is retained in [executed-scripts](evidence/navi21-unlock/invasive-v1/executed-scripts/). Do not repeat it on the ASRock boards. The failure supports treating hot whole-SA changes as incompatible with the current initialized stack; it does not identify the precise initialization dependency or diagnose defective hidden silicon.

## Recovery evidence and final state

- All three GPUs' global and 24 banked register snapshots exactly match the campaign baseline, including zero USER masks. [Final held registers](evidence/navi21-unlock/invasive-v1/final-held-registers.json).
- Nine fresh HW_ID/correctness dispatches observe the original 30 WGP / 60 CU per GPU, with exactly the original WGP and SIMD maps. There are 638,976 wave observations and **20,447,232 exact integer checks, zero errors**. [Recovery wave probe](evidence/navi21-unlock/invasive-v1/recovery-wave-map.json).
- Six fresh stock rocBLAS GEMM/GEMV arms complete on all GPUs; **384 CPU spot checks, zero errors**. [Recovery GEMM](evidence/navi21-unlock/invasive-v1/recovery-gemm.json). These brief controls do not requalify the complete application workload or establish a performance change.
- No further kernel messages appeared after that reset recovery through the final audit. There was one automatic reset in this campaign, no host reboot and no manual GPU reset. Kernel taint remains zero.
- Loaded VBIOS hashes remain A/A/A; the separately proved VFCT defect remains unfixed. Physical SPI ROM was not read or changed.

## What this rules out, and what remains

There is no hidden inner-WGP reserve in the six surviving arrays. Normal CC SA writes, including clearing bit0 and the whole field together, do not open the missing engine on any of these three boards. Working USER controls make that a substantially stronger negative result than a read-only register interpretation.

A further plausible investigation must identify a documented protection/initialization path before changing whole-engine topology. Correct VFCT selection would establish board-correct power/firmware baselines, but is not itself evidence of a CU unlock. A coherent initialization-time driver experiment would require preserving boot recovery, understanding dependent engine/power/scheduler state and testing actual new-WGP outputs. Repeating ignored CC writes or hot whole-SA controls has no current justification. No additional CU, throughput gain or physical fuse irreversibility is claimed.
