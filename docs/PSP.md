# PSP, SYS and SOS: delivery versus state mutation

This branch reconstructs image placement and service routing. It does not identify an accepted CC write. SYS/SOS coordinates below are **file offsets**, unlike SMU/LX6 PCs.

## Established local chain

SYS `1d158` programs HYP as `G + 0x400000`; `f0dc` starts RLC. SOS commands `1059/1070` lead to SYS dispatch through the reconstructed SVC `f2` route. Image-pointer and recipient analyses distinguish wrapper offsets, runtime load assumptions and selected service recipients. Actual runtime placement was not observed in this offline work.

The RLC whole-DRAM snapshot at TOC ID27 is conditionally `G + 0x945000`, using offset `0x545000` and HYP=`G+0x400000`. This contains saved CC and the gate but is not a demonstrated source of changed values. See [RLCG](RLCG.md).

## The 28-byte SYS record is not an established CC writer

Operation13 initializes a record at runtime coordinate `e5cc24`, carrying G/H/O/S data. Operation18 copies that record. Preceding code at file `169b4` masks record fields+4/+8. The resulting destination is `H + O + S - 1MiB`; O and S are whole-MiB quantities, and G−H is a multiple of16MiB under the reviewed derivation.

Those constraints give a conditional modulo-MiB non-overlap with the RLC snapshot. They do not prove arbitrary runtime base placement, but they rule out the earlier proposed overlap under the established local operands. The endpoint registers `1e130/1e058/1e05c` map to VCN/MMSCH, not SMU. Indirect hardware effects are not closed; no CC relationship was established.

Do not reopen this record as a changed-LX6-state producer merely because it handles a buffer or uses an indirect service. New evidence must contradict a stated bound or establish an actual cross-component effect.

## Receipts and remaining coverage

| Topic | Evidence |
| --- | --- |
| SYS record layout/operations | [record audit](../evidence/navi21-unlock/disassembly-v1/sys-rlc-record-audit.json), [origin](../evidence/navi21-unlock/disassembly-v1/sys-rlc-record-origin-audit.json) |
| Conditional non-overlap | [overlap audit](../evidence/navi21-unlock/disassembly-v1/sys-rlc-record-overlap-audit.json) |
| Physical endpoint | [endpoint audit](../evidence/navi21-unlock/disassembly-v1/sys-record-endpoint-audit.json) |
| SOS service route | [SVC route](../evidence/navi21-unlock/disassembly-v1/sos-svc-route-audit.json), [f2 recipient](../evidence/navi21-unlock/disassembly-v1/sos-f2-recipient-audit.json) |
| Ownership/lifetime | [buffer ownership](../evidence/navi21-unlock/disassembly-v1/psp-buffer-ownership-audit.json), [staging lifetime](../evidence/navi21-unlock/disassembly-v1/sys-staging-lifetime-audit.json) |

Unknowns include full indirect service coverage, actual runtime ownership and placement, pre-OS CC SA initialization, protection state and hardware acceptance. Source-visible loading order cannot substitute for these observations. No host boot, PSP loading or firmware experiment is scheduled by this repository.
