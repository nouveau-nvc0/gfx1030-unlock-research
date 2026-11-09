# gfx1030-unlock-research

Offline Navi21 / RDNA2 firmware and register research, with measurements from three RX 6800 (gfx1030) boards. **No additional CU has been enabled. Research is paused as of 9 November 2026.** This repository is a handoff and reproducible evidence collection, not an unlock utility.

The observed 60-CU topology is limited by an outer Shader Array gate: both arrays of one Shader Engine are disabled. Surviving arrays already execute all five WGP positions. Fifteen transient CC writes were ignored; USER controls worked, including a measured 60 → 58 → 60 CU cycle. A firmware routine that copies saved CC WGP/RB values back to registers has been identified, but a complete changed-value / invocation / accepted-write chain has not.

## Start here

1. [Agent instructions](AGENTS.md) and [current status](docs/STATUS.md).
2. [Architecture and address conventions](docs/ARCHITECTURE.md).
3. [LX6 CC save/restore and remaining producers](docs/LX6.md), [RLCG transfers and indexed operations](docs/RLCG.md).
4. [SMU command and callback behavior](docs/SMU.md), [PSP/SYS/SOS delivery](docs/PSP.md), [GOP, ATOM and BIOS policy](docs/GOP-BIOS.md).
5. [Prioritized research directions and explicit unknowns](docs/ROADMAP.md).
6. [Toolchain and reproduction](docs/TOOLCHAIN.md), [evidence provenance and limitations](docs/EVIDENCE.md).

## Repository layout

| Path | Purpose |
| --- | --- |
| `docs/` | Curated English explanation of the latest findings, assumptions and open work |
| `scripts/` | Research scripts; categorized by `tools/catalog.json`; some access hardware |
| `tools/` | Portable offline reproduction, integrity checks and script catalog |
| `evidence/navi21-unlock/` | Public receipts, byte listings and register/source evidence; research layout preserved |
| `archive/` | Export inventory and external-input manifest, including omitted binary hashes |
| Root historical reports | Hardware, VFCT, ROM and lab-planning reports; dated conclusions may be superseded by `docs/` |

The full chronological [handoff](evidence/navi21-unlock/disassembly-v1/HANDOFF-2026-11-09.txt) remains available. It records intermediate interpretations and their corrections. Use the curated documents for current conclusions, then follow their receipts for exact addresses and bytes.

## Offline checks

```sh
python3 tools/verify.py
python3 tools/run_offline.py --list
# Requires your own hash-matching firmware inputs; writes only a fresh output directory.
python3 tools/run_offline.py --firmware-dir /path/to/amdgpu --all --output work/replay
```

See the toolchain document for optional dependencies, supported audit scope and external inputs. The default check does not load firmware, access a GPU, change a service, or execute experimental hardware scripts.

## Rights

This collection contains material with different upstream licenses. Original notices are retained; see [NOTICE](NOTICE.md). No blanket license is asserted over firmware-derived listings or third-party material. Firmware images, physical ROM dumps, compiled tools and unrelated deployment configuration are not published here; their available provenance and hashes are retained.
