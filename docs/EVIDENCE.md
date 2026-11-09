# Evidence organization and provenance

The public export preserves the research `evidence/navi21-unlock/` relative layout so scripts, receipts and byte listings remain cross-referenceable. `archive/export-manifest.json` lists included files with byte counts/SHA256 and external inputs with exclusion reasons. This is an export inventory, not a claim that every historical hypothesis is current. Identifying metadata and unrelated operational records have been removed; digests describe the published files.

## Collections

| Directory | Contents / status |
| --- | --- |
| `initial/`, `final/`, root register/driver JSON | Original read-only topology and state observations |
| `wave-map/` | Physical SE/WGP/SIMD execution and integer verification |
| `cc-access-v1/` | Register-access follow-up; distinguish from later invasive trials |
| `invasive-v1/` | 23 transient CC/USER trials, incident, restoration and recovery |
| `bios-policy-plan-v1/` | Reference motherboard policy, mocked instruction replays, provenance |
| `xt-rom-comparison-v1/` | XL/XT comparison and source hashes |
| `disassembly-v1/` | Firmware listings, bounded analyses, original chronological handoff |
| `sources/` | Pinned public driver/register sources and upstream provenance records |
| `tools/UMR-LICENSE` | Original UMR licensing notice; executable omitted |

## Historical coordinates and omitted inputs

Original receipts may contain `/workspace/gfx1030-unlock-research`, `/workspace/gfx1030-unlock-research`, `/tmp/navi21-disasm`, `/tmp/navi21-gop` and `/lab` paths. These are provenance from the investigation, not directories to create or overwrite on another machine. The portable runner adapts a narrowly specified firmware path prefix in memory and operates in a fresh workspace. It does not alter firmware instruction bytes. The publication pass removes unrelated metadata from observational receipts and marks the exported corpus through its manifests.

Complete firmware images, ROM/SPI/VFCT/power-table binary dumps, compiled executables/libraries, presentation images and downloaded HTML/prose are external. Their original hashes and available acquisition metadata remain in the export manifest and source records. Some historical report links therefore refer to external inputs; this is intentional and must not be mistaken for bundled content. No claim is made that a new machine can reproduce private hardware observations without those boards or inputs.

`archive/toolchain/` retains additional BIOS acquisition/tool manifests and an original extraction/disassembly helper. The helper's `/lab` path reflects its original analysis workspace; it is archival, not a default command. Source manifests often contain upstream URLs with pinned commits/tags. When an exact input can no longer be obtained, report it as unavailable rather than substituting current firmware.

## Reproduction boundaries

The portable audit suite verifies selected instructions, operands, hash guards, table arithmetic and existing listing relationships. It consumes archived listings; it does not regenerate all disassembly from scratch, reconstruct all control flow, emulate whole firmware or validate hardware acceptance.

Tests use Python `assert`; never run them with `python -O` or `PYTHONOPTIMIZE`. The runner rejects optimized mode. A passing assertion demonstrates its stated local check only. A newly discovered mapping or decoder correction can change a conclusion without changing the original bytes.

Curated documents supersede earlier speculation in the handoff and root reports. Keep contradictory stages visible with dates and corrections; do not erase failed paths. New research should add new receipts and describe precisely which earlier interpretation changed.
