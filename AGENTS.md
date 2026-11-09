# Agent handoff

## State and authority

Research is **paused**, by the user's explicit instruction on 2026-11-09. Repository preparation and publication were authorized separately. Reading this repository is not authorization to resume experiments. Do not start a new research goal, GPU job, driver transition, register write, reset, reboot, NVRAM change or firmware update without a new user instruction.

Start with README.md, docs/STATUS.md, docs/ARCHITECTURE.md and docs/ROADMAP.md. The chronological handoff is evidence history, not an executable work queue. Later corrections supersede earlier speculative notes. Keep research and deployment state separate.

## Evidence discipline

- Distinguish measured hardware behavior, byte-checked local code behavior, conditional inference, and unexplored behavior.
- Record firmware SHA256, processor, address space, file-to-runtime mapping, entry assumptions, exact argument values and limits of coverage.
- A literal equal to a register offset is not proof of access to that register. Separate index ports, bit coordinates, VRAM addressing and direct MMIO.
- A static write instruction is not proof that the hardware accepts a write. A saved-state copy is not a producer of a changed mask.
- Failed lookup searches and linear disassembly are not complete call graphs. Preserve undecoded gaps, indirect entries, mutable tables and asynchronous callbacks.
- Do not promote an initial-image value to a runtime invariant. SMU callback-list consumers have no proved eight-entry termination bound.
- Do not re-run completed exclusions without new evidence. Roadmap.md identifies the outstanding questions and their stopping criteria.
- Tests assert selected bytes and arithmetic, or replay mocked instruction paths. They do not emulate a complete firmware boot or prove hardware behavior.

## Hardware constraints

The measured boards occupy PCI addresses 04:00.0, 07:00.0 and 0a:00.0. The primary display board at 04:00.0 must not be reset or reassigned experimentally. A reset method listed as bus is not proof of a complete firmware reset.

Do not repeat the hot whole-SA USER-disable test: it hung a queue and caused a MODE1 reset. CC writes already tested were ignored. Operational GFXOFF ownership must be reviewed separately before any hardware access.

## Repository work

Run tools from the repository root. Preserve firmware instructions and measurement results; put portability in tools/. Public exports omit identifying metadata and unrelated operational records. Never change a measured result to make an assertion pass. Generate new evidence in an ignored fresh `work/` directory and compare it explicitly.

Do not commit credentials, private keys, complete installed SPI/NVRAM images, generated binaries, downloaded firmware or local environments. Record external input hashes and origin instead. Keep third-party copyright/license notices. All documentation and commit messages must be English. Every commit must include:

    Assisted-by: GPT-6 Astra (OpenAI Codex)
