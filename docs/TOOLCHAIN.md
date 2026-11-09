# Toolchain and offline reproduction

## Default verification: no external dependencies

Python3.10+ is sufficient for packaging checks and the portable audit subset. Run from the repository root:

```sh
make check
make list
```

[The readable tool index](TOOLS-INDEX.md) lists every script. `tools/catalog.json` categorizes all103 research scripts and pins their published SHA256. `scripts/` contains the research tools. Public versions of the hardware collectors omit unrelated metadata; transient writers have execution disabled and retain register/rollback logic for study. Hardware readers, transient writers and HIP programs are explicitly separated in the catalog; they are never called by the default targets. A filename containing “readonly” still accesses hardware and is not a packaging check.

## Portable core replay

Supply these compressed images in an external directory. Hashes below apply to **decompressed bytes**, not the compressed xz file:

| File | SHA256 |
| --- | --- |
| `sienna_cichlid_rlc.bin.xz` | `19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0` |
| `sienna_cichlid_smc.bin.xz` | `0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d` |
| `sienna_cichlid_sos.bin.xz` | `67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37` |

The original machine supplied them from `/usr/lib/firmware/amdgpu`; obtain your own matching distribution/linux-firmware inputs under their license. The decompressed hashes are authoritative. An exact upstream firmware commit was not recorded for every input; do not silently use latest when these guards fail.

```sh
python3 tools/run_offline.py --all \
  --firmware-dir /path/to/amdgpu --output work/replay-01
# Or one named audit:
python3 tools/run_offline.py navi21-smu-command41-pointer-candidates-audit.py \
  --firmware-dir /path/to/amdgpu --output work/pointer-01
```

The explicit allowlist contains48 standard-library audits. It excludes hardware access, subprocess-driven generators, ROM-dependent tools, UMR-archive-dependent tools and optional decoder packages. `--all` means this reviewed subset, not every historical script.

The runner verifies scripts against the catalog, checks all three firmware hashes, copies evidence and scripts into a new workspace, and replaces only the historical firmware path prefix in string constants in the in-memory Python AST. This also handles dynamic filename construction. The runner does not rewrite source scripts. Results, logs and summary stay in the output directory; an existing output directory is refused. Do not run with Python optimization, which disables assertions. This adapter is a reproducibility convenience, not a general isolation boundary for arbitrary scripts.

## Targeted Xtensa disassembly

Use a separate environment; Capstone6 is required for the retained Xtensa workflow:

```sh
python3 -m venv .venv-xtensa
.venv-xtensa/bin/pip install -r tools/requirements/xtensa.txt
mkdir -p downloads work/binutils
curl -fL 'https://deb.debian.org/debian/pool/main/b/binutils-xtensa-lx106/binutils-xtensa-lx106_2.40-2+5+b1_amd64.deb' \
  -o downloads/binutils.deb
# Compare SHA256 with archive/toolchain/artifacts.json before extracting.
sha256sum downloads/binutils.deb
dpkg-deb -x downloads/binutils.deb work/binutils
.venv-xtensa/bin/python scripts/navi21-smu-disassemble.py \
  --firmware /path/to/amdgpu/sienna_cichlid_rlc.bin.xz --kind rlc-iram \
  --objdump work/binutils/usr/bin/xtensa-lx106-elf-objdump \
  --start 0x71ac --stop 0x74c4 --output work/lx6-71ac.txt
```

Use `--kind smu` for SMU, whose code begins at file0x200. The Debian artifact is amd64; other hosts need a compatible build of the same binutils source. The hybrid decoder is incomplete and linear listings are not a CFG. See ARCHITECTURE.md for corrected CALL target arithmetic.

`navi21-smu-cfg-scan.py`, `navi21-smu-expand-calls.py` and branch-repair scripts preserve the original workflow. Some retain generic absolute workspace/decoder paths and are **archival generators**, not exposed by the portable runner. Inspect their arguments and adapt paths in a disposable copy before use; do not construct the original absolute directory tree over an existing deployment.

## UEFI/GOP/BDS replay

```sh
python3 -m venv .venv-uefi
.venv-uefi/bin/pip install -r tools/requirements/uefi.txt
.venv-uefi/bin/python scripts/navi21-bios-policy-probe.py --help
.venv-uefi/bin/python scripts/navi21-bios-vga-probe.py --help
```

Pinned packages: Capstone5.0.9, pefile2024.8.26, Unicorn2.1.4, uefi_firmware1.16. Keep this environment separate from the Xtensa one. Original package archive hashes for BIOS dependencies are recorded in `bios-policy-plan-v1/findings.json`; requirement files pin versions but do not claim a universal platform-wheel hash lock.

Reference BIOS downloads and UEFIExtract A76 / ifrextractor1.6.1 URLs and hashes are in `archive/toolchain/bios-download-manifest.json`. Reference commit is `b27e6e0909c1288639f5adfc5b8708d9f342acc6`. Use UEFIExtract to extract modules, then verify the accepted BDS/CsmDxe hashes in the probe scripts before replay. `archive/toolchain/bios-disassemble.py` records the original objdump-based module workflow. Mocked services and synthetic memory do not constitute a board boot test.

GOP extraction is in `navi21-gop-inventory.py`: verifies the XL/XT ROM hashes, parses PCIR payloads, decompresses EFI sections, validates machine types and records PE sections. Reference ROM provenance is in `xt-rom-comparison-v1/full-reference-comparison.json`. GOP scripts retain original `/tmp/navi21-gop` and BIOS-tools paths; use a disposable adapted copy and matching external ROM/PE inputs. Subsequent wrapper/BAR/VRAM/indirect-I/O scripts consume those extracted images. Saved replay receipts remain usable without distributing firmware binaries.

## UMR and hardware tooling

UMR source commit: `058a7045b600886d3cdd46b191886eb8db6a3746`, upstream `https://gitlab.freedesktop.org/tomstdenis/umr`. The original16MiB source archive hash is in `archive/toolchain/artifacts.json`. Register-definition audits read selected tar members and verify their hashes; these scripts retain the original absolute archive path. If fetching an equivalent git export changes archive bytes, verify the commit and individual member hashes; do not claim the archive hash matched.

Original build logs and source records are retained under `evidence/navi21-unlock/`. Hardware collectors require the original AMDGPU/debugfs permissions, exact register names and balanced operational GFXOFF ownership. HIP validation programs require the recorded ROCm/HIP environment. They are historical experiment tools, **not commands to run during the pause**. The original whole-SA test is blocked from repetition. Bootstrap targets perform offline checks only.

## Publication validation

See `archive/validation.json` for the actual checks performed while packaging. The entire historical firmware extraction/UEFI/hardware campaign is not claimed to have been rerun. The core48-audit suite uses matching external firmware and archived listings; default integrity checks additionally cover all exported evidence and script hashes, Python syntax and curated Markdown link targets.

## Public source variants

The hardware collectors export GPU topology and version information without persistent device identities. Transient-writer copies preserve register and rollback logic for study, with execution disabled and site-specific launch commands removed. Historical executed-source digests identify the original measured run; the catalog separately identifies the published source variants. Observational receipts may have metadata removed, while firmware bytes and measured GPU results are preserved.
