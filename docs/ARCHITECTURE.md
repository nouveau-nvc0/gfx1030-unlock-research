# Architecture, vocabulary and address spaces

## Hardware topology and the public driver

Navi21's maximum layout is four Shader Engines (SE), two Shader Arrays (SA, also called SH) per SE and five Workgroup Processors (WGP) per array. One WGP corresponds to two CU. Maximum design dimensions are not a health test of disabled units.

`gfx_v10_3_get_disabled_sa()` combines CC and USER SA masks with OR. CU and RB enumeration skip disabled arrays before counting WGP. Within an enabled array, the driver ORs CC and USER inactive-WGP bits and clips to the five valid positions. USER can add disables; clearing USER cannot undo CC. Current live CC SA mask was `0xc01` on PowerColor/07 and `0x301` on the ASRock/04 and /0a boards; USER SA was zero. See [inventory](../gpu-inventory.md) and [driver discussion](../navi21-unlock-report.md#3-current-linux-initialization-and-dependency-chain).

Firmware roles are separate: PSP loads/manages components; SYS/SOS contain boot/delivery services; SMU has Xtensa state/command machinery; the RLC package contains a main RLCG program and a separate Xtensa LX6 IRAM/DRAM image. GOP and the ATOM interpreter execute during platform display initialization. None of their names alone identifies the producer of the CC SA mask.

## Address conventions

All bare numeric addresses in curated firmware documents are hexadecimal unless stated otherwise. A function name is only a local label from its entry coordinate, not a recovered vendor symbol.

| Component | Coordinate used here | File relation / limitation |
| --- | --- | --- |
| Host GC registers | Byte aperture offsets | GC segment0 base `0x1260` DWORDs; SA `0x8924`, WGP `0x89bc`, RB `0x98f4` |
| SMU/SMC | Code-relative byte PC | Decompressed file offset = `0x200 + PC`; literals are in the same image coordinate unless qualified |
| LX6 IRAM | Relative byte PC | File `[0xb360,0x1b360)`; inferred virtual base `0x5fff0000` |
| LX6 DRAM | Inferred virtual byte address | File `[0x1b560,0x1f560)`; inferred base `0x5ffec000` |
| RLCG | DWORD word-PC | Main file `[0x200,0x6200)`; `wordPC = 0x2000 + (fileoff-0x200)/4`; ISA only partially understood |
| SYS | File byte offsets | Image `[0x100,0x21870)`; inferred runtime = file + `0xdfff00` |
| SOS | File byte offsets | Wrapper at `0x21870`, code at `0x21970`; inferred runtime = file − `0x21970`; TOC at `0x35cd0` |
| GOP | PE image RVA in analysis notes | Convert through section table before checking file bytes; XL and XT RVAs differ |

The LX6 aperture uses `0x60000000 + host byte offset` for the reviewed WGP/RB accesses. This is a path-specific relationship, not a universal mapping for SMU or SYS. `0x680…` and `0x700…` LX6 operations, SMU `0x0141…` ports and RLCG word indices must retain their own address spaces.

## Decoder constraints

Capstone 6.0.0a5 decodes windowed Xtensa instructions; GNU binutils 2.40 lx106 fills some instruction gaps but does not provide the full LX6 configuration. The hybrid linear listings contain data and signatures too. Followed entry windows provide stronger local evidence but are not a complete CFG.

Xtensa direct CALL targets must use the aligned PC: `((pc + 4) & ~3) + 4 * signextend(imm18)`. Naively adding a printed displacement to an unaligned PC produces errors of one to three bytes. Historical corrected branch-target receipts are retained. Conditional moves preserve unrelated register values; scanner limitations and unknown memory loads still prevent whole-program constant propagation.

## Evidence levels

1. **Measured:** actual register/dispatch observations on the named boards, with explicit restoration and incident records.
2. **Byte-checked:** selected instructions match the pinned firmware and local arithmetic/control interpretation is asserted.
3. **Mocked instruction replay:** actual instructions execute in synthetic RAM with service callbacks replaced; validates that routine under those inputs.
4. **Conditional inference:** depends on entry, pointer, mutable state, mapping or hardware assumptions that must be named.
5. **Unknown:** no adequate coverage or relation established. Absence of a found reference does not turn this into impossibility.
