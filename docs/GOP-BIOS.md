# GOP, ATOM, ROM provenance and motherboard policy

## Reference XL/XT comparison

The public Phantom Gaming references are TPU230822 XT (1MiB, SHA256 prefix `ec4674da`) and TPU233900 XL (1MiB, prefix `6ffb1d8b`). Collection MD5/SHA1 agree. The XL prefix differs from the local04 VFCT at four POST/checksum fields; this is not an independent physical-ROM read.

`GFX_INFO` v2.6 differs only at bytes44/46 (`10/3 → 9/4`); the 60/72-CU descriptor interpretation is provisional. `ASIC_Init` and six of seven commands match; internal command66 differs in ten working-space operand bytes.29/31 PSP-directory payloads match. Later GOP analysis, summarized below, supersedes the early report's “GOP untraced” statement. Neither descriptor differences nor the common command tables establish a harvesting control or an early CC-write window.

[Comparison receipts](../evidence/navi21-unlock/xt-rom-comparison-v1/), [historical report](../navi21-unlock-report.md).

## GOP register wrappers and initial scratch destination

The x64 XL/XT GOPs were extracted and inventoried separately; ARM64 counterparts were extracted but are not equivalently analyzed. Direct write-leaf references were enumerated: XL14 references to `62e8` in `6320/6468/65d4/6734`; XT16 to `4e54` in `4e8c/4fd4/5140/7e28`. Some leaf writes merely select an index before a read. A direct-reference inventory does not close indirect protocol calls.

XL `6734` gets FirmwareInfo through `PCI_IO.RomImage`, checks version/base, computes `(base << 2) + 0x20`, and writes caller R8D. Initial FirmwareInfo base+18 is `0x4c`, selecting DWORD register `0x54` / byte `0x150`. XT `5140` computes the same destination but reads/ORs the input before writing; value semantics are not identical. XL's direct caller supplies `0x20000000` or `0x10000000`.

Scratch-caller analysis independently covers XL35 sites/14 functions and XT24 sites/14 functions, selecting indices `{0,2,3,5,6,7,8,10}` under the documented function-entry/ABI assumptions. Neither set selects CC with the initial base. Complete data mutation and alternate-entry coverage remain open.

[Write leaves](../evidence/navi21-unlock/disassembly-v1/gop-write-leaf-inventory.json), [XL scratch callers](../evidence/navi21-unlock/disassembly-v1/gop-scratch-callers.json), [XT callers](../evidence/navi21-unlock/disassembly-v1/gop-scratch-callers-candidate.json).

## High-bit route is VRAM access; tables can mutate

The reviewed route uses MM_INDEX at byte0, MM_DATA at byte4 and forced bit31, matching the saved public `amdgpu_device_mm_access` VRAM convention. Wrapper `87dc` therefore provides a VRAM-write route, not direct GC CC selection. Its final byte address is:

`(((base + uint16(offset)) mod 2^32) | 0x80000000) & 0xfffffffc`.

Bit31 remains set for any base; literal `8924/89bc` cannot be the resulting address. Exact VRAM position also depends on MM_INDEX_HI, which the immediate wrapper does not set. Indirect effects of VRAM writes remain separate.

Crucially, initial ROM tables are not immutable. XL initialization `1914 → 7960` invokes ATOM command6, shifts its returned DWORD left10, and conditionally updates data11 fields+4/+8 using FirmwareInfo+54 (initially `c00`, with fallback `40`). Arithmetic is modulo2^32. The actual hardware return is unknown. Twenty-four synthetic instruction replays cover stock/existing-size/existing-base/fallback cases. An older `80000000..8000fffc` bound applies only to initial tables and must not be used as a runtime exclusion. Other FirmwareInfo fields are also modified; absence of a known +18 writer is not proof of total immutability.

[Mutation analysis](../evidence/navi21-unlock/disassembly-v1/gop-runtime-table-update.txt), [replay](../evidence/navi21-unlock/disassembly-v1/gop-vram-base-replay.json), [VRAM source interpretation](../evidence/navi21-unlock/disassembly-v1/gop-write-leaves-analysis.txt).

## General BAR transfer and pointer ownership

XL `69fc` and XT `6bcc` are byte-identical transfer helpers. Context+20 is PCI_IO, byte+106 selects BAR, R8D is offset, RDX is buffer, stack argument5 is byte count, argument6 chooses read(nonzero)/write(zero). Width is DWORD/WORD/BYTE according to divisibility. The helper neither filters CC nor validates ranges itself.64 mocked instruction cases passed across both images and synthetic BAR0/BAR3 cases, stopping before the PCI callback.

New initialization allocates/zeroes a `0x9c0` context, making +106 initially0. Register BAR+104 is separately set3. No literal +106 setter was found in the retained listing. This supports initial framebuffer BAR0 usage, not permanent immutability. Synthetic BAR3 replay proves forwarding, not an actual stock caller selecting BAR3.

The three literal `+18` indirect sites per image include two PCI_IO.Mem.Write paths and a BootServices.RaiseTPL call. Offset equality alone does not identify a protocol. Register-loaded pointers, computed entries and mutable contexts remain open.

ROM initialization retains a pointer, not a byte copy: optional global XL`cdd0`/XT`ce10` overrides `PCI_IO.RomImage`; the resulting pointer reaches context+88 then+70 and the interpreter. Another consumer constructs VFCT. No producer of the optional global was found; initial zero and no direct xrefs do not rule out computed/external writes. Installed ROM-buffer origin/hash remains unproved.

[BAR replay](../evidence/navi21-unlock/disassembly-v1/gop-bar-transfer-replay.json), [protocol analysis](../evidence/navi21-unlock/disassembly-v1/gop-protocol-write-followup.txt), [ROM ownership](../evidence/navi21-unlock/disassembly-v1/gop-rom-source-followup.txt).

## ATOM interpreter

Parsed stock command rows include all branches, even unreachable ones; initial zero register base was established in XL GOP. Index/data-port operands are tracked separately. The retained direct destination audit does not turn REG0/1 indirect values into direct register addresses. Dynamic tables, pointer changes and general protocol paths remain outside a blanket “no write possible” claim. [ATOM write audit](../evidence/navi21-unlock/disassembly-v1/gop-atom-write-audit.json), [indirect I/O replay](../evidence/navi21-unlock/disassembly-v1/gop-indirectio-replay.json).

## X99-TF CSM/Video reference policy

The installed SPI image was not obtained: strict `/dev/mem` prevented the attempted mapping. No reboot, alternate access policy or flash occurred. The user-supplied Koshak reference is commit `b27e6e0909c1288639f5adfc5b8708d9f342acc6`, X99-TF2020-05-25, **not** a verified copy of the installed NALEX modifications.

Reference Setup byte65 controls CSM; byte6c selects Video (0=none,1=UEFI,2=Legacy). BDS forces effective UEFI policy while LegacyBios protocol is absent, restoring selected policy when it arrives. CsmDxe also exits early with CSM disabled.24 isolated original-instruction ROM-policy cases passed. Six mocked PCI enumeration orders show CsmDxe returning the first enumerated offboard VGA, not a stable guarantee of physical04.

CSM enabled + Video Legacy is a native candidate, not an applied or fully proved solution. Secondary POST absence and primary display preservation are unproved; a special patch has not been established necessary. Reference “nobeep” changes four BDS bytes at `3d69/3da4` from OR AL,3 to AND AL,fc. Preserve installed memory/timing modifications and active settings; never flash this reference as the current image. Any future image requires an exact installed base and a separate explicit deployment request.

[Reference findings](../evidence/navi21-unlock/bios-policy-plan-v1/findings.json), [historical lab plan](../next-experiments.md). Those plans are inactive during the research pause.
