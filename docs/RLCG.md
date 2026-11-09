# RLCG: partial instruction semantics and state transfers

RLCG PCs are DWORD indices; this is a different processor/program from LX6. The instruction interpretation is partial. Every conclusion below is restricted to the decoded operands and retained words, not a complete ISA emulator.

## CC reads and direction-sensitive helper

`3523` reads CC register index `226f` and USER `2270` through helper `353e` in direction0, then combines disabled masks. Seventeen literal calls to `353e` were accounted for. Reverse-direction calls target only `24d7`, `ec4b` and `ec6e`, associated with SPI/RLC power masks in the reviewed map; none establishes a CC write. A helper capable of writing in one direction does not make all of its read callers writers.

Evidence: [CC operands](../evidence/navi21-unlock/disassembly-v1/rlcg-cc-operand-audit.json), [command bridge](../evidence/navi21-unlock/disassembly-v1/rlcg-command-bridge-audit.json).

## Whole LX6 DRAM snapshot

RLC TOC ID10 supplies boot state, ID27 supplies the snapshot path. Transfer ports are `fb55/fb56`, size `0x4000` bytes. ID27 offset is `0x545000`; conditional on `HYP = G + 0x400000`, the snapshot is at `G + 0x945000`.

`31e5` saves the whole block, including saved CC arrays and the gate, without an identified payload transformation. Moving the block explains preservation, not creation of changed CC data. Ten literal transfers through `30ae` are accounted for; SPM skew operands are fixed. Stores to RLCG `ed80` at `2a58/2a8b` use fixed value `0x11` before `31e5`; they are not a demonstrated delivered PC.

Evidence: [TOC](../evidence/navi21-unlock/disassembly-v1/rlcg-toc-audit.json), [DRAM save](../evidence/navi21-unlock/disassembly-v1/rlcg-dram-save-audit.json), [TOC effects](../evidence/navi21-unlock/disassembly-v1/rlcg-toc-effects-audit.json), [SPM transfer](../evidence/navi21-unlock/disassembly-v1/rlcg-spm-transfer-audit.json).

## Indexed e800 family: keep parked until a map exists

Read helper `2e7a` and write helper `2e85` operate through `e800/e801/e803/e804/e805`. Seventy-six read calls use fixed indices. Eighty-nine write calls have local constant setup with 23 distinct indices:

`02,03,09,0e,0f,12,13,21,23,25,27,28,29,2b,2c,31,32,34,35,36,38,60,61`.

No local modification of the index register r2 was found between assignment and write under the partial ISA model. Public GC10.3 RTAVFS ports have similar relative positions and masks1/2 but start at `eb00`, a difference of `0x300` DWORDs. That similarity is insufficient to name the e800 block or connect it to CC. The same literal `e800` in SMU is a data-base reference, not proof of the same ports.

Evidence: [helper behavior](../evidence/navi21-unlock/disassembly-v1/rlcg-e800-helper-audit.json), [constant write indices](../evidence/navi21-unlock/disassembly-v1/rlcg-e800-write-indices-audit.json), [SMU reference](../evidence/navi21-unlock/disassembly-v1/smu-e800-reference-audit.json).

## Remaining work

The physical port/index map, unreviewed ISA effects and indirect entries remain unknown. A useful continuation needs an independently supported map or a specific control/data dependency. Another scan for numeric e800 matches does not close these questions. The whole-block save path also requires a changed-content producer before it can contribute to a CC modification chain.
