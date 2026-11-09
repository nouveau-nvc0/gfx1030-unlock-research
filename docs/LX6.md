# LX6: CC save/restore, gates and store coverage

Addresses in this document use LX6 relative IRAM PCs and inferred DRAM virtual addresses. See [address conventions](ARCHITECTURE.md). Primary receipts are in [disassembly-v1](../evidence/navi21-unlock/disassembly-v1/).

## Local copy routine `71ac`

The low argument byte selects save (`0`) or restore (nonzero). The routine visits four SE × two SA, selects each bank through `70000004` using `(SE << 10) | (SA << 8)`, and sets `70000000 = 0`. It uses `RSIL 15`, restores PS and performs RSYNC. The four arrays contain eight DWORDs each.

| Register address | Purpose | Saved state | Restore instruction | Save instruction |
| --- | --- | --- | --- | --- |
| `600089bc` | CC WGP | `5ffedfc4..5ffedfe3` | `71fe` | `7293` |
| `600098f4` | CC RB | `5ffedfe4..5ffee003` | `7216` | `72ab` |
| `600089c0` | USER WGP | starts `5ffee004` | Same local copy family | Same local copy family |
| `60009b7c` | USER RB | starts `5ffee024` | Same local copy family | Same local copy family |

No value transformation is established in this copy. Saving an unchanged register and restoring it later is not a changed-mask producer. These are WGP/RB accesses, not a demonstrated write to the outer SA register `60008924`.

`6944` is the sole decoded immediate caller of `71ac` (`6a95`). The known calls to `6944` are:

| Call PC | Arguments | Role |
| --- | --- | --- |
| `2f15` | `(1,0)` | Alternative restore |
| `36ca` | `(1,1)` | Main gated restore |
| `3982` | `(0,01000001)` | Save path; packed argument interpretation matters |
| `3b32` | `(1,1)` | Deferred gated restore |
| `3c0e` | `(0,0)` | Save actual state after deferred path |
| `70a2` | `(0,0)` | Alternate save cycle |
| `7142` | `(1,0)` | Alternate restore cycle |

## Invocation is not yet established

The registered `77cc` path can lead through `76f8 → 32a4 → 35d8 → 6944 → 71ac`, but requires byte `5ffee452 != 0`. No nonzero producer for that byte has been established. Deferred `3a00` uses the same gate: with zero it skips restore but can later save the actual CC values at `3c0e`.

Alternative `2edc` restores at `2f15` only if `6803ed50` bit1 and `d99c != 0` permit it; its actual entry remains unknown. `70d4` restores at `7142` when byte `db25 != 0`. The preceding `6f70` path calls save at `70a2`, calls `4774`, then sets `db25 = 1` at `70cc`; restore later clears it at `71a4`. Merely seeing that flag set would not certify that a save completed successfully.

`3300` sets `d99c` from argument0's byte and `d9a0` from argument1 (default `10000`). Two registered command paths lead there: command `1b` at `7d24 → 7ef0`, and command `4b` at `83fc → 8757`, with value `V` from `6803b2ac`, arguments `(V & 1, V >> 8)`. Their scheduling through `5a6c`/`3a00` does not set the separate `e452` gate. Do not conflate the command-controlled scheduling flag with restoration eligibility.

Evidence: [restore entries](../evidence/navi21-unlock/disassembly-v1/rlc-restore-entry-audit.json), [alternative cycle](../evidence/navi21-unlock/disassembly-v1/rlc-alternative-cycle-audit.json), [d99c producers](../evidence/navi21-unlock/disassembly-v1/rlc-d99c-producer-audit.json), [d99c consumers](../evidence/navi21-unlock/disassembly-v1/rlc-d99c-consumer-audit.json).

## MQD snapshot routine `74c4`

This routine stores/loads CP MQD state through a slot-indexed layout. Base is `5ffedc80 + 8*slot`; field offsets are `0c/10/10c/110/20c/210`. Packed argument byte0 selects operation, byte1 enables a custom slot, byte2 selects it; normal calls select slot 31.

Source registers are `CP_MQD_BASE_ADDR` (`6000c824`, mask `fffffffc`), high address (`6000c828`, mask `ffff`), and control (`6000c8ac`, mask `0780310f`). Instance selection comes from `6803b284`.

Arithmetic permits custom slot39 to overlap CC WGP saved state. The gate is byte2 of DWORD `e450`, potentially reached by slot184/control, slot216/high address or slot248/base address. Those sources differ: the documented high-address mask has no byte2 bits; control's bit23 can matter. This is an address-overlap hypothesis, **not** arbitrary mask control or evidence that any such slot is invoked.

A raw CALL/J scan of `74c4..766f` found one true incoming call `6de5 → 74c4`; three other byte matches are inside existing instructions. No absolute pointers were found. A wider set of 260 function/vector listings contains 16,080 byte-checked records and 1,947 immediate edges: nine external edges to the reviewed routines, all known primary CALL8 edges (seven to `6944`, one to `71ac`, one to `74c4`). No additional decoded conditional/interior entry was found. This is bounded coverage, not a whole-firmware graph.

Evidence: [snapshot sources](../evidence/navi21-unlock/disassembly-v1/rlc-snapshot-sources.json), [entry range](../evidence/navi21-unlock/disassembly-v1/rlc-snapshot-entry-range-audit.json), [incoming edges](../evidence/navi21-unlock/disassembly-v1/rlc-cc-incoming-edges-audit.json).

## Store inventory: what has already been accounted for

The reviewed 236 windows contain 2,399 stores, including 108 unresolved non-a1 destination stores. All 108 now have local dispositions; conditional pointer cases remain open. “Accounted for” is not “proved unable to touch state under all entries.”

| Family | Established local bound | Still conditional |
| --- | --- | --- |
| Startup `648` | Clears `[e240,ecb0)`; includes gate, excludes saved CC | Later writers and runtime entry |
| Indexed setter `32c8` | Known callers use indices 0,1,2 relative to `e44c+9+index` | Other indices could differ; no gate-producing caller established |
| Derived stores `01d10` | Three loops cover `[e384,e3c4)`, `[e308,e344)`, `[e348,e384)`: 184 bytes | Inputs vary stored values, not these destinations; other entries unbounded |
| Ring `2a0c/2ab8` | Index `e424` initialized to0; known updates `(old+1)&15` | Index used before masking; index27 would reach `e450`; no such producer found |
| Known copies | Two 20-byte copies target `d978..d98c` and `e438..e44c` | Other callers/interior entries not excluded |
| Optional output `9830` | Seven known calls supply null output | Other callers may not |
| Context `9a84` | Known context range `[e044,e224)` | General runtime context pointer not closed |
| Shared copy body `a1bd..a2fc` | No additional known entry in reviewed range | Computed/interior entry remains outside closure |
| Stack aliases/register windows | Reviewed local allocations and loop bounds | Runtime stack placement and unreviewed entries |

[Disposition audit](../evidence/navi21-unlock/disassembly-v1/rlc-store-disposition-audit.json) links each group to its supporting receipt. Repeating the same fixed-address grep is lower priority than establishing missing entry/pointer provenance or a concrete producer.

## Open requirements

A credible continuation must identify a producer of altered state, a real invocation with the necessary gate/arguments, and hardware acceptance. It must also explain the outer SA gate, not merely WGP/RB save buffers. Missing-engine power, clocks, RB dependencies and physical correctness would remain subsequent questions even after accepted CC writes.
