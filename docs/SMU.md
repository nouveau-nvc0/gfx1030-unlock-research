# SMU command41 and state machinery

SMU PCs and initial-data addresses are relative to the code/data image at decompressed file offset `0x200`. They must not be silently translated using host GC or LX6 address maps.

## Handler and first indirect call

Handler `1d7a8` is registered for command `0x41` on channels7/8, with required flags `0x14` in the retained map. Actual delivery and state eligibility are not established. Parameter high16 indexes a pointer table at `12d10`; low16 indexes a function table at `12d20`. No local index bounds check was identified.

Initial pointer entries are `101fc`, `1042c`, `1065c`, `1088c`, each covering a `0x230`-byte structure. Initial worker entries are `1d698`, `1d60c`, `1d594`, `1d480`. The handler stores the chosen pointer in global `15874`, releases lock2, and makes CALLX8 at `1d7da`. It then **reloads** `15874` at `1d7dd` and stores byte1 at `1d7e2`. A selected pointer before the call is not automatically the pointer used afterward.

Worker `1d480` immediately returns. The first three configure state through `25b68/28b80`, clear `P+1`, and reach `1f354 → 1d488`. Twenty-four reviewed setup calls write within `[P,P+0x230)` and do not hit `P+0x22c`. Pair writer `1d554` covers `P+0x15c..P+0x1db` (32 pairs). Broader error/synchronization calls, including `1d538`, remain outside complete closure.

[Workers audit](../evidence/navi21-unlock/disassembly-v1/smu-command41-workers-audit.json).

## Second indirect call and state fields

`1d488` loads the callback-table pointer from `P+0x22c`. It forms an integer sum from cursor byte `P+0x1f` and start byte `P+0x20`, compares it against end byte `P+0x21`, then calls through the table at `1d4c1`. The sum can be0..510, but an executed lookup is bounded to0..255 by the preceding comparison. This bounds the read span to1KiB, not the number of valid entries.

Reverse path `1b20c` uses start/end `P+0x22/+0x23` and CALLX8 at `1b248`. `P+1` values1/2 affect early return and resumption. Callback `1d7ec` writes1 to `P+1` using reloaded global `15874`; `1ed28` writes2 to a structure's `P+1`. Neither is itself an assignment to the global pointer.

Initial callback pointers are `115a0` for the first three structures and `115e0` for the fourth. Step0 has zero ranges, callback0=`1d7fc` (return). **Other initial states already have nonzero ranges.** All nine 36-byte records in each of four structures (36 records) were examined, resolving to nine functions:

`1d7fc, 1d7ec, 1ef4c, 1ef20, 1da98, 1da4c, 1da28, 1da18, 1da5c`.

Several act on a separate structure at `ff8c`. `1ef4c` schedules `1efa0` via `295a4`; `1ef20` also ORs `0x80000` into `0141d700`. No local assignment to global `15874` was found in these nine bodies. Transitive and scheduled effects remain open.

Command42 (`1d77c`) calls `28b50` with selected P, parameter low8 and bits16..23. Command43 (`1d714`) reaches `1f1a4`, clears `P+1`, and drives state via `1d6f8 → 1b42c`. Commands44/45 read `P+6`/`P+1`. No fixed writer to the four initial `P+0x22c` locations was found; that is not an all-writer proof. The known `1bf68` caller supplies separate object `110d4`, so its same-offset stores do not establish mutation of these four objects.

[State audit](../evidence/navi21-unlock/disassembly-v1/smu-command41-state-audit.json), [initial ranges](../evidence/navi21-unlock/disassembly-v1/smu-command41-initial-ranges-audit.json).

## ff8c transitions and enable producers

`ff8c` uses callback table `12c50`. Initial group masks/enables are zero. Setup `26798` makes18 calls to `25b68`, defining nine distinct state pairs across ten groups. Scheduled `1efa0` requests `28b50(ff8c,9,1)` then `(ff8c,1,1)`: group9 includes0→8 and group1 includes1→2. `28b50` requires enable byte1 and a changed request mask before driving the state machine; setup definitions alone do not prove runtime transitions.

Group9 enable calls: `1db92/1dbe8/1f5c4`; disable: `1dc48`. Group1 enables: `1ddfd/1ee4e/1f517`; disable: `1df3f`. `28b80` writes at `P+0x1e0+8*group`: `101b4`/`10174` respectively, not global `15874`. Actual producer invocation remains unknown.

State8 uses forward `1ded8`, reverse `1ddec`. State2 uses forward `1ed48/1ecb4/1dd54`, reverse `1ebe0/1ead8/1dd48`.

[Transition definitions](../evidence/navi21-unlock/disassembly-v1/smu-ff8c-transition-audit.json), [enable paths and ports](../evidence/navi21-unlock/disassembly-v1/smu-ff8c-enable-ports-audit.json).

## State8: indexed operation, not a direct address

`1de0c` uses read helper `31508` and write helper `2f3e0` with selector `0x35`, argument `0x1ce18`. Helpers subtract `0x1c000`, obtaining relative `0xe18`, and pack control `0x231a19`. The control port is `0141d054`, data port `0141d088`.

The nonzero arm writes `(read | 3) & 0xffffffef`; the zero arm writes `read & 0xffffffec`. Argument `1ce18` is not a demonstrated direct register address. Physical indexed-register identity and relation to CC/saved arrays are unknown. Direct writes to `0141cb0c/0141d700` and calls to `373f4` are separate effects.

## State2: coordinate reads and compact callback lists

`1ecb4` reads six coordinates from initial table `11cd0`: `eacc,ee3c,f1ac,f51c,f88c,fbfc`. Reads use `01200000 + low20` and inspect bits28..30. It writes `0x100` to `0120e71c`; optional `1ec58` writes low8 configuration into `0141d7d8`. `1ec20 → 36fc0(0)` links the already reviewed PACE flow; `1ec2c` copies floats; `1ec3c` schedules work.

List producer `2ff84`, at `30199..3020f`, reads eight pointers from **`12110`** (literal base `11f14+1fc`). Mask bytes `9f45/9f47/9f46` compact selected pointers into lists `159e0/15a00/15a20`. All256 one-byte masks were checked. The eight source callbacks each perform one fixed RMW after read-only polling:

| Function | Destination |
| --- | --- |
| `2d808` | `0125a028` |
| `2d7e0` | `0125a004` |
| `2d7b4` | `0125a02c` |
| `2d78c` | `0125a000` |
| `2d760`, `2d708` | `0125a024` |
| `2d734`, `2d6dc` | `0125a01c` |

Polling helpers `2d8b8/2d860` read bit31 at `0125a000/0125a01c`. No local CC/global15874 assignment was established. Physical meaning and indirect effects are unresolved.

**The builder does not append a zero terminator or clear unused suffixes in this loop.** Consumers `1ebfc(arg1)` and `1ebbc(arg0)` walk until zero, with an8-bit cursor. A full first list can continue into the next; reuse can retain old entries. Initial26 zero DWORDs are not a runtime termination proof. Do not report “at most eight callbacks execute” from the builder's eight-entry source bound.

[List audit](../evidence/navi21-unlock/disassembly-v1/smu-state2-list-audit.json).

## Direct byte-store candidates: latest result

Initial low selector3 picks immediate-return worker `1d480`. Under normal return and stable global15874 this isolates the final byte1 store from the worker callbacks. The high-selector table permits65,536 indices;42,453 initial cells fit the firmware image,23,083 are uncovered.

An enumeration of reviewed CC offsets `8924/89bc/98f4` at bases `0`, `01200000`, `60000000`, `68000000`, `70000000`, plus the LX6 saved-mask/gate ranges, found one numeric candidate: value `89bc` at cell `13b94`, selector `3a1`. Existing consumers `2776c/36cfc/37fac` pass it through `38b88(width16) → 1f77c`, which interprets word index `44d`, bit28 through a separate `0125d000` read/cache mechanism.

This does not identify a direct byte-store CC alias. Even under a hypothetical direct little-endian alias, byte0 does not overlap documented inactive-WGP bits16..31. Runtime table mutation, concurrent global changes, command delivery, other address spaces and hardware byte-write semantics remain unknown. [Pointer audit](../evidence/navi21-unlock/disassembly-v1/smu-command41-pointer-candidates-audit.json).
