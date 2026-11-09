# Prioritized directions and unexplored work

**This is a backlog, not authorization to resume.** Priorities reflect usefulness of new evidence, not confidence that an unlock exists. A viable result must explain the outer SA limit and satisfy changed-value, invocation and acceptance requirements separately.

## Priority 1: connect a concrete producer to the relevant CC state

| Question | Established starting point | Useful next evidence | Completion / stopping rule |
| --- | --- | --- | --- |
| Who produces the outer CC SA mask? | Driver consumes `CC_GC_SA_UNIT_DISABLE`; hot writes ignored | A byte-checked initialization/protection path with correct address-space mapping | Must reach the SA gate, not just WGP/RB buffers; stop branches with proved unrelated endpoints |
| Who sets LX6 gate `5ffee452` nonzero? | Main/deferred restore requires it; startup clears it | Actual indexed/indirect producer, entry and arguments | Do not repeat fixed literal searches; show producer and invocation or keep unknown |
| Can a saved CC value differ before restore? | `71ac` copies saved WGP/RB without transformation | A bounded writer to the saved ranges with sourced values | Mere whole-block save/copy is insufficient |
| Is a custom MQD slot ever invoked? | `74c4` overlap arithmetic; known callers default31 | Concrete custom-enable/slot producer and source register state | Slots39/184/216/248 are arithmetic candidates only; no assumed arbitrary writes |
| Are alternative restore entries reachable? | `2edc`/`70d4`; known d99c and db25 controls | Registered/indirect entry provenance and matching save lifecycle | Flag-set does not prove completed save or altered payload |

## Priority 2: resolve physical maps before expanding firmware state machines

SMU state8 gives a concrete indexed transaction (`0141d054/0141d088`, selector35, relativee18). State2 gives fixed `0125a000/004/01c/024/028/02c` RMW destinations and explicit callback lists. RLCG gives e800-family ports and23 fixed write indices. These are useful anchors if an independent map or cross-component dependency becomes available.

Do not expand every callback merely because it writes something. Require a plausible, evidenced relation to harvesting, power/clock initialization, protection state or the saved arrays. Similar-looking RTAVFS ports at eb00 do not identify e800. A numeric SMU `89bc` match is a bit-coordinate lead already resolved locally, not a direct CC-store discovery.

Unexplored here: complete state reachability, asynchronous changes to global15874, runtime callback-table mutation, physical meaning of the indexed endpoints, and side effects beyond reviewed bodies. The SMU list builder lacks a proven terminator invariant; future analysis must retain adjacent-list and reuse behavior.

## Priority 3: close selected GOP ownership questions only if relevant

Potentially useful questions are context+106 BAR mutation, optional ROM-pointer producer, FirmwareInfo scratch-base mutation and register-loaded PCI protocol callbacks. ARM64 GOP behavior is not equivalently traced. A stock BAR3 writer with a proven CC-related destination would matter; synthetic BAR3 parameter forwarding alone does not.

Avoid reopening `87dc` as a direct GC store: its forced-bit31 route is source-supported VRAM access. Avoid treating initial ROM tables as immutable: ordinary initialization mutates them. Reference XL/XT descriptor differences are not a proved harvesting control.

## Priority 4: future controlled observations, separately authorized

A later experiment could compare CC/USER state at well-defined initialization stages, with exact loaded-image hashes and a reviewed restoration procedure. The boot display must remain usable. Verify the actual firmware source because VFCT or cached VRAM may take precedence over a supplied ROM image.

No early writable-before-lock window, clearable lock bit or XT-specific CC writer has been proved. Do not choose a write point merely because it is earlier. Full missing-SE functionality, power/clock initialization and physical defects remain untested. Bus reset alone does not establish full firmware-state restoration.

## Already explored: avoid repeating without new evidence

- Ordinary CC SA/WGP writes:15 ignored. USER controls work. Hot whole-SA disable caused a hang/reset and must not be repeated.
- LX6 local stores:2,399 inventoried;108 unknown non-stack destinations now have local dispositions. Conditions remain explicit; this is not complete program closure.
- LX6 direct edges:260 listing windows and1,947 immediate edges did not reveal an additional direct/interior entry to the reviewed CC routines.
- Known20-byte copies, derived184-byte arrays, bounded rings under normal index invariants: no changed-CC producer.
- RLCG whole DRAM save: preserves state; no transformation identified.
- SYS28-byte record: conditional non-overlap; endpoint is VCN/MMSCH, not SMU.
- SMU command41 initial pointer subset:42,453 examined,23,083 uncovered; lone89bc match does not establish CC addressing or relevant byte coverage.
- Initial callback state0 was insufficient; all36 initial state records were subsequently reviewed. Nonzero ranges already exist in the image.
- GOP stock scratch callers and initial ATOM destinations do not establish CC selection; runtime ownership questions remain distinct.
- VFCT A/A/A misselection is confirmed and unfixed, but not causal proof of CU loss.

## What a complete claim would need

1. Exact firmware/input provenance and correct processor/address mapping.
2. Producer of a changed **relevant** mask, with value and destination proven.
3. Actual call/state/argument sequence reaching the store; mutable and asynchronous dependencies accounted for.
4. Measured accepted hardware state, with a defined restoration route.
5. Physical dispatch and correctness from the newly available units, including whole-engine dependencies.
6. Repeatable performance only after correctness, with topology, clocks, software and workload held comparable.

None of items2–5 is currently complete for enabling additional CU. Ignored normal writes also do not prove universal impossibility or irreversible fusing.
