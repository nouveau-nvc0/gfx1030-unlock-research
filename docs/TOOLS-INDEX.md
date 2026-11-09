# Research tool catalog

The catalog identifies the published research scripts. Hardware collectors omit unrelated metadata; transient writer copies have execution disabled. The portable allowlist is explicit.

| Script | Category | Purpose |
| --- | --- | --- |
| [navi21-analyze-vfct.py](../scripts/navi21-analyze-vfct.py) | historical-offline-tool | Offline VFCT selection replay against a saved inventory; no device access. |
| [navi21-bank-writability.py](../scripts/navi21-bank-writability.py) | archived-hardware-logic-execution-disabled | Authorized transient WGP-disable readback control on an idle Navi21 GPU. |
| [navi21-bios-policy-probe.py](../scripts/navi21-bios-policy-probe.py) | historical-offline-tool | Emulate known X99-TF BDS ROM-policy routines offline; no hardware access. |
| [navi21-bios-vga-probe.py](../scripts/navi21-bios-vga-probe.py) | historical-offline-tool | Offline Unicorn experiment on the known X99-TF legacy VGA selector. |
| [navi21-compare-roms.py](../scripts/navi21-compare-roms.py) | historical-offline-tool | Compare saved Navi21 ATOM ROMs offline. Never accesses hardware or executes ROM code. |
| [navi21-gemm-baseline.hip](../scripts/navi21-gemm-baseline.hip) | hardware-experiment-do-not-run | Research source; inspect before use. |
| [navi21-gop-atom-write-audit.py](../scripts/navi21-gop-atom-write-audit.py) | historical-offline-tool | Offline byte-checked stock ATOM destination inventory; not a full emulator. |
| [navi21-gop-bar-transfer-check.py](../scripts/navi21-gop-bar-transfer-check.py) | historical-offline-tool | Replay GOP BAR transfer helpers, stopping at synthetic PCI callbacks. |
| [navi21-gop-health-registration.py](../scripts/navi21-gop-health-registration.py) | historical-offline-tool | Byte-checked identification of GOP DriverHealth repair notification callbacks. |
| [navi21-gop-indirect-tail-check.py](../scripts/navi21-gop-indirect-tail-check.py) | historical-offline-tool | Audit fixed-displacement BAR writes and replay ATOM destination tail jumps. |
| [navi21-gop-indirectio-check.py](../scripts/navi21-gop-indirectio-check.py) | historical-offline-tool | Bounded offline replay of GOP indirect-I/O dispatcher, synthetic RAM only. |
| [navi21-gop-inventory.py](../scripts/navi21-gop-inventory.py) | historical-offline-tool | Offline extraction and PE inventory of the two pinned reference-ROM GOPs. |
| [navi21-gop-scratch-callers.py](../scripts/navi21-gop-scratch-callers.py) | historical-offline-tool | Conservative per-function x64 constant flow for direct scratch-write callers. |
| [navi21-gop-vram-base-check.py](../scripts/navi21-gop-vram-base-check.py) | historical-offline-tool | Original-instruction replay of GOP's runtime VRAM-table base update. |
| [navi21-gop-wrapper-check.py](../scripts/navi21-gop-wrapper-check.py) | historical-offline-tool | Replay original XL GOP address wrappers with reference ROMs in synthetic RAM. |
| [navi21-gop-write-leaves.py](../scripts/navi21-gop-write-leaves.py) | historical-offline-tool | Inventory direct references to the x64 GOP PCI Mem.Write wrapper. |
| [navi21-lx6-port-definition-audit.py](../scripts/navi21-lx6-port-definition-audit.py) | historical-offline-tool | Compare exact TOC port candidates with the pinned local register database. |
| [navi21-psp-base-producer-audit.py](../scripts/navi21-psp-base-producer-audit.py) | historical-offline-tool | Record the conditional producer of the SYS RLC base value. |
| [navi21-psp-buffer-ownership-audit.py](../scripts/navi21-psp-buffer-ownership-audit.py) | portable-offline-audit | Record offline driver evidence separating staging, allocation and RLC base. |
| [navi21-psp-cc-reference-audit.py](../scripts/navi21-psp-cc-reference-audit.py) | historical-offline-tool | Bounded direct-reference locator for CC destinations in SYS/SOS firmware. |
| [navi21-psp-rlc-base-locator.py](../scripts/navi21-psp-rlc-base-locator.py) | historical-offline-tool | Locate the concrete RLC base setup candidate in the offline SYS image. |
| [navi21-psp-rlc-dispatch-audit.py](../scripts/navi21-psp-rlc-dispatch-audit.py) | historical-offline-tool | Resolve two local SYS selector paths into previously decoded RLC callers. |
| [navi21-psp-rlc-start-audit.py](../scripts/navi21-psp-rlc-start-audit.py) | historical-offline-tool | Check local SYS call contexts around RLC base programming and start. |
| [navi21-read-registers.py](../scripts/navi21-read-registers.py) | hardware-reader-do-not-run-automatically | Allowlisted gfx1030 register reads. Default: no bank selection and no writes. |
| [navi21-readonly-inventory.py](../scripts/navi21-readonly-inventory.py) | hardware-reader-do-not-run-automatically | Collect cached AMDGPU topology and allowlisted read-only diagnostics. |
| [navi21-rlc-4004-destination-audit.py](../scripts/navi21-rlc-4004-destination-audit.py) | portable-offline-audit | Enumerate the LX6 4004 selector offline; no firmware execution. |
| [navi21-rlc-alternative-cycle-audit.py](../scripts/navi21-rlc-alternative-cycle-audit.py) | portable-offline-audit | Offline provenance of the alternative restore flag db25. |
| [navi21-rlc-callback-unused-entry-audit.py](../scripts/navi21-rlc-callback-unused-entry-audit.py) | portable-offline-audit | Offline direct-reference coverage for seven other callback setters. |
| [navi21-rlc-cc-incoming-edges-audit.py](../scripts/navi21-rlc-cc-incoming-edges-audit.py) | portable-offline-audit | Inventory decoded immediate incoming edges to three CC-related procedures. |
| [navi21-rlc-computed-store-bounds-audit.py](../scripts/navi21-rlc-computed-store-bounds-audit.py) | portable-offline-audit | Bound selected unresolved LX6 stores from byte-checked existing listings. |
| [navi21-rlc-copy-entry-audit.py](../scripts/navi21-rlc-copy-entry-audit.py) | portable-offline-audit | Raw range-wide reference check for the LX6 shared copy body. |
| [navi21-rlc-d99c-consumer-audit.py](../scripts/navi21-rlc-d99c-consumer-audit.py) | portable-offline-audit | Offline distinction between d99c callback scheduling and e452 restore gate. |
| [navi21-rlc-d99c-producer-audit.py](../scripts/navi21-rlc-d99c-producer-audit.py) | portable-offline-audit | Offline registered-handler paths to the alternative restore flag d99c. |
| [navi21-rlc-derived-store-audit.py](../scripts/navi21-rlc-derived-store-audit.py) | portable-offline-audit | Byte-checked destination bounds for the six computed stores in01d10. |
| [navi21-rlc-direct-root-audit.py](../scripts/navi21-rlc-direct-root-audit.py) | portable-offline-audit | Check listed RLC direct-call targets against separately available roots. |
| [navi21-rlc-gate-index-audit.py](../scripts/navi21-rlc-gate-index-audit.py) | portable-offline-audit | Audit known direct callers of RLC's indexed state-byte setter. |
| [navi21-rlc-interrupt-dispatch-audit.py](../scripts/navi21-rlc-interrupt-dispatch-audit.py) | historical-offline-tool | Offline byte-checked expansion of RLC interrupt dispatcher entries. |
| [navi21-rlc-jump-tables.py](../scripts/navi21-rlc-jump-tables.py) | historical-offline-tool | Extract four bounded RLC switch tables from pinned firmware; offline only. |
| [navi21-rlc-movt-store-audit.py](../scripts/navi21-rlc-movt-store-audit.py) | historical-offline-tool | Reproduce resolved LX6 stores after conservative MOVT/MOVF handling. |
| [navi21-rlc-pace-bounds-audit.py](../scripts/navi21-rlc-pace-bounds-audit.py) | portable-offline-audit | Bounded offline checks for two PACE selectors and the state ring. |
| [navi21-rlc-pace-level-audit.py](../scripts/navi21-rlc-pace-level-audit.py) | portable-offline-audit | Audit the local PACE level writer; consumes a fresh local CFG receipt. |
| [navi21-rlc-restore-entry-audit.py](../scripts/navi21-rlc-restore-entry-audit.py) | portable-offline-audit | Raw immediate-entry search and byte evidence for restore caller conditions. |
| [navi21-rlc-saved-array-overlap.py](../scripts/navi21-rlc-saved-array-overlap.py) | historical-offline-tool | Address model for RLC74c4's indexed hardware snapshots; offline only. |
| [navi21-rlc-saved-lifecycle-audit.py](../scripts/navi21-rlc-saved-lifecycle-audit.py) | portable-offline-audit | Local order of CC save/restore calls; no global execution or timing claim. |
| [navi21-rlc-saved-neighbors-audit.py](../scripts/navi21-rlc-saved-neighbors-audit.py) | portable-offline-audit | Check neighboring snapshot writers against exact saved-CC intervals. |
| [navi21-rlc-scratch-consumer-audit.py](../scripts/navi21-rlc-scratch-consumer-audit.py) | portable-offline-audit | Offline audit of the RLC 35-word scratch consumer, not a hardware test. |
| [navi21-rlc-snapshot-entry-range-audit.py](../scripts/navi21-rlc-snapshot-entry-range-audit.py) | portable-offline-audit | Raw range-wide reference check for the LX6 MQD snapshot body. |
| [navi21-rlc-snapshot-sources.py](../scripts/navi21-rlc-snapshot-sources.py) | historical-offline-tool | Resolve indexed RLC snapshot sources against saved GC register headers. |
| [navi21-rlc-srm-locate.py](../scripts/navi21-rlc-srm-locate.py) | historical-offline-tool | Offline signed-section boundary and packed-register locator; no GPU access. |
| [navi21-rlc-startup-state-audit.py](../scripts/navi21-rlc-startup-state-audit.py) | portable-offline-audit | Pinned RLC startup data audit, no execution or hardware access. |
| [navi21-rlc-store-coverage-audit.py](../scripts/navi21-rlc-store-coverage-audit.py) | historical-offline-tool | Refresh the scoped LX6 store inventory and expose local coverage limits. |
| [navi21-rlc-store-disposition-audit.py](../scripts/navi21-rlc-store-disposition-audit.py) | portable-offline-audit | Link every current unresolved-address store to a bounded scope or open item. |
| [navi21-rlc-transition-controls-audit.py](../scripts/navi21-rlc-transition-controls-audit.py) | portable-offline-audit | Bound the local restore-transition callee group and identify SERDES fields. |
| [navi21-rlc-window-store-audit.py](../scripts/navi21-rlc-window-store-audit.py) | portable-offline-audit | Offline destination bounds for remaining LX6 window/table stores. |
| [navi21-rlcg-cc-operand-audit.py](../scripts/navi21-rlcg-cc-operand-audit.py) | portable-offline-audit | Pinned RLCG operand inventory and explicitly conditional field interpretation. |
| [navi21-rlcg-command-bridge-audit.py](../scripts/navi21-rlcg-command-bridge-audit.py) | portable-offline-audit | Offline RLCG word/operand consistency receipt, not a complete ISA decoder. |
| [navi21-rlcg-dram-save-audit.py](../scripts/navi21-rlcg-dram-save-audit.py) | portable-offline-audit | Audit the concrete RLCG descriptor save path, retaining inferred ISA limits. |
| [navi21-rlcg-e800-helper-audit.py](../scripts/navi21-rlcg-e800-helper-audit.py) | portable-offline-audit | Pin the indexed RLCG helper structure without assigning a physical block. |
| [navi21-rlcg-e800-map-comparison.py](../scripts/navi21-rlcg-e800-map-comparison.py) | historical-offline-tool | Compare the unidentified indexed port with same-generation RTAVFS metadata. |
| [navi21-rlcg-e800-write-indices-audit.py](../scripts/navi21-rlcg-e800-write-indices-audit.py) | portable-offline-audit | Trace the local constant index setup for every literal e800 write call. |
| [navi21-rlcg-gpm-transfer-audit.py](../scripts/navi21-rlcg-gpm-transfer-audit.py) | portable-offline-audit | Offline GPM transfer comparison; retains unproved ISA/address correspondences. |
| [navi21-rlcg-lx6-control-audit.py](../scripts/navi21-rlcg-lx6-control-audit.py) | historical-offline-tool | Bounded RLCG LX6-control inspection; retain generation/ISA limits. |
| [navi21-rlcg-lx6-index-audit.py](../scripts/navi21-rlcg-lx6-index-audit.py) | portable-offline-audit | Check whether the known LX6 bulk path requires a nonzero port index. |
| [navi21-rlcg-spm-transfer-audit.py](../scripts/navi21-rlcg-spm-transfer-audit.py) | portable-offline-audit | Offline SPM transfer constants and bounded direct-call inventory. |
| [navi21-rlcg-toc-audit.py](../scripts/navi21-rlcg-toc-audit.py) | portable-offline-audit | Extract local SOS TOC and compare its fields with RLCG descriptor operands. |
| [navi21-rlcg-toc-effects-audit.py](../scripts/navi21-rlcg-toc-effects-audit.py) | portable-offline-audit | Bounded table-effect and memory-base selection audit, no runtime assertions. |
| [navi21-sa-writability.py](../scripts/navi21-sa-writability.py) | archived-hardware-logic-execution-disabled | Authorized Navi21 CC/USER SA-mask readback experiments. |
| [navi21-smu-cfg-scan.py](../scripts/navi21-smu-cfg-scan.py) | historical-offline-tool | Conservative local constant propagation over targeted SMU listings. |
| [navi21-smu-command41-initial-ranges-audit.py](../scripts/navi21-smu-command41-initial-ranges-audit.py) | portable-offline-audit | Decode all nine initial state records, not only step0, for command41 data. |
| [navi21-smu-command41-pointer-candidates-audit.py](../scripts/navi21-smu-command41-pointer-candidates-audit.py) | portable-offline-audit | Enumerate image-backed initial pointer selections for command41 byte store. |
| [navi21-smu-command41-state-audit.py](../scripts/navi21-smu-command41-state-audit.py) | portable-offline-audit | Record state-selection bounds and precise limits of the pointer-write locator. |
| [navi21-smu-command41-workers-audit.py](../scripts/navi21-smu-command41-workers-audit.py) | portable-offline-audit | Trace command41's initial workers and identify its second callback layer. |
| [navi21-smu-disassemble.py](../scripts/navi21-smu-disassemble.py) | historical-offline-tool | Offline targeted Xtensa listing; never accesses a GPU. |
| [navi21-smu-e800-reference-audit.py](../scripts/navi21-smu-e800-reference-audit.py) | portable-offline-audit | Check SMU literals for a concrete counterpart of the RLCG indexed ports. |
| [navi21-smu-event-table.py](../scripts/navi21-smu-event-table.py) | historical-offline-tool | Extract the offline SMU event descriptors; never accesses hardware. |
| [navi21-smu-expand-calls.py](../scripts/navi21-smu-expand-calls.py) | historical-offline-tool | Offline closure runner; uses pinned local decoder environment in /tmp/navi21-disasm. |
| [navi21-smu-ff8c-enable-ports-audit.py](../scripts/navi21-smu-ff8c-enable-ports-audit.py) | portable-offline-audit | Pin ff8c enable call sites and state8's concrete indexed-port transaction. |
| [navi21-smu-ff8c-transition-audit.py](../scripts/navi21-smu-ff8c-transition-audit.py) | portable-offline-audit | Tie the scheduled callback to concrete ff8c transition definitions. |
| [navi21-smu-irq-mask-audit.py](../scripts/navi21-smu-irq-mask-audit.py) | portable-offline-audit | Reproduce offline SMU IRQ-mask evidence; no device access. |
| [navi21-smu-lx6-port-audit.py](../scripts/navi21-smu-lx6-port-audit.py) | portable-offline-audit | Extend the earlier SMU port locator with concrete TOC-derived LX6 candidates. |
| [navi21-smu-pace-delivery-audit.py](../scripts/navi21-smu-pace-delivery-audit.py) | portable-offline-audit | Offline evidence for conditional PACE update delivery and command boundary. |
| [navi21-smu-pace-source-audit.py](../scripts/navi21-smu-pace-source-audit.py) | portable-offline-audit | Offline provenance of the final sixteen words in the SMU/RLC block. |
| [navi21-smu-registered-roots.py](../scripts/navi21-smu-registered-roots.py) | historical-offline-tool | Extract offline callback registrations from local CFG argument constants. |
| [navi21-smu-repair-branch-targets.py](../scripts/navi21-smu-repair-branch-targets.py) | historical-offline-tool | Offline decode of missing internal branch targets; preserve alternate starts. |
| [navi21-smu-state2-list-audit.py](../scripts/navi21-smu-state2-list-audit.py) | portable-offline-audit | Trace the producer of the state2 callback list and its eight source entries. |
| [navi21-smu-transfer-program-audit.py](../scripts/navi21-smu-transfer-program-audit.py) | portable-offline-audit | Offline reconstruction of the observed 140-byte SMU transfer program. |
| [navi21-smu-window-umc-audit.py](../scripts/navi21-smu-window-umc-audit.py) | portable-offline-audit | Offline correspondence of SMU window tables to UMC register coordinates. |
| [navi21-sos-f2-recipient-audit.py](../scripts/navi21-sos-f2-recipient-audit.py) | historical-offline-tool | Trace dynamic recipient selection for the internal RLC packet. |
| [navi21-sos-image-order-audit.py](../scripts/navi21-sos-image-order-audit.py) | historical-offline-tool | Check the local initialization order selecting image fielda023c. |
| [navi21-sos-image-origin-audit.py](../scripts/navi21-sos-image-origin-audit.py) | historical-offline-tool | Record the concrete producer of kernel image pointer601c. |
| [navi21-sos-image-pointer-audit.py](../scripts/navi21-sos-image-pointer-audit.py) | historical-offline-tool | Record image-source pointer initialization and independent command-window base. |
| [navi21-sos-initial-recipient-audit.py](../scripts/navi21-sos-initial-recipient-audit.py) | historical-offline-tool | Record the special fixed-selector loader path and its concrete caller. |
| [navi21-sos-recipient-property-audit.py](../scripts/navi21-sos-recipient-property-audit.py) | historical-offline-tool | Identify ordinary recipient registration's dependency on existing SYS routing. |
| [navi21-sos-rlc-map-audit.py](../scripts/navi21-sos-rlc-map-audit.py) | historical-offline-tool | Resolve the local mapping setup used for RLC base-register accesses. |
| [navi21-sos-rlc-packet-audit.py](../scripts/navi21-sos-rlc-packet-audit.py) | historical-offline-tool | Trace SOS construction of the two RLC-related internal SYS packets. |
| [navi21-sos-svc-route-audit.py](../scripts/navi21-sos-svc-route-audit.py) | historical-offline-tool | Check the SOS SVC dispatch and concrete load/store helper instructions. |
| [navi21-sys-recipient-entry-audit.py](../scripts/navi21-sys-recipient-entry-audit.py) | historical-offline-tool | Connect recipient entry installation with a concrete SYS entry candidate. |
| [navi21-sys-record-endpoint-audit.py](../scripts/navi21-sys-record-endpoint-audit.py) | historical-offline-tool | Match the SYS record-address endpoint to the local register database. |
| [navi21-sys-rlc-record-audit.py](../scripts/navi21-sys-rlc-record-audit.py) | historical-offline-tool | Offline SYS record-copy path; positions are firmware file offsets. |
| [navi21-sys-rlc-record-origin-audit.py](../scripts/navi21-sys-rlc-record-origin-audit.py) | historical-offline-tool | Offline checks of record preparation and its address-base producer. |
| [navi21-sys-rlc-record-overlap-audit.py](../scripts/navi21-sys-rlc-record-overlap-audit.py) | historical-offline-tool | Conditional address proof for the SYS record versus RLC DRAM snapshot. |
| [navi21-sys-staging-lifetime-audit.py](../scripts/navi21-sys-staging-lifetime-audit.py) | portable-offline-audit | Check matched-version source ordering and reuse of the SYS staging buffer. |
| [navi21-wave-map.hip](../scripts/navi21-wave-map.hip) | hardware-experiment-do-not-run | Research source; inspect before use. |
