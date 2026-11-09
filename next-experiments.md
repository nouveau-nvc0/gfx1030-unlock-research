# Future Navi21 experiments

Research is paused. This document records public technical questions only; it does not authorize hardware activity. No additional CU has been enabled.

## Immediate offline priorities

1. Establish a producer of the outer CC SA mask or a changed saved value. The known LX6 copy routine covers WGP/RB state and does not itself explain the outer SA limit.
2. Establish a nonzero producer of the LX6 restore gate `5ffee452`, or a real entry into an alternative restore route.
3. Resolve the physical indexed-register maps for the concrete SMU state8/state2 and RLCG e800 endpoints before broad callback expansion.
4. Close selected GOP data/ownership questions only where they can plausibly connect to harvesting or initialization.

[Detailed priorities and stopping rules](docs/ROADMAP.md) · [current status](docs/STATUS.md).

## Reference BIOS policy

The X99-TF reference at commit `b27e6e0909c1288639f5adfc5b8708d9f342acc6` was analyzed offline. Setup byte65 controls CSM; byte6c selects Video. While LegacyBios protocol is absent, BDS forces effective UEFI video; its protocol-arrival callback restores the selected policy. CsmDxe selects the first enumerated offboard VGA in the isolated tests, not a stable physical slot.

CSM enabled + Video Legacy is a native candidate whose complete display behavior remains unproved. An exact installed SPI image was not obtained. Reference images must not be treated as deployable replacements; preserve existing code and active settings in any later explicitly requested image work.

[Detailed GOP and BIOS behavior](docs/GOP-BIOS.md) · [reference findings](evidence/navi21-unlock/bios-policy-plan-v1/findings.json).

## Requirements for future hardware observations

Any later stage comparison requires a separate instruction, exact loaded-image hashes, a reviewed restoration procedure and preservation of the primary display path. Ordinary CC writes were ignored in all fifteen tested cases. The hot whole-SA USER-disable test must not be repeated: it caused a queue hang and reset.

A complete claim must establish changed relevant state, actual invocation, accepted hardware writes and correct physical dispatch from additional units. Those requirements remain incomplete.
