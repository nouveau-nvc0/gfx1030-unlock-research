#!/usr/bin/env python3
"""Authorized Navi21 CC/USER SA-mask readback experiments.

Default prints the plan without opening a device. --execute requires an idle
GPU and restores the saved register in finally. Modes cover a CC SA bit, CC
low bit0, the full CC SA field, or a redundant USER disable bit. Active-SA
execution is blocked after the v1 trial caused a queue hang and automatic GPU
reset. The public copy preserves readback/rollback logic for study, with execution disabled.
No firmware, OTP, clocks, SPI or RLC policy writes. Hardware can defeat rollback.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import time

REG = 0x8924
TRIALS = {
    "0000:07:00.0": (0x00000c01, 0x00000400),
    "0000:04:00.0": (0x00000301, 0x00000100),
    "0000:0a:00.0": (0x00000301, 0x00000100),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bdf", choices=TRIALS, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--user-control", action="store_true", help="Positive control: set an already CC-disabled SA bit in USER, then restore")
    ap.add_argument("--clear-bit0-control", action="store_true", help="Clear only undocumented low bit 0, preserving the entire SA-disable field")
    ap.add_argument("--clear-sa-field-and-bit0", action="store_true", help="CC only: clear the SA-disable field and low bit0 together, then restore without dispatch")
    ap.add_argument("--active-sa-control", action="store_true", help="USER only: disable one known-active SA, then restore")
    ap.add_argument("--run-probe", action="store_true", help="Active-SA control only: run a bounded ordinary correctness shader")
    a = ap.parse_args()
    if a.execute:
        raise RuntimeError("Execution disabled in this public archive; review and adapt for an isolated research setup")
    if sum([a.user_control, a.clear_bit0_control, a.clear_sa_field_and_bit0, a.active_sa_control]) > 1:
        raise RuntimeError("Choose one trial mode")
    if a.run_probe and not a.active_sa_control:
        raise RuntimeError("Dispatch applies only to the active-SA disable control")
    if a.execute and a.active_sa_control:
        raise RuntimeError("Active-SA trial disabled: v1 caused a queue hang and automatic GPU reset; review invasive-v1 evidence")
    expected_cc, clear_mask = TRIALS[a.bdf]
    register = 0x8928 if a.user_control or a.active_sa_control else REG
    original = 0 if a.user_control or a.active_sa_control else expected_cc
    target = clear_mask if a.user_control else original & ~clear_mask
    if a.clear_bit0_control:
        if a.user_control:
            raise RuntimeError("Bit0 control applies only to CC")
        clear_mask = 1
        target = original & ~1
    if a.clear_sa_field_and_bit0:
        clear_mask = 0xff01
        target = original & ~clear_mask
    if a.active_sa_control:
        target = 0x100 if a.bdf == "0000:07:00.0" else 0x400
        clear_mask = target
        if expected_cc & target:
            raise RuntimeError("Active-SA control target was already disabled")
    if a.user_control:
        assert expected_cc | target == expected_cc | original
    plan = {"bdf": a.bdf, "register": "GC_USER_SA_UNIT_DISABLE" if a.user_control or a.active_sa_control else "CC_GC_SA_UNIT_DISABLE", "byte_offset": hex(register),
            "required_original": hex(original), "target": hex(target), "clear_mask": hex(clear_mask),
            "rollback": hex(original), "compute_dispatch": a.run_probe, "execute": a.execute}
    if not a.execute:
        print(json.dumps(plan, indent=2))
        return
    if os.geteuid() != 0:
        raise RuntimeError("Execute as root")
    if a.output.exists():
        raise RuntimeError("Evidence output already exists")
    a.output.mkdir(parents=True)
    journal = (a.output / "events.jsonl").open("x", buffering=1)

    def record(event, **kw):
        row = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   monotonic_ns=time.monotonic_ns(), event=event, **kw)
        journal.write(json.dumps(row) + "\n")
        journal.flush()
        os.fsync(journal.fileno())

    record("authorization", scope="User requested further invasive experiments after reviewing single-bit CC SA PoC", plan=plan)
    ledger = Path("/run/navi21-gfxoff-held.json")
    expected_holds = {f"/sys/kernel/debug/dri/{i}/amdgpu_gfxoff" for i in range(3)}
    if not ledger.exists() or set(json.loads(ledger.read_text())) != expected_holds:
        raise RuntimeError("Balanced operational GFXOFF hold required")
    found = []
    for i in range(3):
        dev = Path(f"/sys/class/drm/card{i}/device").resolve()
        if (dev / "vendor").read_text().strip() != "0x1002" or (dev / "device").read_text().strip() != "0x73bf":
            raise RuntimeError("Unexpected ASIC")
        clients = Path(f"/sys/kernel/debug/dri/{i}/clients").read_text()
        record("clients", card=i, text=clients)
        if len([s for s in clients.splitlines() if s.strip()]) > 1:
            raise RuntimeError("A GPU has active DRM clients")
        if dev.name == a.bdf:
            found.append(i)
    if len(found) != 1:
        raise RuntimeError("BDF mapping not unique")
    lock = Path("/run/navi21-invasive.lock").open("w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fd = os.open(f"/sys/kernel/debug/dri/{found[0]}/amdgpu_regs2", os.O_RDWR | os.O_CLOEXEC)

    def read(offset=register):
        b = os.pread(fd, 4, offset)
        if len(b) != 4:
            raise RuntimeError("Short register read")
        return struct.unpack("<I", b)[0]

    def write(value):
        if os.pwrite(fd, struct.pack("<I", value), register) != 4:
            raise RuntimeError("Short register write")

    def interrupted(signum, frame):
        raise InterruptedError(f"Signal {signum}")

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    changed = False
    result = dict(plan)
    try:
        before = read(REG)
        user_before = read(0x8928)
        record("baseline", cc=hex(before), user=hex(user_before))
        if before != expected_cc or user_before != 0:
            raise RuntimeError("Baseline differs from the reviewed trial")
        # Mark before entering the write syscall: even a partial/error path
        # must attempt to restore the saved, validated register exactly once.
        changed = True
        t0 = time.monotonic_ns()
        write(target)
        after = read()
        result.update(readback=hex(after), target_accepted=after == target,
                      write_readback_ns=time.monotonic_ns() - t0)
        record("write_readback", written=hex(target), readback=hex(after), elapsed_ns=result["write_readback_ns"])
        if a.run_probe:
            raise RuntimeError("The archived probe launcher is not included in the public tool")
    finally:
        if changed:
            try:
                # Do not allow ordinary process termination to interrupt this
                # one restoration attempt. Hardware recovery is not automatic.
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                    signal.signal(sig, signal.SIG_IGN)
                write(original)
                restored = read()
                user_after = read(0x8928)
                cc_after = read(REG)
                result.update(restored=hex(restored), user_after=hex(user_after),
                              cc_after=hex(cc_after),
                              rollback_verified=restored == original and user_after == user_before and cc_after == expected_cc)
                record("rollback", cc=hex(cc_after), user=hex(user_after), verified=result["rollback_verified"])
            except BaseException as error:
                result.update(rollback_verified=False, rollback_error=repr(error))
                record("rollback_error", error=repr(error))
        os.close(fd)
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        journal.close()
    print(json.dumps(result, indent=2))
    if not result.get("rollback_verified"):
        raise RuntimeError("Rollback not verified; stop all subsequent experiments")
    if result.get("readback") not in (hex(original), hex(target)):
        raise RuntimeError("Unexpected readback; stop all subsequent experiments")


if __name__ == "__main__":
    main()
