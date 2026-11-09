#!/usr/bin/env python3
"""Authorized transient WGP-disable readback control on an idle Navi21 GPU.

--execute tests WGP0's INACTIVE bit in one known-active SA, or CC low bit0,
takes a bank-isolation snapshot and restores the original. --run-probe adds
a bounded ordinary correctness/HW_ID dispatch with the USER disable only.
No enabling of nonphysical WGP, power policy, firmware or OTP writes.
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

TRIALS = {"0000:07:00.0": (0, 0xc01), "0000:04:00.0": (1, 0x301), "0000:0a:00.0": (1, 0x301)}
CC = 0x89bc
USER = 0x89c0
IOC = 0xc0282000


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bdf", choices=TRIALS, required=True)
    ap.add_argument("--register", choices=["cc", "user"], required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--clear-bit0-control", action="store_true", help="Clear CC low bit 0 only, preserving the WGP-disable field")
    ap.add_argument("--run-probe", action="store_true", help="For USER only: run the ordinary HW_ID/correctness shader before restoring")
    a = ap.parse_args()
    if a.execute:
        raise RuntimeError("Execution disabled in this public archive; review and adapt for an isolated research setup")
    se, expected_sa = TRIALS[a.bdf]
    offset = CC if a.register == "cc" else USER
    original = 0xffe00001 if a.register == "cc" else 0
    target = original | 0x10000
    if a.clear_bit0_control:
        if a.register != "cc" or a.run_probe:
            raise RuntimeError("Bit0 control applies only to CC, without dispatch")
        target = original & ~1
    if a.run_probe and a.register != "user":
        raise RuntimeError("Dispatch control applies only to USER")
    plan = dict(bdf=a.bdf, se=se, sh=0, register=a.register, byte_offset=hex(offset),
                original=hex(original), target=hex(target),
                action="CC low-bit0 readback" if a.clear_bit0_control else "disable WGP0 transiently",
                compute_dispatch=a.run_probe, execute=a.execute)
    if not a.execute:
        print(json.dumps(plan, indent=2))
        return
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    a.output.mkdir(parents=True, exist_ok=False)
    events = (a.output / "events.jsonl").open("x", buffering=1)

    def log(event, **kw):
        events.write(json.dumps(dict(event=event, utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                     monotonic_ns=time.monotonic_ns(), **kw)) + "\n")
        events.flush()
        os.fsync(events.fileno())

    log("authorized_plan", plan=plan)
    holds = json.loads(Path("/run/navi21-gfxoff-held.json").read_text())
    if set(holds) != {f"/sys/kernel/debug/dri/{i}/amdgpu_gfxoff" for i in range(3)}:
        raise RuntimeError("Balanced GFXOFF hold required")
    selected = []
    for i in range(3):
        dev = Path(f"/sys/class/drm/card{i}/device").resolve()
        if (dev / "device").read_text().strip() != "0x73bf" or (dev / "vendor").read_text().strip() != "0x1002":
            raise RuntimeError("Wrong ASIC")
        clients = Path(f"/sys/kernel/debug/dri/{i}/clients").read_text()
        log("clients", card=i, text=clients)
        if len([s for s in clients.splitlines() if s.strip()]) > 1:
            raise RuntimeError("GPU clients present")
        if dev.name == a.bdf:
            selected.append(i)
    if len(selected) != 1:
        raise RuntimeError("BDF mapping error")
    lock = Path("/run/navi21-invasive.lock").open("w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fd = os.open(f"/sys/kernel/debug/dri/{selected[0]}/amdgpu_regs2", os.O_RDWR | os.O_CLOEXEC)

    def select(s, h):
        fcntl.ioctl(fd, IOC, struct.pack("=10I", 0, 1, 0, s, h, 0xffffffff, 0, 0, 0, 0))

    def read(off):
        b = os.pread(fd, 4, off)
        if len(b) != 4:
            raise RuntimeError("Short read")
        return struct.unpack("<I", b)[0]

    def snap():
        rows = []
        for s in range(4):
            for h in range(2):
                select(s, h)
                c, u = read(CC), read(USER)
                if c == 0xffffffff or u == 0xffffffff:
                    raise RuntimeError("Inaccessible MMIO; stop")
                rows.append(dict(se=s, sh=h, cc=hex(c), user=hex(u)))
        return rows

    def write(v):
        select(se, 0)
        if os.pwrite(fd, struct.pack("<I", v), offset) != 4:
            raise RuntimeError("Short write")

    def interrupted(signum, frame):
        raise InterruptedError(f"Signal {signum}")

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    changed = False
    result = dict(plan)
    try:
        fcntl.ioctl(fd, IOC, bytes(40))
        if read(0x8924) != expected_sa or read(0x8928) != 0:
            raise RuntimeError("Unexpected global SA baseline")
        baseline = snap()
        if any(r["cc"] != "0xffe00001" or r["user"] != "0x0" for r in baseline):
            raise RuntimeError("Unexpected WGP baseline")
        log("baseline", banks=baseline)
        changed = True
        start = time.monotonic_ns()
        write(target)
        select(se, 0)
        value = read(offset)
        during = snap()
        result.update(readback=hex(value), target_accepted=value == target, during=during,
                      snapshot_window_ns=time.monotonic_ns() - start)
        if a.run_probe:
            raise RuntimeError("The archived probe launcher is not included in the public tool")
    finally:
        if changed:
            try:
                for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    signal.signal(sig, signal.SIG_IGN)
                write(original)
                restored = snap()
                fcntl.ioctl(fd, IOC, bytes(40))
                cc_sa, user_sa = read(0x8924), read(0x8928)
                verified = restored == baseline and cc_sa == expected_sa and user_sa == 0
                result.update(restored=restored, cc_sa_after=hex(cc_sa), user_sa_after=hex(user_sa), rollback_verified=verified)
                log("restored", result=result)
            except BaseException as error:
                result.update(rollback_verified=False, error=repr(error))
                log("rollback_error", error=repr(error))
        os.close(fd)
        (a.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        events.close()
    print(json.dumps({k: v for k, v in result.items() if k not in ["during", "restored"]}, indent=2))
    if not result.get("rollback_verified"):
        raise RuntimeError("Rollback failed; stop")
    if result.get("readback") not in (hex(original), hex(target)):
        raise RuntimeError("Unexpected readback; stop")


if __name__ == "__main__":
    main()
