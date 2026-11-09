#!/usr/bin/env python3
"""Allowlisted gfx1030 register reads. Default: no bank selection and no writes.

--banked requires separate user authorization: the kernel transiently writes
GRBM_GFX_INDEX while holding grbm_idx_mutex, then restores broadcast selection.
No harvesting, dispatch, RLC, SMU, clock, power, PCI, or firmware writes exist here.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import struct


# Linux v7.3.1 gc_10_3_0_offset.h and sienna_cichlid_ip_offset.h.
# Offsets below are DWORD offsets; debugfs expects byte offsets.
GLOBAL = {
    "CC_GC_SA_UNIT_DISABLE": (0x1260, 0x0fe9),
    "GC_USER_SA_UNIT_DISABLE": (0x1260, 0x0fea),
    "GB_ADDR_CONFIG": (0x1260, 0x13de),
    "GRBM_GFX_INDEX": (0xa000, 0x2200),
    "CGTS_TCC_DISABLE": (0xa000, 0x5006),
    "CGTS_USER_TCC_DISABLE": (0xa000, 0x5007),
}
BANKED = {
    "GRBM_GFX_INDEX": (0xa000, 0x2200),
    "CC_GC_SHADER_ARRAY_CONFIG": (0x1260, 0x100f),
    "GC_USER_SHADER_ARRAY_CONFIG": (0x1260, 0x1010),
    "SPI_PG_ENABLE_STATIC_WGP_MASK": (0x1260, 0x1277),
    "RLC_PG_ALWAYS_ON_WGP_MASK": (0xa000, 0x4c53),
    "CC_RB_BACKEND_DISABLE": (0x1260, 0x13dd),
    "GC_USER_RB_BACKEND_DISABLE": (0x1260, 0x147f),
}


def read_register(fd, address):
    data = os.pread(fd, 4, 4 * sum(address))
    if len(data) != 4:
        raise RuntimeError("Short MMIO read")
    return struct.unpack("<I", data)[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--banked", action="store_true", help="Separate selector-write authorization required")
    a = ap.parse_args()
    # Runtime PM alone does not wake GC from GFXOFF on these boards. An ordinary
    # balanced operational hold is a prerequisite, owned outside this reader.
    ledger = Path("/run/navi21-gfxoff-held.json")
    expected = {f"/sys/kernel/debug/dri/{i}/amdgpu_gfxoff" for i in range(3)}
    if not ledger.exists() or set(json.loads(ledger.read_text())) != expected:
        raise RuntimeError("Acquire the standard balanced GFXOFF hold before MMIO reads")
    result = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "mode": "kernel-locked banked reads" if a.banked else "unbanked reads, no ioctl, no selector writes", "gpus": []}
    for i in range(3):
        dev = Path(f"/sys/class/drm/card{i}/device").resolve()
        if (dev / "vendor").read_text().strip() != "0x1002" or (dev / "device").read_text().strip() != "0x73bf":
            raise RuntimeError("Unexpected ASIC: fail closed")
        node = f"/sys/kernel/debug/dri/{i}/amdgpu_regs2"
        fd = os.open(node, os.O_RDONLY | os.O_CLOEXEC)
        try:
            gpu = {"card": i, "bdf": dev.name, "global": {}, "banks": []}
            for n, addr in GLOBAL.items():
                gpu["global"][n] = {"byte_offset": hex(4 * sum(addr)), "value": hex(read_register(fd, addr))}
                if gpu["global"][n]["value"] == "0xffffffff":
                    raise RuntimeError(f"Inaccessible MMIO at {dev.name}/{n}; stop, do not interpret as a fuse mask")
            cc_sa = int(gpu["global"]["CC_GC_SA_UNIT_DISABLE"]["value"], 16)
            user_sa = int(gpu["global"]["GC_USER_SA_UNIT_DISABLE"]["value"], 16)
            disabled_sa = ((cc_sa | user_sa) >> 8) & 0xff
            gpu["decoded"] = {"cc_disabled_sa_mask": (cc_sa >> 8) & 0xff,
                              "user_disabled_sa_mask": (user_sa >> 8) & 0xff,
                              "effective_disabled_sa_mask": disabled_sa}
            if a.banked:
                # UAPI amdgpu_debugfs_regs2_iocdata: use_srbm,use_grbm,pg_lock,
                # grbm{se,sh,instance}, srbm{me,pipe,queue,vmid}. V1, 10 u32.
                # ioctl changes fd metadata only; each pread selects its bank
                # under the kernel mutex and restores 0xffffffff broadcast.
                for se in range(4):
                    for sh in range(2):
                        state = struct.pack("=10I", 0, 1, 0, se, sh, 0xffffffff, 0, 0, 0, 0)
                        fcntl.ioctl(fd, 0xc0282000, state)
                        bank = {"se": se, "sh": sh, "registers": {}}
                        for n, addr in BANKED.items():
                            bank["registers"][n] = {"byte_offset": hex(4 * sum(addr)), "value": hex(read_register(fd, addr))}
                        cc_wgp = int(bank["registers"]["CC_GC_SHADER_ARRAY_CONFIG"]["value"], 16)
                        user_wgp = int(bank["registers"]["GC_USER_SHADER_ARRAY_CONFIG"]["value"], 16)
                        if cc_wgp == 0xffffffff or user_wgp == 0xffffffff:
                            raise RuntimeError("Inaccessible bank; stop rather than decode all-ones data")
                        eligible = (~((cc_wgp | user_wgp) >> 16)) & 0x1f
                        bank["decoded"] = {"wgp_eligible_mask": eligible,
                                           "sa_disabled": bool(disabled_sa & (1 << (se * 2 + sh))),
                                           "effective_wgp_mask": 0 if disabled_sa & (1 << (se * 2 + sh)) else eligible,
                                           "register_read_is_not_proof_of_execution": True}
                        gpu["banks"].append(bank)
                # Disable bank selection on this fd before reading GRBM index.
                fcntl.ioctl(fd, 0xc0282000, bytes(40))
                gpu["grbm_after"] = hex(read_register(fd, GLOBAL["GRBM_GFX_INDEX"]))
            result["gpus"].append(gpu)
        finally:
            os.close(fd)
    with a.output.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"output": str(a.output), "mode": result["mode"], "gpus": len(result["gpus"])}))


if __name__ == "__main__":
    main()
