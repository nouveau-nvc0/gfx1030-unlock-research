#!/usr/bin/env python3
"""Emulate known X99-TF BDS ROM-policy routines offline; no hardware access.

Accept only the extracted 2020-05-25 reference BDS executables. Firmware code
runs in Unicorn memory with mocked UEFI variable/protocol services. This tests
the isolated policy path, not a complete firmware boot or a physical GPU.
Dependencies: pefile, unicorn (isolated tools directory, not host packages).
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import uuid

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
)

ALLOWED = {
    "3f32de7a09c09a24302f9f20b997622309507d7f561c8893e04833755e65954c",
    "c2e8315af4199c267380d419cf3ea369c1bdb9367402a2f040510358180df537",
}
BASE, STACK, SERVICES, STUBS = 0x1000000, 0x2000000, 0x3000000, 0x3100000
UNSUPPORTED = 0x8000000000000003
NOT_FOUND = 0x800000000000000E


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--module", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    data = args.module.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest not in ALLOWED:
        raise RuntimeError("Unknown BDS executable; fixed RVA experiment refused")
    image = pefile.PE(data=data).get_memory_mapped_image()
    samples = []
    for csm_present in (False, True):
        for policy in (0, 1, 2):
            u = Uc(UC_ARCH_X86, UC_MODE_64)
            u.mem_map(BASE, 0x20000)
            u.mem_write(BASE, image)
            u.mem_map(STACK, 0x20000)
            u.mem_map(SERVICES, 0x2000)
            u.mem_map(STUBS, 0x1000)
            events = []

            def qwrite(address, value):
                u.mem_write(address, struct.pack("<Q", value))

            def qread(address):
                return struct.unpack("<Q", u.mem_read(address, 8))[0]

            def ret(value=0, frame_size=0):
                sp = u.reg_read(UC_X86_REG_RSP) + frame_size
                target = qread(sp)
                u.reg_write(UC_X86_REG_RAX, value)
                u.reg_write(UC_X86_REG_RSP, sp + 8)
                u.reg_write(UC_X86_REG_RIP, target)

            qwrite(BASE + 0xE2C0, SERVICES)
            qwrite(BASE + 0xE2C8, SERVICES + 0x1000)
            qwrite(SERVICES + 0xB0, STUBS + 0x10)
            qwrite(SERVICES + 0x1000 + 0x48, STUBS + 0x20)
            setup = bytearray(0x72)
            setup[0x65] = int(csm_present)
            setup[0x6C] = policy

            def hook(uc, address, size, user_data):
                if address == BASE + 0x76EC:
                    # AMI library initialization was outside this scoped path.
                    ret()
                elif address == STUBS + 0x20:
                    assert uc.reg_read(UC_X86_REG_RCX) == BASE + 0x2048
                    guid = bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RDX), 16))
                    assert uuid.UUID(bytes_le=guid) == uuid.UUID("ec87d643-eba4-4bb5-a1e5-3f3e36b20da9")
                    sizeptr = uc.reg_read(UC_X86_REG_R9)
                    assert qread(sizeptr) == 0x72
                    buffer = qread(uc.reg_read(UC_X86_REG_RSP) + 0x28)
                    uc.mem_write(buffer, bytes(setup))
                    events.append("GetVariable(Setup), mocked input")
                    ret()
                elif address == STUBS + 0x10:
                    guid = bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RDX), 16))
                    assert uuid.UUID(bytes_le=guid) == uuid.UUID("db9a1e3d-45cb-4abb-853b-e5387fdb2e2d")
                    assert uc.reg_read(UC_X86_REG_RCX) == 2
                    events.append("LocateHandle(LegacyBios), mocked presence=" + str(csm_present))
                    ret(0 if csm_present else NOT_FOUND)
                elif address == BASE + 0x7FF4:
                    events.append("Deferred protocol-notification registration, mocked")
                    ret()
                elif address == BASE + 0xAC15:
                    # Execute the real callback through policy restoration;
                    # skip subsequent unrelated protocol/event allocation.
                    events.append("Real CSM callback copied original policy; remaining callback skipped")
                    ret(frame_size=0x58)

            u.hook_add(UC_HOOK_CODE, hook)
            u.reg_write(UC_X86_REG_RSP, STACK + 0x10000)
            # Begin immediately before the Setup read, after AMI-library setup.
            u.emu_start(BASE + 0x295E, BASE + 0x2A5A, count=1000)
            assert u.reg_read(UC_X86_REG_RIP) == BASE + 0x2A5A
            effective = u.mem_read(BASE + 0x7E3, 1)[0]
            assert effective == (policy if csm_present else 1)
            results = []
            for kind, selector in (("legacy", 0), ("uefi", 1)):
                sp = STACK + 0x10000
                qwrite(sp, STUBS + 0x100)
                u.reg_write(UC_X86_REG_RSP, sp)
                u.reg_write(UC_X86_REG_RCX, 3)  # PCI display class
                u.reg_write(UC_X86_REG_RDX, selector)
                u.emu_start(BASE + 0xA788, STUBS + 0x100, count=100)
                assert u.reg_read(UC_X86_REG_RIP) == STUBS + 0x100
                status = u.reg_read(UC_X86_REG_RAX)
                expected_allowed = (effective == 1 and selector == 1) or (effective == 2 and selector == 0)
                assert status == (0 if expected_allowed else UNSUPPORTED)
                results.append(dict(rom_kind=kind, efi_status=hex(status), allowed=status == 0))
            samples.append(dict(csm_protocol_present=csm_present, configured_video=policy,
                                effective_video=effective, mocked_services=events, results=results))
    result = dict(module_sha256=digest, scope="Offline emulation of original BDS policy instructions; mocked UEFI services; no physical hardware/firmware execution",
                  initialization_cases=len(samples), policy_cases=sum(len(s["results"]) for s in samples),
                  success=True, samples=samples)
    with args.output.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({k: result[k] for k in ("module_sha256", "initialization_cases", "policy_cases", "success")}))


if __name__ == "__main__":
    main()
