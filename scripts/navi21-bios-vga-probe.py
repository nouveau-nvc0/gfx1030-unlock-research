#!/usr/bin/env python3
"""Offline Unicorn experiment on the known X99-TF legacy VGA selector.

Mock three discrete VGA controllers and vary enumeration order. This executes
selection code only, with no physical GPU access or ROM initialization.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP

BASE, STACK, BS, RT, STUB, DATA = 0x1000000, 0x2000000, 0x3000000, 0x3001000, 0x3100000, 0x4000000
EXPECTED = "3a5ff822ee5bffea5b56349e661031b94fbaad8d8cf6967c621c559879d47aa3"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--module", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    binary = a.module.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    if digest != EXPECTED:
        raise RuntimeError("Unknown CsmDxe image; fixed RVA experiment refused")
    image = pefile.PE(data=binary).get_memory_mapped_image()
    samples = []
    cards = ["0000:04:00.0", "0000:07:00.0", "0000:0a:00.0"]
    for order in itertools.permutations(cards):
        u = Uc(UC_ARCH_X86, UC_MODE_64)
        for base, size in [(BASE, 0x20000), (STACK, 0x20000), (BS, 0x2000), (STUB, 0x1000), (DATA, 0x40000)]:
            u.mem_map(base, size)
        u.mem_write(BASE, image)

        def put(address, value):
            u.mem_write(address, struct.pack("<Q", value))

        def get(address):
            return struct.unpack("<Q", u.mem_read(address, 8))[0]

        handles = {card: 0x5000000 + i * 0x1000 for i, card in enumerate(cards)}
        pciio = {handles[card]: DATA + 0x2000 + i * 0x200 for i, card in enumerate(cards)}
        put(BASE + 0xAA88, BS)
        put(BASE + 0xAA90, RT)
        for offset, stub in [(0x138, 0x10), (0x98, 0x20), (0x48, 0x30), (0x140, 0x40)]:
            put(BS + offset, STUB + stub)
        put(RT + 0x48, STUB + 0x50)
        put(RT + 0x58, STUB + 0x60)  # Fail if the selector tries SetVariable.
        for address in pciio.values():
            for offset, stub in [(0x30, 0x70), (0x78, 0x80), (0x70, 0x90)]:
                put(address + offset, STUB + stub)
        for i, card in enumerate(order):
            put(DATA + 0x13000 + i * 8, handles[card])
        put(DATA + 0x10000, DATA + 0x11000)
        put(DATA + 0x18000, DATA + 0x20000)
        u.mem_write(DATA + 0x20000 + 0x167D, b"\x01")
        u.mem_write(DATA + 0x20000 + 0x10B5, b"\x00\xff")
        setup = bytearray(0x17CB)
        setup[0x4F] = 2  # IntelSetup Active Video = Offboard.
        events = []

        def hook(uc, address, size, user_data):
            if not STUB <= address < STUB + 0x100:
                return
            sp = uc.reg_read(UC_X86_REG_RSP)
            arg5 = get(sp + 0x28)
            rcx, rdx, r8, r9 = [uc.reg_read(reg) for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
            which = address - STUB
            if which == 0x10:  # LocateHandleBuffer(ByProtocol, PciIo)
                assert rcx == 2 and bytes(uc.mem_read(rdx, 16)) == binary[0x300:0x310]
                put(r9, 3)
                put(arg5, DATA + 0x13000)
            elif which == 0x20:  # HandleProtocol(PciIo)
                assert bytes(uc.mem_read(rdx, 16)) == binary[0x300:0x310]
                put(r8, pciio[rcx])
            elif which == 0x30:  # FreePool, mocked static allocation
                pass
            elif which == 0x40:  # LocateProtocol, CPU/root-bus information
                assert bytes(uc.mem_read(rcx, 16)) == binary[0x4D0:0x4E0]
                put(r8, DATA + 0x18000)
            elif which == 0x50:  # GetVariable(IntelSetup)
                assert rcx == BASE + 0xFB0 and get(r9) == len(setup)
                uc.mem_write(arg5, bytes(setup))
            elif which == 0x60:
                raise RuntimeError("Unexpected SetVariable in offline selection path")
            elif which == 0x70:  # Pci.Read: class/revision dword
                assert rdx == 2 and r8 == 8 and r9 == 1
                uc.mem_write(arg5, struct.pack("<I", 0x03000000))
            elif which == 0x80:  # Attributes(Get): all controllers offboard
                put(r9, 0)
            elif which == 0x90:  # GetLocation
                handle = next(h for h, p in pciio.items() if p == rcx)
                card = next(c for c, h in handles.items() if h == handle)
                put(rdx, 0)
                put(r8, int(card[5:7], 16))
                put(r9, 0)
                put(arg5, 0)
                events.append("GetLocation " + card)
            else:
                raise RuntimeError("Unexpected mocked UEFI service")
            uc.reg_write(UC_X86_REG_RAX, 0)
            uc.reg_write(UC_X86_REG_RIP, get(sp))
            uc.reg_write(UC_X86_REG_RSP, sp + 8)

        u.hook_add(UC_HOOK_CODE, hook)
        sp = STACK + 0x10000
        put(sp, STUB + 0x800)
        put(sp + 0x28, DATA + 0x12000)
        put(sp + 0x30, 0)
        for reg, value in [(UC_X86_REG_RSP, sp), (UC_X86_REG_RCX, DATA), (UC_X86_REG_RDX, 0), (UC_X86_REG_R8, 0), (UC_X86_REG_R9, DATA + 0x10000)]:
            u.reg_write(reg, value)
        u.emu_start(BASE + 0xA3DC, STUB + 0x800, count=5000)
        assert u.reg_read(UC_X86_REG_RIP) == STUB + 0x800
        status, count, selected = u.reg_read(UC_X86_REG_RAX), get(DATA + 0x12000), get(DATA + 0x11000)
        assert status == 0 and count == 1 and selected == handles[order[0]]
        samples.append(dict(enumeration_order=list(order), selected=order[0], selected_count=count,
                            efi_status=hex(status), events=events))
    result = dict(module_sha256=digest, success=True, cases=len(samples),
                  scope="Offline original VGA-selection instructions with mocked PCI/UEFI data; no ROM execution and no physical GPU access",
                  result="Offboard policy selects one VGA, the first enumerated discrete card; this does not guarantee its physical identity on the board", samples=samples)
    with a.output.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({k: result[k] for k in ("module_sha256", "success", "cases", "result")}))


if __name__ == "__main__":
    main()
