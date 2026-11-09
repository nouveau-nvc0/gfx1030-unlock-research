#!/usr/bin/env python3
"""Offline VFCT selection replay against a saved inventory; no device access."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("evidence", type=Path)
    a = ap.parse_args()
    p = a.evidence
    raw = (p / "acpi-VFCT.bin").read_bytes()
    assert raw[:4] == b"VFCT"
    length = struct.unpack_from("<I", raw, 4)[0]
    assert length == len(raw)
    assert sum(raw) % 256 == 0
    start, lib = struct.unpack_from("<II", raw, 52)
    off = start
    entries = []
    while off + 28 <= length:
        bus, dev, fn, vendor, device, ssvid, ssid, rev, n = struct.unpack_from("<IIIHHHHII", raw, off)
        assert off + 28 + n <= length
        data = raw[off + 28:off + 28 + n]
        entry = dict(offset=off, bdf=f"0000:{bus:02x}:{dev:02x}.{fn}", bus=bus, dev=dev, fn=fn,
                     vendor=vendor, device=device, ssvid=ssvid, ssid=ssid, revision=rev,
                     bytes=n, sha256=sha(data), empty=not n)
        if n:
            assert data[:2] == b"\x55\xaa"
            entry["vbios_identifiers"] = [s.decode("ascii") for s in re.findall(rb"113-[A-Za-z0-9_-]+", data)]
            h = struct.unpack_from("<H", data, 0x48)[0]
            entry["rom_subsystem"] = "%04x:%04x" % struct.unpack_from("<HH", data, h + 24)
        entries.append(entry)
        off += 28 + n
    assert off == length
    inventory = json.loads((p / "initial/inventory.json").read_text())
    decisions = []
    for g in inventory["gpus"]:
        bus = int(g["bdf"][5:7], 16)
        dev = int(g["bdf"][8:10], 16)
        fn = int(g["bdf"][11:], 16)
        candidates = [e for e in entries if e["bytes"] and e["vendor"] == 0x1002 and
                      e["device"] == 0x73bf and e["dev"] == dev and e["fn"] == fn]
        old = candidates[0]  # Running soft-filter loop returns at its first identity match.
        exact = [e for e in candidates if e["bus"] == bus]
        assert len(exact) == 1
        loaded = (p / "initial" / g["card"] / "amdgpu_vbios.bin").read_bytes()
        live_pp = (p / (g["card"] + "-pp_table.bin")).read_bytes()
        native_pp = (p / f"vfct-{bus:02x}-{dev:02x}-{fn}-powerplay.bin").read_bytes()
        selected_pp = (p / f"vfct-{old['bus']:02x}-{dev:02x}-{fn}-powerplay.bin").read_bytes()
        decisions.append(dict(card=g["card"], bdf=g["bdf"], cached_vbios_sha256=sha(loaded),
                              old_algorithm_bdf=old["bdf"], old_algorithm_sha256=old["sha256"],
                              exact_bdf=exact[0]["bdf"], exact_sha256=exact[0]["sha256"],
                              loaded_matches_old=sha(loaded) == old["sha256"],
                              loaded_matches_exact=sha(loaded) == exact[0]["sha256"],
                              live_pp_sha256=sha(live_pp), expected_pp_sha256=sha(native_pp),
                              live_pp_matches_selected=live_pp == selected_pp,
                              physical_rom="Not directly read. VFCT is the firmware POST copy, not an independent flash dump."))
    assert all(d["loaded_matches_old"] and d["live_pp_matches_selected"] for d in decisions)
    lines = inventory["kernel_gpu_log"]["stdout"].splitlines()
    out = dict(vfct_length=length, checksum_valid=True, vbios_image_offset=start,
               lib1_image_offset=lib, all_entries=entries, devices=decisions,
               boot_messages=[s for s in lines if any(t in s for t in ["VFCT", "ATOM BIOS"])])
    (p / "vfct-selection-audit.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(decisions, indent=2))


if __name__ == "__main__":
    main()
