#!/usr/bin/env python3
"""Collect cached AMDGPU topology and allowlisted read-only diagnostics.

Never opens MMIO, PCI ROM, amdgpu_regs*, SMU, PSP, or sysfs controls for writing.
The public collector records GPU topology and version data only.
Run as root for debugfs; all output goes below --output.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess


def command(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=45)
    return {"argv": args, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    result = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "gpus": []}

    def save(src, dest):
        try:
            data = src.read_bytes()
            if dest.endswith("-properties.txt"):
                data = ("\n".join(line for line in data.decode().splitlines()
                                  if not re.match(r"^(?:unique_id|gpu_id)\s", line)) + "\n").encode()
            target = a.output / dest
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            return {"file": dest, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        except (OSError, ValueError) as e:
            return {"source": str(src), "error": str(e)}

    result["os"] = save(Path("/etc/os-release"), "os-release.txt")
    result["kernel_release"] = command(["uname", "-r"])
    packages = command(["rpm", "-qa"])
    packages["stdout"] = "\n".join(x for x in packages["stdout"].splitlines()
                                      if re.match(r"(kernel-default|kernel-firmware-amdgpu|Mesa|libdrm|libvulkan|rocm|umr)", x))
    result["packages"] = packages
    result["module"] = command(["modinfo", "amdgpu"])
    # Root-only journal may contain unrelated service messages: retain GPU/kernel errors only.
    journal = command(["journalctl", "-k", "-b", "--no-pager", "-o", "cat"])
    journal["stdout"] = "\n".join(x for x in journal["stdout"].splitlines()
                                    if re.search(r"amdgpu|kfd|GPU reset|GPU fault|ring .*timeout", x, re.I))
    result["kernel_gpu_log"] = journal
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        if not re.fullmatch(r"card\d+", card.name):
            continue
        dev = (card / "device").resolve()
        if (dev / "vendor").read_text().strip() != "0x1002":
            continue
        i = int(card.name[4:])
        gpu = {"card": card.name, "bdf": dev.name, "sysfs": {}, "debugfs": {}, "pcie_path": []}
        dest = card.name
        for n in ["vendor", "device", "subsystem_vendor", "subsystem_device", "revision", "vbios_version",
                  "product_name", "mem_info_vram_total", "mem_info_vram_used",
                  "mem_info_vis_vram_total", "mem_info_gtt_total", "gpu_busy_percent", "mem_busy_percent",
                  "current_link_speed", "current_link_width", "max_link_speed", "max_link_width",
                  "pp_dpm_sclk", "pp_dpm_mclk", "power_dpm_force_performance_level", "pp_features"]:
            f = dev / n
            if f.exists():
                gpu["sysfs"][n] = save(f, f"{dest}/sysfs-{n}.txt")
        for p in [dev, *dev.parents]:
            if re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", p.name):
                entry = {"bdf": p.name}
                for n in ["current_link_speed", "current_link_width", "max_link_speed", "max_link_width"]:
                    if (p / n).exists():
                        entry[n] = (p / n).read_text().strip()
                gpu["pcie_path"].append(entry)
        dbg = Path(f"/sys/kernel/debug/dri/{i}")
        for n in ["name", "amdgpu_gca_config", "amdgpu_firmware_info", "amdgpu_vbios", "amdgpu_pm_info"]:
            gpu["debugfs"][n] = save(dbg / n, f"{dest}/{n}.{'bin' if n in ['amdgpu_gca_config', 'amdgpu_vbios'] else 'txt'}")
        gpu["lspci"] = command(["lspci", "-Dnnvv", "-s", dev.name])
        gpu["lspci"]["stdout"] = "\n".join(line for line in gpu["lspci"]["stdout"].splitlines()
                                                if "Device Serial Number" not in line)
        result["gpus"].append(gpu)
    for node in sorted(Path("/sys/class/kfd/kfd/topology/nodes").glob("*")):
        for n in ["properties", "name"]:
            if (node / n).exists():
                save(node / n, f"kfd/node{node.name}-{n}.txt")
    (a.output / "inventory.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(a.output), "gpus": [{k: g.get(k) for k in ["card", "bdf", "render", "dev_info"]} for g in result["gpus"]]}, indent=2))


if __name__ == "__main__":
    main()
