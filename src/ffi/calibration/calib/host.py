"""Host facts and the quiet-machine gate: memory, load, competing builds, and a hardware record for the results."""

from __future__ import annotations

import os
import platform
import re
import subprocess
import time

BUSY_COMMANDS = ("cargo", "rustc", "dotnet", "testhost", "VBCSCompiler", "batch_bench", "agg_bench", "gas_bench")


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def memory() -> dict:
    """Bytes of physical memory, memory a new process can take without swapping others out, and swap in use."""
    if platform.system() == "Linux":
        info = {}
        for line in open("/proc/meminfo"):
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0]) * 1024
        return {"total": info["MemTotal"], "available": info["MemAvailable"],
                "swap_used": info.get("SwapTotal", 0) - info.get("SwapFree", 0)}
    total = int(_run(["sysctl", "-n", "hw.memsize"]).strip() or 0)
    vm = _run(["vm_stat"])
    page = int(re.search(r"page size of (\d+)", vm).group(1)) if "page size of" in vm else 16384

    def pages(name: str) -> int:
        m = re.search(rf"{name}:\s+(\d+)", vm)
        return int(m.group(1)) if m else 0

    swap = _run(["sysctl", "-n", "vm.swapusage"])
    m = re.search(r"used = ([0-9.]+)M", swap)
    return {"total": total, "available": (pages("Pages free") + pages("Pages inactive") + pages("Pages purgeable")) * page,
            "swap_used": int(float(m.group(1)) * 2**20) if m else 0}


def load1() -> float:
    return os.getloadavg()[0]


def busy_processes(ignore: set[int]) -> list[str]:
    """Other build, test or benchmark processes doing work (> 5% CPU)."""
    out = []
    for line in _run(["ps", "-Ao", "pid=,pcpu=,comm="]).splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, cpu, comm = int(parts[0]), float(parts[1]), os.path.basename(parts[2].strip())
        if pid in ignore or cpu <= 5.0:
            continue
        if any(comm == c or comm.startswith(c) for c in BUSY_COMMANDS):
            out.append(f"{pid}:{comm}:{cpu}")
    return out


def wait_quiet(max_load: float, timeout_s: int, ignore: set[int] | None = None, poll_s: int = 15) -> dict:
    """Waits until no competing process is busy and the 1-minute load is below `max_load`."""
    ignore = (ignore or set()) | {os.getpid()}
    waited = 0
    while True:
        busy, l1 = busy_processes(ignore), load1()
        if not busy and l1 < max_load:
            return {"waited_s": waited, "load1": l1, "quiet": True}
        if waited >= timeout_s:
            return {"waited_s": waited, "load1": l1, "quiet": False, "busy": busy}
        time.sleep(poll_s)
        waited += poll_s


def record() -> dict:
    """The hardware and software a result was measured on."""
    system = platform.system()
    rec = {"system": system, "release": platform.release(), "machine": platform.machine(), "cpus": os.cpu_count(),
           "memory": memory(), "load1": load1(), "hostname": platform.node()}
    if system == "Darwin":
        rec["cpu"] = _run(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
        rec["perf_cores"] = _run(["sysctl", "-n", "hw.perflevel0.physicalcpu"]).strip()
        rec["efficiency_cores"] = _run(["sysctl", "-n", "hw.perflevel1.physicalcpu"]).strip()
    else:
        rec["lscpu"] = _run(["lscpu"])
        rec["kernel"] = _run(["uname", "-a"]).strip()
    rec["rustc"] = _run(["rustc", "-V"]).strip()
    return rec
