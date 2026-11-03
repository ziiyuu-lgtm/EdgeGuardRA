"""Best-effort, non-identifying inventory for local reproducibility."""
from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
import platform
import sqlite3
import sys
import time


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None


def collect_environment() -> dict:
    """Report interpreter, visible hardware and Linux limits, without host names."""
    cpu = platform.processor() or "not reported"
    cpuinfo = _read("/proc/cpuinfo")
    if cpuinfo:
        cpu = next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines()
                    if line.startswith("model name") and ":" in line), cpu)
    memory = None
    for line in (_read("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            memory = int(line.split()[1]) * 1024
            break
    try:
        affinity = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        affinity = None
    dependencies = {}
    for name in ("pip", "setuptools", "wheel", "matplotlib", "numpy", "contourpy",
                 "cycler", "fonttools", "kiwisolver", "packaging", "pillow",
                 "pyparsing", "python-dateutil", "six"):
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            dependencies[name] = None
    timer = time.get_clock_info("perf_counter")
    return {
        "python": sys.version.split()[0], "implementation": platform.python_implementation(),
        "sqlite": sqlite3.sqlite_version, "system": platform.system(),
        "kernel": platform.release(), "architecture": platform.machine(),
        "libc": list(platform.libc_ver()), "cpu_model": cpu,
        "logical_cpus_visible": os.cpu_count(), "affinity_cpus": affinity,
        "host_memory_bytes_visible": memory,
        "cgroup_cpu_max": _read("/sys/fs/cgroup/cpu.max"),
        "cgroup_memory_max": _read("/sys/fs/cgroup/memory.max"),
        "perf_counter_resolution_seconds": timer.resolution,
        "perf_counter_monotonic": timer.monotonic,
        "packages": dependencies,
        "hardware_scope": "Guest-visible inventory; shared host, storage and scheduling are not controlled."
    }


def check_environment(lock_path: str | Path) -> dict:
    """Compare the interpreter, SQLite and installed plot dependencies to a lock."""
    import json
    with Path(lock_path).open("rb") as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ValueError("environment lock exceeds 65536 bytes")
    try:
        lock = json.loads(raw)
        expected = lock["required"]
        if (type(expected) is not dict or
            any(type(expected.get(k)) is not str for k in ("python", "implementation", "sqlite")) or
            type(expected.get("packages")) is not dict or
            any(type(k) is not str or type(v) is not str for k, v in expected["packages"].items())):
            raise ValueError("invalid environment lock")
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid environment lock") from exc
    actual = collect_environment()
    mismatches = []
    for name in ("python", "implementation", "sqlite"):
        if actual[name] != expected[name]:
            mismatches.append({"component": name, "expected": expected[name], "actual": actual[name]})
    for name, version in expected["packages"].items():
        if actual["packages"].get(name) != version:
            mismatches.append({"component": name, "expected": version,
                               "actual": actual["packages"].get(name)})
    return {"matches": not mismatches, "mismatches": mismatches,
            "scope": "Interpreter, SQLite and package versions only; hardware equality is not asserted."}
