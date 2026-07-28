"""Lightweight host metrics — real CPU/memory without psutil.

Uses ctypes on Windows and /proc on Linux, so it stays dependency-free and
keeps the panel's footprint tiny (the whole point on a small VPS). CPU is a
short (~0.1s) sample taken per call, which is accurate enough for a dashboard
and cheap enough to run on each page load.
"""
from __future__ import annotations

import sys
import time

_IS_WINDOWS = sys.platform.startswith("win")


# --------------------------------------------------------------------------
# CPU
# --------------------------------------------------------------------------
def _cpu_times() -> tuple[int, int]:
    """Return (total, idle) CPU tick counters for this instant."""
    if _IS_WINDOWS:
        return _win_cpu_times()
    return _linux_cpu_times()


def cpu_percent(interval: float = 0.1) -> float:
    """Busy CPU percentage sampled over `interval` seconds."""
    try:
        total1, idle1 = _cpu_times()
        time.sleep(interval)
        total2, idle2 = _cpu_times()
        total_d = total2 - total1
        idle_d = idle2 - idle1
        if total_d <= 0:
            return 0.0
        return round(max(0.0, (1 - idle_d / total_d)) * 100, 1)
    except Exception:  # noqa: BLE001 — metrics must never break the dashboard
        return 0.0


def _linux_cpu_times() -> tuple[int, int]:
    with open("/proc/stat") as f:
        parts = f.readline().split()
    values = [int(x) for x in parts[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle + iowait
    return sum(values), idle


def _win_cpu_times() -> tuple[int, int]:
    import ctypes
    from ctypes import wintypes

    class FILETIME(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    def _as_int(ft: "FILETIME") -> int:
        return (ft.high << 32) | ft.low

    idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
    ctypes.windll.kernel32.GetSystemTimes(
        ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
    )
    # On Windows, kernel time already includes idle time.
    total = _as_int(kernel) + _as_int(user)
    return total, _as_int(idle)


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------
def mem_percent() -> float:
    """Used physical memory as a percentage."""
    try:
        if _IS_WINDOWS:
            return _win_mem_percent()
        return _linux_mem_percent()
    except Exception:  # noqa: BLE001
        return 0.0


def _linux_mem_percent() -> float:
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, _, rest = line.partition(":")
            info[key] = int(rest.split()[0])  # kB
    total = info["MemTotal"]
    available = info.get("MemAvailable", info["MemFree"])
    return round((total - available) / total * 100, 1)


def _win_mem_percent() -> float:
    import ctypes
    from ctypes import wintypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(stat)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    return float(stat.dwMemoryLoad)  # already a 0–100 percentage
