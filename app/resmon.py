"""Background per-account resource sampler for the WHM Resource Usage page.

Shared hosting runs PHP-FPM as `pm = ondemand`, so an idle account has *no*
processes at all — a single instantaneous /proc read almost always sees zero.
That makes a live table look broken even though it's accurate for that split
second. This module samples every couple of seconds in a daemon thread and keeps,
per account, both the latest value and a short rolling peak, so bursty FPM
workers get caught and an admin sees "who's been heavy in the last minute" even
without staring at the page.

It is deliberately tiny and defensive: one short-lived sample per tick, every
exception swallowed, a daemon thread that never blocks shutdown. The sampler
callback is injected (it calls the active provider + DB), so this module stays
free of app imports and is trivial to reason about.
"""
from __future__ import annotations

import threading
import time
from typing import Callable

_LOCK = threading.Lock()
_STATE: dict[str, dict] = {}   # system_user -> live + peak numbers
_PEAK_WINDOW = 60.0            # seconds a peak survives before it decays away
_INTERVAL = 2.0               # sample cadence
_started = False


def _merge(sample: dict[str, dict]) -> None:
    now = time.time()
    with _LOCK:
        for user, u in sample.items():
            s = _STATE.get(user, {})
            cpu = float(u.get("cpu", 0.0))
            mem = float(u.get("mem_mb", 0.0))
            # Decay a stale peak, then raise it to the current value if higher.
            if now - s.get("peak_cpu_ts", 0.0) > _PEAK_WINDOW:
                s["peak_cpu"] = 0.0
            if now - s.get("peak_mem_ts", 0.0) > _PEAK_WINDOW:
                s["peak_mem_mb"] = 0.0
            if cpu >= s.get("peak_cpu", 0.0):
                s["peak_cpu"], s["peak_cpu_ts"] = cpu, now
            if mem >= s.get("peak_mem_mb", 0.0):
                s["peak_mem_mb"], s["peak_mem_ts"] = mem, now
            s.update(cpu=cpu, mem_mb=mem, procs=int(u.get("procs", 0)), ts=now)
            _STATE[user] = s


def snapshot() -> dict[str, dict]:
    """Current per-account numbers + rolling peaks. Empty until the first tick."""
    with _LOCK:
        return {k: dict(v) for k, v in _STATE.items()}


def start(sampler: Callable[[], dict[str, dict]], interval: float = _INTERVAL) -> None:
    """Start the daemon sampler once. `sampler()` returns {system_user: {...}}."""
    global _started
    if _started:
        return
    _started = True

    def _loop() -> None:
        while True:
            try:
                _merge(sampler() or {})
            except Exception:  # noqa: BLE001 — a bad tick must never kill the thread
                pass
            time.sleep(interval)

    threading.Thread(target=_loop, name="litespanel-resmon", daemon=True).start()
