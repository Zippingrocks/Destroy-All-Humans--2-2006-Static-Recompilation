"""Sample DAH2's per-frame phase timings from a running process, read-only.

    py -3 tools/sample_present_timing.py --pid PID --map dah2_recomp.map \
        --seconds 90 --csv timing.csv

dah2_guest_gpu_present() publishes the phase timings of the most recent frame
(QPC ticks) in g_dah2_present_timing_*: how long the game ran since the last
present (guest), how long the 30 Hz limiter waited (cap), and the GPU command
translation (commit), flush and swap costs. A frame misses its 33.3 ms deadline
only when guest + commit + flush + swap exceeds the period; cap is idle time and
is excluded. This samples those globals without suspending the process and
prints which phase dominates the slow frames, split into windows of N frames.

The poll uses a per-timer high-resolution waitable timer, so it does not change
the system-wide timer resolution (which would perturb other running processes).
Frames that complete between two polls are detected through the sample counter
and reported as missed; their phases are lost but they still count for FPS.
"""
from __future__ import annotations

import argparse
import ctypes
import statistics
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva  # noqa: E402

NAMES = ["samples", "frequency", "guest", "cap", "commit", "flush", "swap", "total"]


def high_res_timer():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateWaitableTimerExW.restype = ctypes.c_void_p
    k.CreateWaitableTimerExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    h = k.CreateWaitableTimerExW(None, None, 0x2, 0x1F0003)  # HIGH_RESOLUTION | ALL_ACCESS
    k.SetWaitableTimer.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong), ctypes.c_long,
                                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    def wait_ms(ms: float):
        due = ctypes.c_longlong(-int(ms * 10000))
        k.SetWaitableTimer(h, ctypes.byref(due), 0, None, None, 0)
        k.WaitForSingleObject(h, 1000)
    return wait_ms


def pct(values, p):
    return sorted(values)[min(len(values) - 1, int(len(values) * p))] if values else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--map", type=Path, required=True)
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--poll-ms", type=float, default=4)
    ap.add_argument("--window", type=int, default=300, help="frames per summary window")
    ap.add_argument("--csv", type=Path)
    a = ap.parse_args()

    rvas = [symbol_rva(a.map, "g_dah2_present_timing_" + n) for n in NAMES]
    contiguous = all(rvas[i + 1] - rvas[i] == 8 for i in range(len(rvas) - 1))
    reader = Reader(a.pid, suspend=False)
    wait = high_res_timer()

    def snapshot():
        if contiguous:
            return struct.unpack("<8Q", reader.read(reader.base + rvas[0], 64))
        return tuple(struct.unpack("<Q", reader.read(reader.base + r, 8))[0] for r in rvas)

    rows, missed, last = [], 0, None
    t0 = time.perf_counter()
    try:
        while time.perf_counter() - t0 < a.seconds:
            v = snapshot()
            if v[0] != 0 and (last is None or v[0] != last):
                if last is not None and v[0] - last > 1:
                    missed += v[0] - last - 1
                last = v[0]
                tick = 1000.0 / v[1] if v[1] else 0.0
                rows.append((time.perf_counter() - t0, v[0], v[2] * tick, v[3] * tick,
                             v[4] * tick, v[5] * tick, v[6] * tick, v[7] * tick))
            wait(a.poll_ms)
    finally:
        reader.close()

    if not rows:
        print("no samples (process not presenting yet, or wrong pid/map)")
        return 1
    if a.csv:
        with a.csv.open("w", encoding="utf-8") as fh:
            fh.write("t_s,frame,guest_ms,cap_ms,commit_ms,flush_ms,swap_ms,total_ms\n")
            for r in rows:
                fh.write(",".join("%.4f" % x if isinstance(x, float) else str(x) for x in r) + "\n")

    span = rows[-1][0] - rows[0][0]
    frames = rows[-1][1] - rows[0][1]
    print("frames %d..%d in %.1fs => %.2f fps | sampled %d, missed-between-polls %d" %
          (rows[0][1], rows[-1][1], span, frames / span if span else 0, len(rows), missed))
    print("%-13s %-7s %-22s %-22s %-22s %-22s %s" % ("frames", "fps", "guest med/p95/max", "commit med/p95/max",
                                                    "flush med/p95/max", "swap med/p95/max", "work>33.3"))
    for i in range(0, len(rows), a.window):
        w = rows[i:i + a.window]
        if len(w) < 4:
            continue
        dt = w[-1][0] - w[0][0]
        fps = (w[-1][1] - w[0][1]) / dt if dt else 0
        work = [r[2] + r[4] + r[5] + r[6] for r in w]

        def trio(col):
            c = [r[col] for r in w]
            return "%.1f/%.1f/%.1f" % (statistics.median(c), pct(c, .95), max(c))
        over = sum(1 for x in work if x > 33.34)
        print("%5d-%-7d %-7.1f %-22s %-22s %-22s %-22s %d/%d" % (w[0][1], w[-1][1], fps, trio(2), trio(4),
                                                              trio(5), trio(6), over, len(w)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
