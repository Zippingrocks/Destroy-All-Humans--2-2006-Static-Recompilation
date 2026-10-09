"""Attribute frame time to kernel services in a running DAH2 process, read-only.

    py -3 tools/sample_kernel_costs.py --pid PID --map dah2_recomp.map \
        --window 20 --windows 5

kernel_thunk_dispatch counts every kernel call and the QPC ticks spent inside
its bridge in exported globals (g_xbox_kernel_stat_*), so no logging has to be
enabled -- stderr is discarded in normal runs and tracing itself changes frame
timing. This snapshots them every --window seconds and prints, per window, the
services that cost the most real time, as ms of the process's wall second.

Time is inclusive: a bridge that waits, or that runs a guest routine on the
caller's behalf (a DPC, KeSynchronizeExecution), is charged for all of it. A
wait that blocks while the 30 Hz limiter would have idled anyway is not a cost
to frame time; compare against the frame budget before concluding anything.
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva  # noqa: E402

SLOTS = 378
PARSER = Path(__file__).resolve().parent.parent / "xboxrecomp" / "tools" / "xbe_parser" / "xbe_parser.py"


def export_names() -> dict[int, str]:
    try:
        src = PARSER.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"KERNEL_EXPORTS\s*[:=][^{]*\{(.*?)\n\}", src, re.S)
        return {int(o): n for o, n in re.findall(r"(\d+)\s*:\s*[\"']([A-Za-z_][A-Za-z0-9_]*)", m.group(1))}
    except Exception:
        return {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--map", type=Path, required=True)
    ap.add_argument("--window", type=float, default=20.0)
    ap.add_argument("--windows", type=int, default=4)
    ap.add_argument("--top", type=int, default=8)
    a = ap.parse_args()

    rva = {n: symbol_rva(a.map, "g_xbox_kernel_stat_" + n) for n in ("calls", "ticks", "ordinal")}
    frva = {n: symbol_rva(a.map, "g_xbox_kernel_frame_" + n) for n in ("calls", "ticks")}
    stall_rva = symbol_rva(a.map, "g_xbox_kernel_stall_sites")
    freq_rva = symbol_rva(a.map, "g_dah2_present_timing_frequency")
    frames_rva = symbol_rva(a.map, "g_dah2_present_timing_samples")
    names = export_names()
    reader = Reader(a.pid, suspend=False)

    def snap():
        calls = struct.unpack("<%dq" % SLOTS, reader.read(reader.base + rva["calls"], 8 * SLOTS))
        ticks = struct.unpack("<%dq" % SLOTS, reader.read(reader.base + rva["ticks"], 8 * SLOTS))
        ords = struct.unpack("<%di" % SLOTS, reader.read(reader.base + rva["ordinal"], 4 * SLOTS))
        freq = struct.unpack("<Q", reader.read(reader.base + freq_rva, 8))[0]
        frames = struct.unpack("<Q", reader.read(reader.base + frames_rva, 8))[0]
        fcalls = struct.unpack("<%dq" % SLOTS, reader.read(reader.base + frva["calls"], 8 * SLOTS))
        fticks = struct.unpack("<%dq" % SLOTS, reader.read(reader.base + frva["ticks"], 8 * SLOTS))
        # each site: LONG ret, LONG usec, LONG64 calls  (16 bytes, 8-aligned)
        raw = reader.read(reader.base + stall_rva, 8 * 16)
        stalls = [struct.unpack_from("<iiq", raw, i * 16) for i in range(8)]
        return calls, ticks, ords, freq, frames, time.perf_counter(), fcalls, fticks, stalls

    prev = snap()
    try:
        for w in range(a.windows):
            time.sleep(a.window)
            cur = snap()
            freq = cur[3] or prev[3] or 1
            dt = cur[5] - prev[5]
            dframes = cur[4] - prev[4]
            rows = []
            for s in range(SLOTS):
                dc = cur[0][s] - prev[0][s]
                dtk = cur[1][s] - prev[1][s]
                if dc > 0:
                    o = cur[2][s]
                    rows.append((dtk / freq * 1000.0 / dt, dc / dt, (dtk / freq * 1e6 / dc), o, dc))
            rows.sort(reverse=True)
            print("window %d: %.1fs, %d frames (%.1f fps), %d kernel calls/s total" %
                  (w + 1, dt, dframes, dframes / dt, sum(r[4] for r in rows) / dt))
            print("   %-9s %-34s %10s %12s %10s" % ("ordinal", "service", "ms per s", "calls per s", "us/call"))
            for ms_s, cps, us, o, _ in rows[:a.top]:
                print("   %-9d %-34s %10.2f %12.1f %10.1f" % (o, names.get(o, "?"), ms_s, cps, us))
            frows = []
            for s in range(SLOTS):
                dc = cur[6][s] - prev[6][s]
                dtk = cur[7][s] - prev[7][s]
                if dc > 0 and dframes > 0:
                    frows.append((dtk / freq * 1000.0 / dframes, dc / dframes, dtk / freq * 1e6 / dc, cur[2][s]))
            frows.sort(reverse=True)
            print("   -- on the FRAME thread (counts against the 33.3 ms budget) --")
            print("   %-9s %-34s %12s %12s %10s" % ("ordinal", "service", "ms per frame", "calls/frame", "us/call"))
            for ms_f, cpf, us, o in frows[:a.top]:
                print("   %-9d %-34s %12.3f %12.2f %10.1f" % (o, names.get(o, "?"), ms_f, cpf, us))
            tot = sum(r[0] for r in frows)
            print("   frame-thread kernel total: %.3f ms/frame" % tot)
            for i, (ret, usec, calls) in enumerate(cur[8]):
                if ret:
                    pc = prev[8][i][2] if prev[8][i][0] == ret else 0
                    print("   stall site ret=0x%08X %6d us  %8.1f calls/s" % (ret & 0xFFFFFFFF, usec, (calls - pc) / dt))
            prev = cur
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
