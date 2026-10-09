"""Profile a DAH2_FN_TRACE run: call-count deltas of every guest function over a window.
  py -3 tools/hot_functions.py --pid P --map M [--seconds 10] [--top 25]"""
import argparse, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--seconds", type=float, default=10); ap.add_argument("--top", type=int, default=25); a = ap.parse_args()
r = Reader(a.pid, suspend=False)
base = r.base + symbol_rva(a.map, "g_fnt_count"); SPACE = 0x400000
def snap():
    raw = b"".join(r.read(base + o, 0x10000) for o in range(0, SPACE * 4, 0x10000))
    return struct.unpack("<%dI" % SPACE, raw)
s1 = snap(); t0 = time.time(); time.sleep(a.seconds); s2 = snap(); dt = time.time() - t0
d = sorted(((s2[i] - s1[i]) & 0xFFFFFFFF, i) for i in range(SPACE) if s2[i] != s1[i])
tot = sum(x for x, _ in d)
print("%.1f s, %d functions active, %d calls total" % (dt, len(d), tot))
for n, i in reversed(d[-a.top:]): print("  sub_%08X  %10d calls (%.1f%%)" % (i, n, 100.0 * n / tot))
