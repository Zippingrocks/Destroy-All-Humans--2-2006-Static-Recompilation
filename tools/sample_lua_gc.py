"""Sample the Lua state's GC accounting (nblocks [L+0x68], GCthreshold [L+0x5c]) of a running recomp.
  py -3 tools/sample_lua_gc.py --pid P --map M [--l 0x85f503b4] [--seconds 120] [--interval 0.1]"""
import argparse, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--l", type=lambda x: int(x, 0), default=0x85f503b4); ap.add_argument("--seconds", type=float, default=120); ap.add_argument("--interval", type=float, default=0.1)
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
cnt = r.base + symbol_rva(a.map, "g_dah2_present_timing_samples")
t0 = time.time(); last = None
while time.time() - t0 < a.seconds:
    try:
        n = struct.unpack("<Q", r.read(cnt, 8))[0]
        d = r.read(off + a.l + 0x5c, 0x10)
        thr, _, _, nb = struct.unpack("<4I", d)
    except Exception as e:
        print("read failed", e); break
    cur = (thr, nb)
    if cur != last:
        print("present %6d thr=%9d nblocks=%9d" % (n, thr, nb), flush=True); last = cur
    time.sleep(a.interval)
