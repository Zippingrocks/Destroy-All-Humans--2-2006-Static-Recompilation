"""Log changes of a guest memory range of a running recomp, stamped with present count + native-call index.
  py -3 tools/sample_guest_mem.py --pid P --map M --addr 0x85f50358 --len 64 [--seconds 100] [--interval 0.005]"""
import argparse, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--addr", type=lambda x: int(x, 0), required=True); ap.add_argument("--len", type=int, default=64)
ap.add_argument("--seconds", type=float, default=100); ap.add_argument("--interval", type=float, default=0.005)
ap.add_argument("--start-present", type=int, default=0)
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
cnt = r.base + symbol_rva(a.map, "g_dah2_present_timing_samples"); nat = r.base + symbol_rva(a.map, "g_fnt_nat_idx")
t0 = time.time(); last = None
while time.time() - t0 < a.seconds:
    try:
        n = struct.unpack("<Q", r.read(cnt, 8))[0]
        if n < a.start_present: time.sleep(0.05); continue
        ni = struct.unpack("<I", r.read(nat, 4))[0]
        d = r.read(off + a.addr, a.len)
    except Exception as e:
        print("read failed", e); break
    if d != last:
        print("present %6d nat %6d: %s" % (n, ni, " ".join("%08x" % struct.unpack_from("<I", d, i)[0] for i in range(0, len(d) - 3, 4))), flush=True); last = d
    time.sleep(a.interval)
