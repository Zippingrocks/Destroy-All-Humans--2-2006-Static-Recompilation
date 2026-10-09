"""Dump guest memory of a running recomp when the present counter reaches given values.

  py -3 tools/dump_recomp_mem.py --pid P --map X.map --at 1120,1126,1140 --range 0x2A0000:0xA0000 --prefix OUT
Writes OUT_<present>.bin. Reads are non-suspending; the first read after the target
present may be a frame or two late (polling at ~1 ms)."""
import argparse, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser()
ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--at", required=True); ap.add_argument("--range", default="0x2A0000:0xA0000")
ap.add_argument("--prefix", required=True); ap.add_argument("--timeout", type=float, default=300)
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
cnt = r.base + symbol_rva(a.map, "g_dah2_present_timing_samples")
va, n = (int(x, 0) for x in a.range.split(":"))
targets = sorted(int(x) for x in a.at.split(","))
end = time.time() + a.timeout
for t in targets:
    while time.time() < end:
        cur = struct.unpack("<Q", r.read(cnt, 8))[0]
        if cur >= t: break
        time.sleep(0.002)
    data = b"".join(r.read(off + va + o, min(0x1000, n - o)) for o in range(0, n, 0x1000))
    Path(f"{a.prefix}_{cur}.bin").write_bytes(data); print("dumped at present", cur)
