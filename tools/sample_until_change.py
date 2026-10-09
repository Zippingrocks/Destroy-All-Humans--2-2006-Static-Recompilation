"""Poll guest regions of a running recomp; when WATCH (addr,len) changes from its initial post-start value, save the last
unchanged snapshot and the changed one.  py -3 tools/sample_until_change.py --pid P --map M --region 0x850fd600:0x2a00 --region 0x7ff800:0x400 --watch 0x850fff20 --out dir"""
import argparse, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--region", action="append", required=True); ap.add_argument("--watch", type=lambda x: int(x, 0), required=True)
ap.add_argument("--expect", type=lambda x: int(x, 0), default=0xFD000000, help="trigger when watched dword >= this")
ap.add_argument("--fall", action="store_true", help="trigger when watched dword drops below --expect after having been >= it")
ap.add_argument("--out", type=Path, required=True); ap.add_argument("--seconds", type=float, default=600)
ap.add_argument("--interval", type=float, default=0.0)
a = ap.parse_args()
regs = [(int(x.split(":")[0], 0), int(x.split(":")[1], 0)) for x in a.region]
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
nat = r.base + symbol_rva(a.map, "g_fnt_nat_idx")
a.out.mkdir(parents=True, exist_ok=True)
t0 = time.time(); prev = None; hist = []; seen = False
while time.time() - t0 < a.seconds:
    try:
        snap = [r.read(off + ad, ln) for ad, ln in regs]
        ni = struct.unpack("<I", r.read(nat, 4))[0]
        w = struct.unpack("<I", r.read(off + a.watch, 4))[0]
    except Exception as e:
        print("read failed", e); break
    if a.fall:
        if w >= a.expect: seen = True
        trig = seen and w < a.expect
    else:
        trig = w >= a.expect
    if trig:
        print("triggered at nat", ni, "watch=%08x" % w)
        for k, h in enumerate(hist[-3:]):
            for (ad, ln), d in zip(regs, h[1]): (a.out / ("pre%d_%08x.bin" % (k, ad))).write_bytes(d)
            print("pre%d nat %d" % (k, h[0]))
        for (ad, ln), d in zip(regs, snap): (a.out / ("post_%08x.bin" % ad)).write_bytes(d)
        break
    if prev is None or snap != prev:
        hist.append((ni, snap)); hist = hist[-4:]; prev = snap
    time.sleep(a.interval)
