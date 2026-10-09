"""Poll a running recomp's broadphase context S (default 0x850fff10) until its 3 sorted lists stop being consistent (every record id
0..count-1 must have exactly two entries per list, entries sorted by key), then save the last valid and the first invalid snapshot.
  py -3 tools/sample_until_invalid.py --pid P --map M --out dir [--s 0x850fff10]"""
import argparse, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--s", type=lambda x: int(x, 0), default=0x850fff10); ap.add_argument("--out", type=Path, required=True)
ap.add_argument("--seconds", type=float, default=400); ap.add_argument("--stack", default="0x7ff000:0x1000")
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
nat = r.base + symbol_rva(a.map, "g_fnt_nat_idx")
sa, sl = [int(x, 0) for x in a.stack.split(":")]
a.out.mkdir(parents=True, exist_ok=True)
def rd(ad, n): return r.read(off + ad, n)
def u32(b, o=0): return struct.unpack_from("<I", b, o)[0]
def check(S):
    h = rd(S, 0x90)
    if u32(h) != 0x2ba970: return None
    rec = u32(h, 0x40); cnt = u32(h, 0x44)
    if not (0x80000000 <= rec < 0x88000000) or cnt > 0x100 or cnt == 0: return None
    for nm, o in (("L0", 0x4c), ("L1", 0x58), ("L2", 0x64)):
        p, n = u32(h, o), u32(h, o + 4)
        if n != 2 * cnt: return "%s count %d != 2*%d" % (nm, n, cnt)
        d = rd(p, 4 * n); seen = {}
        prevk = -1
        for i in range(n):
            e = u32(d, 4 * i); k, idv = e & 0xffff, e >> 16
            if k < prevk: return "%s unsorted at %d" % (nm, i)
            prevk = k; seen[idv] = seen.get(idv, 0) + 1
        for idv in range(cnt):
            if seen.get(idv, 0) != 2: return "%s id %x has %d entries" % (nm, idv, seen.get(idv, 0))
    return "ok"
def snap(S):
    h = rd(S, 0x90); rec = u32(h, 0x40); cnt = u32(h, 0x44)
    out = {"S": h, "rec": rd(rec, 16 * (cnt + 2)), "stack": rd(sa, sl)}
    for nm, o in (("L0", 0x4c), ("L1", 0x58), ("L2", 0x64)): out[nm] = rd(u32(h, o), 4 * (u32(h, o + 4) + 2))
    return out
t0 = time.time(); last = None; lastnat = 0; nok = 0
while time.time() - t0 < a.seconds:
    try:
        ni = struct.unpack("<I", r.read(nat, 4))[0]
        res = check(a.s)
    except Exception as e:
        print('check exception', repr(e)); time.sleep(0.5); continue
    if res is None:
        nn = globals().get('nn', 0) + 1; globals()['nn'] = nn
        if nn % 5000 == 1: print('check None', nn, 'nat', ni, flush=True)
        continue
    if res == "ok":
        nok += 1
        if nok % 2000 == 1: print("ok samples", nok, "nat", ni, flush=True)
        try: last = (ni, snap(a.s))
        except Exception: pass
        continue
    try:
        first_bad = snap(a.s)
    except Exception: continue
    bad = True
    for _ in range(3):
        time.sleep(0.004)
        try:
            res2 = check(a.s)
        except Exception: res2 = None
        if res2 == "ok": bad = False; break
    if not bad: continue
    print("INVALID at nat %d: %s / %s (last valid nat %s)" % (ni, res, res2, last and last[0]))
    if last:
        for k, v in last[1].items(): (a.out / ("valid_%s.bin" % k)).write_bytes(v)
    for k, v in first_bad.items(): (a.out / ("invalid_%s.bin" % k)).write_bytes(v)
    break
