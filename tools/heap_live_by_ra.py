"""Histogram the live medium-pool blocks of a DAH2_FN_TRACE recomp by allocation return address (shadow heap from src/dah2_fn_trace.c).
  py -3 tools/heap_live_by_ra.py --pid P --map M [--top 25]"""
import argparse, collections, pathlib, struct, sys
import numpy as np
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=pathlib.Path, required=True)
ap.add_argument("--top", type=int, default=25); a = ap.parse_args()
r = Reader(a.pid, suspend=True)
try:
    howner = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_howner"), 8))[0]
    hrec = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_hrec"), 8))[0]
    if not howner or not hrec: sys.exit("shadow heap not armed")
    total = 0x10000000 // 4 * 4; chunk = 16 << 20; seqs = set()
    for off in range(0, total, chunk):
        arr = np.frombuffer(r.read_abs(howner + off, chunk) if hasattr(r, "read_abs") else r.read(howner + off, chunk), dtype=np.uint32)
        seqs.update(np.unique(arr[arr != 0]).tolist())
    byra = collections.defaultdict(lambda: [0, 0]); live = 0; bysize = collections.defaultdict(lambda: [0, []])
    xoff = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
    for s in seqs:
        rec = r.read(hrec + (s & ((1 << 22) - 1)) * 16, 16); start, size, ra, tid = struct.unpack("<4I", rec)
        byra[ra][0] += 1; byra[ra][1] += size; live += size
        bysize[size][0] += 1
        if len(bysize[size][1]) < 3: bysize[size][1].append(start)
    print("top block sizes (count x size), with the first words of up to 3 samples:")
    for size, (n, samples) in sorted(bysize.items(), key=lambda kv: -kv[1][0] * kv[0])[:12]:
        print("  %6d x %6d (%.1f MB)" % (n, size, n * size / 1048576))
        for st in samples:
            w = struct.unpack("<8I", r.read(xoff + st + 12, 32))
            print("       %08x: %s" % (st, " ".join("%08x" % x for x in w)))
finally:
    r.close()
print("live blocks %d, live bytes %d (%.1f MB)" % (len(seqs), live, live / 1048576))
for ra, (n, sz) in sorted(byra.items(), key=lambda kv: -kv[1][1])[:a.top]:
    print("  ra %06x  blocks %6d  bytes %9d (%.1f MB)" % (ra, n, sz, sz / 1048576))

# per-caller alloc/free counts of the game's allocator wrappers (needs a build with the 0xF96C0 / 0xF96E0 hooks)
r2 = Reader(a.pid, suspend=True)
try:
    raw = r2.read(r2.base + symbol_rva(a.map, "g_fnt_acaller"), 4096 * 16)
finally:
    r2.close()
rows = [struct.unpack_from("<4I", raw, i * 16) for i in range(4096)]
rows = [x for x in rows if x[0]]
print("\ncallers of the allocator wrapper (alloc/free), by outstanding count:")
for ra, al, by, fr in sorted(rows, key=lambda x: -(x[1] - x[3]))[:a.top]:
    print("  caller ra %06x  allocs %8d  bytes %11d  frees %8d  outstanding %8d" % (ra, al, by, fr, al - fr))

r3 = Reader(a.pid, suspend=True)
try:
    n = struct.unpack("<I", r3.read(r3.base + symbol_rva(a.map, "g_fnt_bigalloc_n"), 4))[0]
    raw = r3.read(r3.base + symbol_rva(a.map, "g_fnt_bigalloc"), 48 * 48)
finally:
    r3.close()
print("\nlarge (>=150000 byte) allocations, guest code addresses above the allocator (nearest first):")
for i in range(min(n, 48)):
    w = struct.unpack_from("<12I", raw, i * 48)
    print("  size %7d ptr %08x  %s" % (w[0], w[1], " ".join("%06x" % x for x in w[2:] if x)))
