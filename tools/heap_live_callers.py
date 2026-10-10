"""Live medium-pool (0x13F390) blocks of a DAH2_FN_TRACE recomp grouped by allocating caller (the shadow heap record's ra; the 0xF96C0
allocator wrapper is looked through).  Useful for finding what keeps allocating without freeing.
  py -3 tools/heap_live_callers.py --pid P --map M [--top 30]"""
import argparse, collections, pathlib, struct, sys
import numpy as np
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=pathlib.Path, required=True)
ap.add_argument("--top", type=int, default=30); ap.add_argument("--pool", choices=("medium", "small"), default="medium"); a = ap.parse_args()
r = Reader(a.pid, suspend=True)
try:
    howner = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_howner" if a.pool == "medium" else "g_sowner"), 8))[0]
    hrec = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_hrec" if a.pool == "medium" else "g_srec"), 8))[0]
    seqs = set(); chunk = 16 << 20
    for off in range(0, 0x10000000 // 4 * 4, chunk):
        arr = np.frombuffer(r.read(howner + off, chunk), dtype=np.uint32)
        seqs.update(np.unique(arr[arr != 0]).tolist())
    by = collections.defaultdict(lambda: [0, 0, collections.Counter()]); tot = 0
    for s in seqs:
        start, size, ra, tid = struct.unpack("<4I", r.read(hrec + (s & ((1 << 22) - 1)) * 16, 16))
        by[ra][0] += 1; by[ra][1] += size; by[ra][2][size] += 1; tot += size
finally:
    r.close()
print("live blocks %d bytes %d (%.1f MB)" % (len(seqs), tot, tot / 1048576))
for ra, (n, sz, sizes) in sorted(by.items(), key=lambda kv: -kv[1][1])[:a.top]:
    print("  caller %06x blocks %6d bytes %10d (%.2f MB)  common sizes %s" % (ra, n, sz, sz / 1048576, sizes.most_common(3)))
