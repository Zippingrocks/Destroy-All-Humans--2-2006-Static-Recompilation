"""Print shadow-heap counters of a DAH2_FN_TRACE recomp: py -3 tools/heap_counters.py --pid P --map M"""
import argparse, pathlib, struct, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=pathlib.Path, required=True); a = ap.parse_args()
r = Reader(a.pid, suspend=True)
try:
    for n in ("g_fnt_heap_allocs", "g_fnt_heap_frees", "g_fnt_big_allocs", "g_fnt_big_frees", "g_fnt_alloc_null", "g_fnt_sheap_allocs", "g_fnt_sheap_frees"):
        print("%-22s %d" % (n, struct.unpack("<I", r.read(r.base + symbol_rva(a.map, n), 4))[0]))
finally:
    r.close()
