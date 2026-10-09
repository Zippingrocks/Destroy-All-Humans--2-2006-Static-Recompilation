"""Dump a Lua (4.0-style, 20-byte-node) table of a running recomp. --state L dumps L->gt ([L+0x44]); --table T dumps table T.
  py -3 tools/lua_dump_table.py --pid P --map M --state 0x85f503b4 [--path driver] [--max 400]"""
import argparse, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--state", type=lambda x: int(x, 0)); ap.add_argument("--table", type=lambda x: int(x, 0)); ap.add_argument("--path", default="")
ap.add_argument("--max", type=int, default=300); a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
def rd(va, n): return r.read(off + va, n)
def u32(va): return struct.unpack("<I", rd(va, 4))[0]
def tstr(p): return rd(p + 0x14, 64).split(bytes(1))[0].decode("latin1")
TN = {1: "nil", 2: "number", 3: "string", 4: "table", 5: "function", 6: "cfunc?", 0: "userdata"}
def entries(t):
    nodes, size = u32(t), u32(t + 8)
    out = []
    for i in range(min(size, 100000)):
        n = nodes + i * 20; kt, kv, vt, vv = struct.unpack("<4I", rd(n, 16))
        if vt == 1 and kt == 1: continue
        out.append((kt, kv, vt, vv))
    return size, out
def show(t, depth=0):
    size, es = entries(t); print("table %08x size %d, %d used" % (t, size, len(es)))
    for kt, kv, vt, vv in es[:a.max]:
        k = tstr(kv) if kt == 3 else "<%d:%x>" % (kt, kv)
        print("  %-28s %s %08x" % (k, TN.get(vt, vt), vv))
gt = a.table if a.table else u32(a.state + 0x44)
if a.path:
    for comp in a.path.split("."):
        size, es = entries(gt); hit = [e for e in es if e[0] == 3 and tstr(e[1]) == comp]
        if not hit: print("path component %r not found (have %d entries)" % (comp, len(es))); sys.exit(1)
        kt, kv, vt, vv = hit[0]; print("%s -> %s %08x" % (comp, TN.get(vt, vt), vv))
        if vt != 4: sys.exit(0)
        gt = vv
show(gt)
