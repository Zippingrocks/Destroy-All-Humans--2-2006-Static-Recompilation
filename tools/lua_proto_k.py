"""Print the constant table of a Lua Proto in a running recomp: py -3 tools/lua_proto_k.py --pid P --map M --k 0x85fb2a60 --n 21"""
import argparse, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--k", type=lambda x: int(x, 0), required=True); ap.add_argument("--n", type=int, required=True); a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
def rd(va, n): return r.read(off + va, n)
for i in range(a.n):
    t, v = struct.unpack("<II", rd(a.k + 8 * i, 8))
    if t == 3: s = rd(v + 0x14, 48).split(b"\0")[0].decode("latin1"); print(i, "str", repr(s))
    elif t == 2: print(i, "num", struct.unpack("<f", struct.pack("<I", v))[0])
    else: print(i, t, hex(v))
