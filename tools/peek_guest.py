"""One-shot guest memory dump of a running/parked recomp.  py -3 tools/peek_guest.py --pid P --map M --addr 0x850fff10 --len 0x90"""
import argparse, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--addr", type=lambda x: int(x, 0), required=True); ap.add_argument("--len", type=lambda x: int(x, 0), default=64)
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
d = r.read(off + a.addr, a.len)
for i in range(0, len(d), 16):
    print("%08x: %s" % (a.addr + i, " ".join("%08x" % struct.unpack_from("<I", d, i + j)[0] for j in range(0, min(16, len(d) - i), 4))))
