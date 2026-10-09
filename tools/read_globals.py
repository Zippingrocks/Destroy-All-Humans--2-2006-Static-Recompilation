"""Read exported 32-bit globals of a running recomp by map symbol (non-suspending).

    py -3 tools/read_globals.py --pid PID --map dah2_recomp.map g_dah2_title_update_calls ...
    py -3 tools/read_globals.py --pid PID --map X.map --guest 0x31D9BC:4 --guest 0x2EC0B8:2
Guest addresses are guest VAs read through g_xbox_memory-equivalent: base+VA when the
image maps guest memory at a fixed host base (see --guest-base-symbol).
"""
import argparse, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva

ap = argparse.ArgumentParser()
ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("names", nargs="*")
ap.add_argument("--guest", action="append", default=[], help="GUESTVA:LENGTH, printed as hex dwords")
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
for n in a.names:
    rva = symbol_rva(a.map, n)
    print(f"{n} = {struct.unpack('<I', r.read(r.base + rva, 4))[0]}")

if a.guest:
    off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
    for spec in a.guest:
        va, n = (int(x, 0) for x in spec.split(":"))
        data = r.read(off + va, n)
        for i in range(0, n, 16):
            row = data[i:i + 16]
            print("%08x: %s" % (va + i, " ".join("%08x" % struct.unpack_from("<I", row, j)[0] for j in range(0, len(row) - 3, 4))))
