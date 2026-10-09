"""Scan a running recomp's guest memory for dword patterns / pointers.
  py -3 tools/scan_guest.py --pid PID --map X.map --lo 0x80000000 --hi 0x86000000 --words 0b,0e,47,87,cc  [--ptr 0x85f6f33c]"""
import argparse, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser()
ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--lo", type=lambda x: int(x, 0), default=0x80000000); ap.add_argument("--hi", type=lambda x: int(x, 0), default=0x86000000)
ap.add_argument("--words", default=""); ap.add_argument("--ptr", type=lambda x: int(x, 0), action="append", default=[])
ap.add_argument("--dump", action="append", default=[], help="VA:LEN dwords after scan")
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
pat = b"".join(struct.pack("<I", int(w, 16)) for w in a.words.split(",")) if a.words else None
ptrs = [struct.pack("<I", p) for p in a.ptr]
CH = 1 << 22
va = a.lo
while va < a.hi:
    try: data = r.read(off + va, CH + 64)
    except Exception: va += CH; continue
    if pat:
        i = data.find(pat)
        while i >= 0 and i < CH:
            print("pattern at %08x" % (va + i)); i = data.find(pat, i + 1)
    for p in ptrs:
        i = data.find(p)
        while i >= 0 and i < CH:
            if i % 4 == 0: print("ptr %s at %08x" % (p[::-1].hex(), va + i))
            i = data.find(p, i + 1)
    va += CH
