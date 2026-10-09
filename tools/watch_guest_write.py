"""Poll a guest dword of a running DAH2_FN_TRACE recomp; when it leaves --expect, suspend the process and dump the
function-entry ring tail + native index (a poor man's write watchpoint).
  py -3 tools/watch_guest_write.py --pid P --map M --addr 0x85f50364 --expect 2 [--tail 60]"""
import argparse, ctypes, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--addr", type=lambda x: int(x, 0), required=True); ap.add_argument("--expect", type=lambda x: int(x, 0), required=True)
ap.add_argument("--tail", type=int, default=60); ap.add_argument("--seconds", type=float, default=200)
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
k = r.kernel; ntdll = ctypes.WinDLL("ntdll")
h = k.OpenProcess(0x0C10, False, a.pid)
off = struct.unpack("<Q", r.read(r.base + symbol_rva(a.map, "g_xbox_mem_offset"), 8))[0]
nat = r.base + symbol_rva(a.map, "g_fnt_nat_idx"); fidx = r.base + symbol_rva(a.map, "g_fnt_flog_idx"); flog = r.base + symbol_rva(a.map, "g_fnt_flog")
ea = off + a.addr; seen = False; t0 = time.time()
while time.time() - t0 < a.seconds:
    v = struct.unpack("<I", r.read(ea, 4))[0]
    if v == a.expect: seen = True
    elif seen:
        ntdll.NtSuspendProcess(ctypes.c_void_p(h))
        ni = struct.unpack("<I", r.read(nat, 4))[0]; fi = struct.unpack("<I", r.read(fidx, 4))[0]
        ring = struct.unpack("<16384I", r.read(flog, 16384 * 4))
        order = list(ring[:fi]) if fi <= 16384 else list(ring[fi % 16384:]) + list(ring[:fi % 16384])
        print("changed to %08x at native idx %d; function entries total %d" % (v, ni, fi))
        print("last functions:", " ".join("%06X" % x for x in order[-a.tail:]))
        print("block now:", " ".join("%08x" % x for x in struct.unpack("<16I", r.read(off + a.addr - 0xc, 64))))
        sys.stdout.flush(); break
print("done (process left suspended)")
