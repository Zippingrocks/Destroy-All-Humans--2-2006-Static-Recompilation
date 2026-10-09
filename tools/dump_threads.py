"""Dump every thread's call chain of a running DAH2 recomp (brief suspend each).

    py -3 tools/dump_threads.py --pid PID --map dah2_recomp.map [--depth 14] [--repeat 3 --interval 0.5]

Labels frames by the linker map (our image) or module!export (system DLLs); shows
thread kernel/user CPU so spinning threads stand out from blocked ones.
"""
import argparse, bisect, ctypes, struct, sys, time
from ctypes import wintypes
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader
from sample_frame_profile import load_symbols, module_table, export_lookup, Unwinder

class FT(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

def thread_ids(pid):
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    class TE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                    ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", wintypes.LONG),
                    ("tpDeltaPri", wintypes.LONG), ("dwFlags", wintypes.DWORD)]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = k.CreateToolhelp32Snapshot(4, 0)
    te = TE(); te.dwSize = ctypes.sizeof(te); out = []
    ok = k.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid: out.append(te.th32ThreadID)
        ok = k.Thread32Next(snap, ctypes.byref(te))
    k.CloseHandle(snap); return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
    ap.add_argument("--depth", type=int, default=14); ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--min-cpu-ms", type=float, default=0, help="hide threads with less total CPU")
    a = ap.parse_args()
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenThread.restype = ctypes.c_void_p
    k.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    for fn in (k.SuspendThread, k.ResumeThread, k.CloseHandle): fn.argtypes = [ctypes.c_void_p]
    k.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k.GetThreadTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(FT)] * 4
    rvas, names = load_symbols(a.map)
    reader = Reader(a.pid, suspend=False)
    modules = module_table(reader.handle)
    unw = Unwinder(reader.handle)
    raw = ctypes.create_string_buffer(1232 + 16); al = (ctypes.addressof(raw) + 15) & ~15
    buf = (ctypes.c_char * 1232).from_address(al)
    def lab(addr):
        r = addr - reader.base
        if 0 <= r < 0x4000000:
            j = bisect.bisect_right(rvas, r) - 1
            return names[j] if j >= 0 else "?"
        for lo, hi, nm, mp in modules:
            if lo <= addr < hi:
                e = export_lookup(mp, lo, addr) if True else ""
                return f"[{nm}!{e}]" if e else f"[{nm}]"
        return f"?{addr:#x}"
    for rep in range(a.repeat):
        print(f"--- snapshot {rep} ---")
        for tid in thread_ids(a.pid):
            th = k.OpenThread(0x0002 | 0x0008 | 0x0040, False, tid)
            if not th: continue
            c, e, kt, ut = FT(), FT(), FT(), FT()
            k.GetThreadTimes(th, *(ctypes.byref(x) for x in (c, e, kt, ut)))
            f = lambda t: ((t.hi << 32) | t.lo) / 10000.0
            k.SuspendThread(th)
            ctypes.memset(al, 0, 1232); struct.pack_into("<I", buf, 0x30, 0x10000B)
            chain = []
            if k.GetThreadContext(th, al):
                try: chain = unw.walk(th, al, limit=a.depth)
                except Exception: pass
            k.ResumeThread(th); k.CloseHandle(th)
            if f(kt) + f(ut) < a.min_cpu_ms: continue
            parts = []
            for ad in chain:
                t = lab(ad)
                if not parts or parts[-1] != t: parts.append(t)
            print(f"tid {tid:6d} kern={f(kt):9.0f}ms user={f(ut):9.0f}ms  " + " <- ".join(parts[:a.depth]))
        if rep + 1 < a.repeat: time.sleep(a.interval)
main()
