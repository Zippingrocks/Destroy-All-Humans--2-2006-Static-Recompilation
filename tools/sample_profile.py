"""Poor man's sampling profiler for a running recomp: suspend the busiest thread, read RIP, resume; histogram by map symbol.

  py -3 tools/sample_profile.py --pid P --map M [--seconds 10] [--interval 0.005] [--top 30] [--stack]
With --stack the host return addresses on the thread stack that fall inside the image are also attributed (inclusive profile)."""
import argparse, bisect, collections, ctypes, ctypes.wintypes as wt, re, struct, time
from pathlib import Path
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--seconds", type=float, default=10); ap.add_argument("--interval", type=float, default=0.005); ap.add_argument("--top", type=int, default=30)
ap.add_argument("--stack", action="store_true"); a = ap.parse_args()
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
THREAD_ALL = 0x1FFFFF; PROCESS_ALL = 0x1FFFFF
class FT(ctypes.Structure): _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]
class M128(ctypes.Structure): _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]
class CONTEXT(ctypes.Structure):
    _fields_ = [("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong), ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
                ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong), ("ContextFlags", wt.DWORD), ("MxCsr", wt.DWORD),
                ("SegCs", wt.WORD), ("SegDs", wt.WORD), ("SegEs", wt.WORD), ("SegFs", wt.WORD), ("SegGs", wt.WORD), ("SegSs", wt.WORD), ("EFlags", wt.DWORD),
                ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong), ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong), ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
                ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong), ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong), ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
                ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong), ("R8", ctypes.c_ulonglong), ("R9", ctypes.c_ulonglong), ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
                ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong), ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong), ("Rip", ctypes.c_ulonglong),
                ("pad", ctypes.c_ubyte * 512), ("VectorRegister", M128 * 26), ("VectorControl", ctypes.c_ulonglong), ("DebugControl", ctypes.c_ulonglong),
                ("LastBranchToRip", ctypes.c_ulonglong), ("LastBranchFromRip", ctypes.c_ulonglong), ("LastExceptionToRip", ctypes.c_ulonglong), ("LastExceptionFromRip", ctypes.c_ulonglong)]
CONTEXT_CONTROL = 0x100001; CONTEXT_INTEGER = 0x100002
class TE32(ctypes.Structure): _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD), ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", wt.LONG), ("tpDeltaPri", wt.LONG), ("dwFlags", wt.DWORD)]
def threads(pid):
    snap = k32.CreateToolhelp32Snapshot(4, 0); te = TE32(); te.dwSize = ctypes.sizeof(te); out = []
    if k32.Thread32First(snap, ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID == pid: out.append(te.th32ThreadID)
            if not k32.Thread32Next(snap, ctypes.byref(te)): break
    k32.CloseHandle(snap); return out
def cpu(h):
    c, e, kt, ut = FT(), FT(), FT(), FT(); k32.GetThreadTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut))
    return ((kt.hi << 32) | kt.lo) + ((ut.hi << 32) | ut.lo)
# symbols from the MSVC map
syms = []
started = False
for l in a.map.read_text(errors="replace").splitlines():
    if "Rva+Base" in l: started = True; continue
    if not started: continue
    p = l.split()
    if len(p) >= 4 and re.fullmatch(r"[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}", p[0]) and p[0].startswith("0001:"):
        try: syms.append((int(p[2], 16) - 0x140000000, p[1]))
        except ValueError: pass
syms.sort(); addrs = [s[0] for s in syms]
def sym(rva):
    i = bisect.bisect_right(addrs, rva) - 1
    return syms[i][1] if i >= 0 else "?"
tids = threads(a.pid)
hs = {t: k32.OpenThread(THREAD_ALL, False, t) for t in tids}
t0 = {t: cpu(h) for t, h in hs.items()}; time.sleep(1.0)
busiest = max(hs, key=lambda t: cpu(hs[t]) - t0[t]); h = hs[busiest]
proc = k32.OpenProcess(PROCESS_ALL, False, a.pid)
mods = (ctypes.c_void_p * 1024)(); need = wt.DWORD()
ctypes.WinDLL("psapi").EnumProcessModules(proc, mods, ctypes.sizeof(mods), ctypes.byref(need)); base = mods[0]
print("busiest tid", busiest, "image base %x" % base)
excl = collections.Counter(); incl = collections.Counter(); offs = collections.Counter(); n = 0
end = time.time() + a.seconds
ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER
while time.time() < end:
    k32.SuspendThread(h)
    if k32.GetThreadContext(h, ctypes.byref(ctx)):
        rva = ctx.Rip - base; excl[sym(rva)] += 1; n += 1; offs[rva] += 1
        if a.stack:
            seen = set([sym(rva)]); buf = (ctypes.c_ulonglong * 512)(); got = ctypes.c_size_t()
            if k32.ReadProcessMemory(proc, ctypes.c_void_p(ctx.Rsp), buf, ctypes.sizeof(buf), ctypes.byref(got)):
                for v in buf[: got.value // 8]:
                    if base <= v < base + 0x10000000:
                        s = sym(v - base)
                        if s not in seen: seen.add(s); incl[s] += 1
    k32.ResumeThread(h); time.sleep(a.interval)
print("%d samples" % n)
print("-- exclusive (RIP) --")
for s, c in excl.most_common(a.top): print("  %5.1f%%  %s" % (100.0 * c / n, s))
if a.stack:
    print("-- inclusive (stack scan, approximate) --")
    for s, c in incl.most_common(a.top): print("  %5.1f%%  %s" % (100.0 * c / n, s))

print("-- top RIP RVAs (with symbol+offset) --")
for rva, c in offs.most_common(20):
    i = bisect.bisect_right(addrs, rva) - 1
    print("  %5.1f%%  rva %x  %s+0x%x" % (100.0 * c / n, rva, syms[i][1], rva - syms[i][0]))
