"""Poor-man's sampling profiler for DAH2's frame thread.

    py -3 tools/sample_frame_profile.py --pid PID --map dah2_recomp.map \
        --seconds 20 --hz 250

Repeatedly suspends the thread that presents frames (g_dah2_present_thread_id),
reads its RIP, resumes it, and buckets the sample by the present phase
(g_dah2_present_phase: 0 = game running, 1 = 30 Hz limiter, 2 = GPU command
translation, 3 = flush, 4 = swap) and by the function containing RIP, resolved
through the linker map. Samples whose RIP is outside the executable are
attributed to the module that contains them (the D3D11 runtime, the GPU
driver, ntdll, ...).

This perturbs the thread (each sample is a suspend/resume), so use it for the
SHAPE of the cost -- which functions dominate which phase -- not for absolute
frame times; use sample_present_timing.py for those. The limiter phase is
excluded from the percentages because it is idle time by design.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import ctypes
import re
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva  # noqa: E402

IMAGE_BASE = 0x140000000
PHASES = {0: "guest", 1: "limiter", 2: "commit", 3: "flush", 4: "swap"}


def load_symbols(map_path: Path):
    """Sorted (rva, name) for every public symbol in the .text section (0001:)."""
    rows = []
    started = False
    for line in map_path.read_text(errors="replace").splitlines():
        if "Rva+Base" in line:
            started = True
            continue
        if not started:
            continue
        parts = line.split()
        if len(parts) < 3 or not parts[0].startswith("0001:"):
            continue
        try:
            rows.append((int(parts[2], 16) - IMAGE_BASE, parts[1]))
        except ValueError:
            pass
    rows.sort()
    return [r[0] for r in rows], [r[1] for r in rows]


def module_table(pid_handle):
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    mods = (ctypes.c_void_p * 1024)()
    needed = ctypes.c_uint32()
    psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                           ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32]
    psapi.EnumProcessModulesEx(pid_handle, mods, ctypes.sizeof(mods), ctypes.byref(needed), 3)
    class MI(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("size", ctypes.c_uint32), ("entry", ctypes.c_void_p)]
    psapi.GetModuleInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MI), ctypes.c_uint32]
    psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    out = []
    for i in range(needed.value // ctypes.sizeof(ctypes.c_void_p)):
        mi = MI()
        if not psapi.GetModuleInformation(pid_handle, mods[i], ctypes.byref(mi), ctypes.sizeof(mi)):
            continue
        name = ctypes.create_unicode_buffer(260)
        psapi.GetModuleFileNameExW(pid_handle, mods[i], name, 260)
        out.append((mi.base, mi.base + mi.size, Path(name.value).name, name.value))
    return out


_EXPORTS = {}


def export_lookup(path: str, base: int, addr: int) -> str:
    """Nearest exported name at or below addr in the DLL at `path` (loaded at base)."""
    ent = _EXPORTS.get(path)
    if ent is None:
        ent = ([], [])
        try:
            d = Path(path).read_bytes()
            pe = struct.unpack_from("<I", d, 0x3C)[0]
            opt = pe + 24
            magic = struct.unpack_from("<H", d, opt)[0]
            dd = opt + (112 if magic == 0x20B else 96)          # data directories
            exp_rva, exp_size = struct.unpack_from("<II", d, dd)
            nsec = struct.unpack_from("<H", d, pe + 6)[0]
            sec0 = opt + struct.unpack_from("<H", d, pe + 20)[0]
            secs = [struct.unpack_from("<IIII", d, sec0 + i * 40 + 8) for i in range(nsec)]  # vsize, va, rawsize, rawptr

            def off(rva):
                for vsz, va, rsz, rp in secs:
                    if va <= rva < va + max(vsz, rsz):
                        return rp + rva - va
                return None
            e = off(exp_rva)
            nfun, nnames, afun, anam, aord = struct.unpack_from("<IIIII", d, e + 20)
            funs = struct.unpack_from("<%dI" % nfun, d, off(afun))
            names_ = struct.unpack_from("<%dI" % nnames, d, off(anam))
            ords = struct.unpack_from("<%dH" % nnames, d, off(aord))
            rows = []
            for i in range(nnames):
                nm = d[off(names_[i]):].split(b"\x00", 1)[0].decode("latin1")
                rva = funs[ords[i]]
                if not (exp_rva <= rva < exp_rva + exp_size):     # skip forwarders
                    rows.append((rva, nm))
            rows.sort()
            ent = ([r[0] for r in rows], [r[1] for r in rows])
        except Exception:
            pass
        _EXPORTS[path] = ent
    rvas_, names_ = ent
    if not rvas_:
        return ""
    r = addr - base
    i = bisect.bisect_right(rvas_, r) - 1
    return "%s+0x%X" % (names_[i], r - rvas_[i]) if i >= 0 and r - rvas_[i] < 0x2000 else ""


class ADDRESS64(ctypes.Structure):
    _fields_ = [("Offset", ctypes.c_uint64), ("Segment", ctypes.c_uint16), ("Mode", ctypes.c_int)]


class KDHELP64(ctypes.Structure):
    _fields_ = [("Thread", ctypes.c_uint64), ("ThCallbackStack", ctypes.c_uint32),
                ("ThCallbackBStore", ctypes.c_uint32), ("NextCallback", ctypes.c_uint32),
                ("FramePointer", ctypes.c_uint32), ("KiCallUserMode", ctypes.c_uint64),
                ("KeUserCallbackDispatcher", ctypes.c_uint64), ("SystemRangeStart", ctypes.c_uint64),
                ("KiUserExceptionDispatcher", ctypes.c_uint64), ("StackBase", ctypes.c_uint64),
                ("StackLimit", ctypes.c_uint64), ("BuildVersion", ctypes.c_uint32),
                ("RetpolineStubFunctionTableSize", ctypes.c_uint32),
                ("RetpolineStubFunctionTable", ctypes.c_uint64),
                ("RetpolineStubOffset", ctypes.c_uint32), ("RetpolineStubSize", ctypes.c_uint32),
                ("Reserved0", ctypes.c_uint64 * 2)]


class STACKFRAME64(ctypes.Structure):
    _fields_ = [("AddrPC", ADDRESS64), ("AddrReturn", ADDRESS64), ("AddrFrame", ADDRESS64),
                ("AddrStack", ADDRESS64), ("AddrBStore", ADDRESS64), ("FuncTableEntry", ctypes.c_void_p),
                ("Params", ctypes.c_uint64 * 4), ("Far", ctypes.c_int), ("Virtual", ctypes.c_int),
                ("Reserved", ctypes.c_uint64 * 3), ("KdHelp", KDHELP64),
                ("_slack", ctypes.c_uint8 * 256)]   # headroom: never let dbghelp write past us


class Unwinder:
    """Real stack walks of another thread through dbghelp's StackWalk64.

    Uses each module's .pdata unwind tables, so it needs no PDB and does not
    suffer the stale-value problem of scanning the raw stack."""

    def __init__(self, process_handle):
        self.h = process_handle
        self.d = ctypes.WinDLL("dbghelp", use_last_error=True)
        d = self.d
        d.SymInitialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
        d.SymSetOptions.argtypes = [ctypes.c_uint32]
        d.SymSetOptions(0x4)  # SYMOPT_DEFERRED_LOADS only: no symbol download/load
        if not d.SymInitialize(self.h, None, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        d.StackWalk64.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_void_p]
        d.StackWalk64.restype = ctypes.c_int
        self.ftab = ctypes.cast(d.SymFunctionTableAccess64, ctypes.c_void_p)
        self.mbase = ctypes.cast(d.SymGetModuleBase64, ctypes.c_void_p)

    def walk(self, thread_handle, ctx_ptr, limit=24):
        """Return return-address list, innermost first. ctx_ptr: 16-aligned CONTEXT (CONTEXT_FULL)."""
        buf = ctypes.create_string_buffer(ctypes.sizeof(STACKFRAME64) + 16)
        sf = STACKFRAME64.from_buffer(buf)
        rip = ctypes.c_uint64.from_address(ctx_ptr + 0xF8).value
        rsp = ctypes.c_uint64.from_address(ctx_ptr + 0x98).value
        rbp = ctypes.c_uint64.from_address(ctx_ptr + 0xA0).value
        for a_, v in ((sf.AddrPC, rip), (sf.AddrFrame, rbp), (sf.AddrStack, rsp)):
            a_.Offset, a_.Mode = v, 3
        out = []
        for _ in range(limit):
            if not self.d.StackWalk64(0x8664, self.h, thread_handle, ctypes.byref(sf), ctx_ptr,
                                      None, self.ftab, self.mbase, None):
                break
            pc = sf.AddrPC.Offset
            if not pc:
                break
            out.append(pc)
        return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--map", type=Path, required=True)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--hz", type=float, default=250)
    ap.add_argument("--top", type=int, default=14)
    ap.add_argument("--unwind", type=int, default=0, metavar="N",
                    help="resolve each sample's real call chain (first N frames) with StackWalk64")
    ap.add_argument("--callers", action="store_true",
                    help="for samples inside system DLLs, add the nearest caller in our image")
    a = ap.parse_args()

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenThread.restype = ctypes.c_void_p
    k.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k.SuspendThread.argtypes = [ctypes.c_void_p]
    k.ResumeThread.argtypes = [ctypes.c_void_p]
    k.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k.CloseHandle.argtypes = [ctypes.c_void_p]

    rvas, names = load_symbols(a.map)
    tid_rva = symbol_rva(a.map, "g_dah2_present_thread_id")
    phase_rva = symbol_rva(a.map, "g_dah2_present_phase")
    reader = Reader(a.pid, suspend=False)
    modules = module_table(reader.handle)
    tid = struct.unpack("<i", reader.read(reader.base + tid_rva, 4))[0]
    if not tid:
        print("frame thread not known yet (no frame presented)")
        return 1
    th = k.OpenThread(0x0002 | 0x0008 | 0x0040, False, tid)  # SUSPEND_RESUME | GET_CONTEXT | QUERY_INFO
    if not th:
        raise ctypes.WinError(ctypes.get_last_error())

    unwinder = Unwinder(reader.handle) if a.unwind else None
    ctx = ctypes.create_string_buffer(1232 + 16)
    # CONTEXT must be 16-byte aligned
    addr = ctypes.addressof(ctx)
    aligned = (addr + 15) & ~15
    buf = (ctypes.c_char * 1232).from_address(aligned)

    class FT(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]
    k.GetThreadTimes.argtypes = [ctypes.c_void_p, ctypes.POINTER(FT), ctypes.POINTER(FT),
                                 ctypes.POINTER(FT), ctypes.POINTER(FT)]

    def thread_cpu_ms():
        c, e, kt, ut = FT(), FT(), FT(), FT()
        k.GetThreadTimes(th, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut))
        f = lambda t: ((t.hi << 32) | t.lo) / 10000.0
        return f(kt), f(ut)

    cpu0 = thread_cpu_ms()
    wall0 = time.perf_counter()
    counts = collections.defaultdict(collections.Counter)
    total = collections.Counter()
    period = 1.0 / a.hz
    end = time.perf_counter() + a.seconds
    nxt = time.perf_counter()
    while time.perf_counter() < end:
        phase = struct.unpack("<I", reader.read(reader.base + phase_rva, 4))[0]
        if phase != 1:  # the limiter is idle by design
            k.SuspendThread(th)
            ctypes.memset(aligned, 0, 1232)
            struct.pack_into("<I", buf, 0x30, 0x10000B if unwinder else 0x100001)  # FULL / CONTROL | AMD64
            ok = k.GetThreadContext(th, aligned)
            rip = struct.unpack_from("<Q", buf, 0xF8)[0] if ok else 0
            rsp = struct.unpack_from("<Q", buf, 0x98)[0] if ok else 0
            chain = None
            if unwinder and ok:
                try:
                    chain = unwinder.walk(th, aligned, limit=max(2, a.unwind))
                except Exception:
                    chain = None
            k.ResumeThread(th)
            if rip and chain:
                def lab(addr):
                    r = addr - reader.base
                    if 0 <= r < 0x4000000:
                        j = bisect.bisect_right(rvas, r) - 1
                        return names[j] if j >= 0 else "?"
                    for lo, hi, nm, mpath in modules:
                        if lo <= addr < hi:
                            return "[" + nm + "]", (lo, mpath)
                    return "?"
                parts = []
                for n_, addr in enumerate(chain[:a.unwind]):
                    t_ = lab(addr)
                    if isinstance(t_, tuple):
                        t_, (lo_, mp_) = t_
                        if n_ == 0:
                            nm_ = export_lookup(mp_, lo_, addr)
                            if nm_:
                                t_ = t_[:-1] + "!" + nm_ + "]"
                    if not parts or parts[-1] != t_:
                        parts.append(t_)
                counts[phase][" <- ".join(parts)] += 1
                total[phase] += 1
            elif rip:
                rva = rip - reader.base
                if 0 <= rva < 0x4000000:
                    i = bisect.bisect_right(rvas, rva) - 1
                    label = names[i] if i >= 0 else "?"
                else:
                    label = "?"
                    for lo, hi, nm, _path in modules:
                        if lo <= rip < hi:
                            label = "[" + nm + "]"
                            break
                    # Attribute to the nearest return address inside our own
                    # image on the raw stack (a heuristic: the first such
                    # value above RSP is normally the caller of the DLL leaf).
                    if rsp and a.callers:
                        raw = b""
                        for chunk in range(0, 4096, 512):
                            try:
                                raw += reader.read(rsp + chunk, 512)
                            except OSError:
                                break   # ran past the committed end of the stack
                        try:
                            for off in range(0, len(raw) - 7, 8):
                                v = struct.unpack_from("<Q", raw, off)[0]
                                r2 = v - reader.base
                                if 0x1000 <= r2 < 0x4000000:
                                    j = bisect.bisect_right(rvas, r2) - 1
                                    if j >= 0:
                                        label += " <- " + names[j]
                                        break
                        except OSError:
                            pass
                counts[phase][label] += 1
                total[phase] += 1
        nxt += period
        delay = nxt - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        else:
            nxt = time.perf_counter()
    cpu1 = thread_cpu_ms()
    wall = (time.perf_counter() - wall0) * 1000.0
    k.CloseHandle(th)
    reader.close()
    print("frame thread over the window: kernel %.0f ms + user %.0f ms of CPU in %.0f ms wall "
          "(%.0f%% busy: %.0f%% kernel, %.0f%% user)  [includes the profiler's own suspends]" %
          (cpu1[0] - cpu0[0], cpu1[1] - cpu0[1], wall,
           100 * ((cpu1[0] - cpu0[0]) + (cpu1[1] - cpu0[1])) / wall,
           100 * (cpu1[0] - cpu0[0]) / wall, 100 * (cpu1[1] - cpu0[1]) / wall))

    grand = sum(total.values()) or 1
    print("samples: %d over %.0fs at ~%.0f Hz (limiter idle excluded)" % (grand, a.seconds, a.hz))
    for phase in sorted(total):
        t = total[phase]
        print("\n== phase %d (%s): %d samples, %.1f%% of non-idle time ==" % (phase, PHASES.get(phase, "?"), t, 100.0 * t / grand))
        for label, c in counts[phase].most_common(a.top):
            print("   %5.1f%%  %s" % (100.0 * c / t, label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
