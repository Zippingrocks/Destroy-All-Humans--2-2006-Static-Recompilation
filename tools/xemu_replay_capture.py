"""Capture the pre/post memory state of one call of a retail guest function in an OWNED private xemu, for replay against the
recompiled version (src/dah2_fn_trace.c dah2_replay).

  py -3 tools/xemu_replay_capture.py --port 1256 --qmp-port 4466 --func 0x1D0260 --skip 19 --min-poll 700 --start2-poll 700 --out sort19.bin

At the function's entry breakpoint it records the registers and the stack arguments, then crawls pointers (heap and stack
ranges) from ecx, the stack frame and the argument values, reading a chunk per pointer (using the pool block header for the exact
size when there is one).  It then runs to the return address and reads the same chunks again.  The .bin layout is read by
dah2_replay():  u32 magic 'RPL1', u32 func, 9 x u32 regs (eax ecx edx ebx esp ebp esi edi eip), u32 stack_lo, u32 stack_hi,
u32 npre, npre x {u32 addr, u32 len, bytes}, u32 npost, npost x {u32 addr, u32 len, bytes}."""
import argparse, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--func", type=lambda x: int(x, 0), required=True)
ap.add_argument("--skip", type=int, default=0); ap.add_argument("--min-poll", type=int, default=0)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10); ap.add_argument("--start2-poll", type=int, default=-1)
ap.add_argument("--out", type=Path, required=True); ap.add_argument("--seconds", type=float, default=3000)
ap.add_argument("--stack-below", type=int, default=0x200); ap.add_argument("--stack-above", type=int, default=0x400)
ap.add_argument("--max-chunks", type=int, default=400); ap.add_argument("--depth", type=int, default=3)
a = ap.parse_args()
REGS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]
HEAP_LO, HEAP_HI = 0x80010000, 0x88000000

subprocess.run([sys.executable, str(Path(__file__).parent / "xemu_hmp.py"), "--qmp-port", str(a.qmp_port), "loadvm " + a.snapshot], capture_output=True)
time.sleep(3)
g = Rsp(a.port); g.cmd("qSupported:multiprocess+;swbreak+")
code = None
for _ in range(6):
    try: code = g.read(INPUT_SITE, 16)
    except ValueError: code = None
    if code and code.hex() == INPUT_CODE: break
    g.interrupt(); time.sleep(0.5); g.buf = b""
assert code and code.hex() == INPUT_CODE
g.cmd("Z1,%x,1" % INPUT_SITE); g.cmd("Z0,%x,1" % a.func)

def read(addr, n):
    out = b""
    while n > 0:
        k = min(n, 0x400)
        d = g.read(addr, k)
        if d is None or len(d) != k: return None
        out += d; addr += k; n -= k
    return out

def u32(b, o=0): return struct.unpack_from("<I", b, o)[0]

def crawl(roots, stack_lo, stack_hi):
    chunks = {}      # addr -> len
    work = [(r, 0) for r in roots]
    seen = set()
    while work and len(chunks) < a.max_chunks:
        p, depth = work.pop(0)
        in_heap = HEAP_LO <= p < HEAP_HI
        in_stack = stack_lo <= p < stack_hi
        if not (in_heap or in_stack) or p in seen: continue
        seen.add(p)
        size = 0x200
        if in_heap:
            hdr = g.read(p - 0xC, 12)
            if hdr and len(hdr) == 12 and u32(hdr, 8) in (0x30D854,):          # medium pool block: [p-8] = size|free
                sz = u32(hdr, 4) & ~1
                if 0 < sz <= 0x10000: size = sz
        start = p & ~0xF
        size = min(size + (p - start), 0x10000)
        d = read(start, size)
        if d is None: continue
        chunks[start] = size
        if depth < a.depth:
            for o in range(0, len(d) - 3, 4):
                v = u32(d, o)
                if (HEAP_LO <= v < HEAP_HI or stack_lo <= v < stack_hi) and (v & ~0xF) not in chunks:
                    work.append((v, depth + 1))
    return chunks

def merge(chunks):
    items = sorted(chunks.items()); out = []
    for ad, ln in items:
        if out and ad <= out[-1][0] + out[-1][1]:
            end = max(out[-1][0] + out[-1][1], ad + ln); out[-1] = (out[-1][0], end - out[-1][0])
        else: out.append((ad, ln))
    return out

polls = 0; hits = 0; deadline = time.time() + a.seconds; state = None
g.send("c")
try:
    while time.time() < deadline:
        stop = g.recv(max(0.2, deadline - time.time()))
        if stop is None: break
        if not re.match(r"[ST]", stop): continue
        regs = bytearray(bytes.fromhex(g.cmd("g"))); r = dict(zip(REGS, struct.unpack_from("<9I", regs, 0)))
        if r["eip"] == INPUT_SITE:
            st = g.read(r["esp"], 12); ret = struct.unpack_from("<I", st, 0)[0]; sa = struct.unpack_from("<I", st, 8)[0]
            pad = bytearray(22)
            if a.start_poll <= polls < a.start_poll + a.hold or (a.start2_poll >= 0 and a.start2_poll <= polls < a.start2_poll + a.hold): struct.pack_into("<H", pad, 4, 0x10)
            struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0); g.write(sa, bytes(pad))
            struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (r["esp"] + 12) & 0xFFFFFFFF); struct.pack_into("<I", regs, 32, ret)
            assert g.cmd("G" + regs.hex()) == "OK"; polls += 1; g.send("c"); continue
        if state is None and r["eip"] == a.func:
            if polls < a.min_poll: hits_skip = True
            else:
                hits += 1
                if hits > a.skip:
                    esp = r["esp"]; lo = esp - a.stack_below; hi = esp + a.stack_above
                    stk = read(esp, 0x40) or b""
                    roots = [r["ecx"], r["edx"], r["esi"], r["edi"], r["ebx"], r["ebp"]] + [u32(stk, o) for o in range(0, len(stk) - 3, 4)]
                    stack_chunk = (lo & ~0xF, hi - (lo & ~0xF))
                    chunks = crawl(roots, lo, hi)
                    chunks[stack_chunk[0]] = stack_chunk[1]
                    ranges = merge(chunks)
                    pre = [(ad, read(ad, ln)) for ad, ln in ranges]
                    pre = [(ad, d) for ad, d in pre if d is not None]
                    state = {"regs": r, "ranges": ranges, "pre": pre, "ret": u32(stk, 0), "lo": lo, "hi": hi}
                    print("captured pre-state at poll %d: %d ranges, %d bytes, ret=%08x" % (polls, len(pre), sum(len(d) for _, d in pre), state["ret"]), flush=True)
                    g.cmd("z0,%x,1" % a.func); g.cmd("Z0,%x,1" % state["ret"])
                    g.send("c"); continue
            g.cmd("z0,%x,1" % r["eip"]); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % r["eip"]); g.send("c"); continue
        if state is not None and r["eip"] == state["ret"]:
            post = [(ad, read(ad, ln)) for ad, ln in state["ranges"]]
            post = [(ad, d) for ad, d in post if d is not None]
            state["post"] = post; state["post_regs"] = r
            print("captured post-state: eax=%08x esp=%08x" % (r["eax"], r["esp"]), flush=True)
            break
        g.cmd("z0,%x,1" % r["eip"]); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % r["eip"]); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    g.cmd("z0,%x,1" % a.func)
    if state: g.cmd("z0,%x,1" % state["ret"])
    g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()

assert state and "post" in state, "capture failed"
with open(a.out, "wb") as f:
    f.write(struct.pack("<II", 0x314C5052, a.func))
    f.write(struct.pack("<9I", *[state["regs"][k] for k in REGS]))
    f.write(struct.pack("<II", state["lo"], state["hi"]))
    f.write(struct.pack("<I", len(state["pre"])))
    for ad, d in state["pre"]: f.write(struct.pack("<II", ad, len(d))); f.write(d)
    f.write(struct.pack("<I", len(state["post"])))
    for ad, d in state["post"]: f.write(struct.pack("<II", ad, len(d))); f.write(d)
    f.write(struct.pack("<9I", *[state["post_regs"][k] for k in REGS]))
print("wrote", a.out, a.out.stat().st_size, "bytes")
