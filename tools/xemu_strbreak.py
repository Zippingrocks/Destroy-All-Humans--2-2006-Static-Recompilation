"""Retail: break at a C-string-taking function (default luaS_new 0x217270, string ptr in edx) and report the call stack
for hits whose string equals --match.
  py -3 tools/xemu_strbreak.py --port 1256 --qmp-port 4466 --match driver --max-hits 4 [--start2-poll 700]"""
import argparse, bisect, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE, function_index
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--bp", type=lambda x: int(x, 0), default=0x217270)
ap.add_argument("--reg", default="edx"); ap.add_argument("--match", required=True); ap.add_argument("--max-hits", type=int, default=3)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10); ap.add_argument("--start2-poll", type=int, default=-1)
ap.add_argument("--min-poll", type=int, default=0); ap.add_argument("--seconds", type=float, default=3000)
a = ap.parse_args()
starts = function_index()
def fn(ad):
    i = bisect.bisect_right(starts, ad) - 1
    return "sub_%08X+0x%X" % (starts[i], ad - starts[i]) if i >= 0 and ad < 0x300000 else "%08x" % ad
subprocess.run([sys.executable, str(Path(__file__).parent / "xemu_hmp.py"), "--qmp-port", str(a.qmp_port), "loadvm " + a.snapshot], capture_output=True); time.sleep(3)
g = Rsp(a.port); g.cmd("qSupported:multiprocess+;swbreak+")
code = None
for _ in range(6):
    try: code = g.read(INPUT_SITE, 16)
    except ValueError: code = None
    if code and code.hex() == INPUT_CODE: break
    g.interrupt(); time.sleep(0.5); g.buf = b""
assert code and code.hex() == INPUT_CODE
g.cmd("Z1,%x,1" % INPUT_SITE); g.cmd("Z0,%x,1" % a.bp)
REGS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]
polls = 0; hits = 0; seen = 0; deadline = time.time() + a.seconds; want = a.match.encode()
g.send("c")
try:
    while time.time() < deadline and hits < a.max_hits:
        stop = g.recv(max(0.2, deadline - time.time()))
        if stop is None: break
        if not re.match(r"[ST]", stop): continue
        regs = bytearray(bytes.fromhex(g.cmd("g"))); r = dict(zip(REGS, struct.unpack_from("<9I", regs, 0)))
        if r["eip"] == INPUT_SITE:
            st = g.read(r["esp"], 12); ret = struct.unpack_from("<I", st, 0)[0]; state = struct.unpack_from("<I", st, 8)[0]
            pad = bytearray(22)
            if a.start_poll <= polls < a.start_poll + a.hold or (a.start2_poll >= 0 and a.start2_poll <= polls < a.start2_poll + a.hold): struct.pack_into("<H", pad, 4, 0x10)
            struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0); g.write(state, bytes(pad))
            struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (r["esp"] + 12) & 0xFFFFFFFF); struct.pack_into("<I", regs, 32, ret)
            assert g.cmd("G" + regs.hex()) == "OK"; polls += 1; g.send("c"); continue
        seen += 1
        s = (g.read(r[a.reg], len(want) + 1) or b"")
        if polls >= a.min_poll and s == want + b"\0":
            hits += 1
            stk = g.read(r["esp"], 1024) or b""
            rets = [fn(struct.unpack_from("<I", stk, o)[0]) for o in range(0, len(stk) - 3, 4) if 0x11000 <= struct.unpack_from("<I", stk, o)[0] < 0x225CA0]
            print("== hit %d poll %d (seen %d): %s" % (hits, polls, seen, " < ".join(rets[:14])), flush=True)
        g.cmd("z0,%x,1" % r["eip"]); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % r["eip"]); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    g.cmd("z0,%x,1" % a.bp); g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
