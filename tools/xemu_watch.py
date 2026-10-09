"""Hardware write-watch a guest dword in an OWNED private xemu (Start injected) and log each write.

  py -3 tools/xemu_watch.py --port 1256 --qmp-port 4466 --addr 0x30D840 --start2-poll 700 --min-poll 700 --max-hits 80
Each hit: poll, writing eip (resolved to sub_XXXXXXXX+off), new value, and the nearest return addresses on the stack."""
import argparse, bisect, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE, function_index
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--addr", type=lambda x: int(x, 0), required=True)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
ap.add_argument("--start2-poll", type=int, default=-1); ap.add_argument("--min-poll", type=int, default=0)
ap.add_argument("--max-hits", type=int, default=100); ap.add_argument("--seconds", type=float, default=2400)
a = ap.parse_args()
starts = function_index()
def fn(addr):
    i = bisect.bisect_right(starts, addr) - 1
    return "sub_%08X+0x%X" % (starts[i], addr - starts[i]) if i >= 0 and addr < 0x300000 else "%08x" % addr
subprocess.run([sys.executable, str(Path(__file__).parent / "xemu_hmp.py"), "--qmp-port", str(a.qmp_port), "loadvm " + a.snapshot], capture_output=True); time.sleep(3)
g = Rsp(a.port); g.cmd("qSupported:multiprocess+;swbreak+")
code = None
for _ in range(6):
    try: code = g.read(INPUT_SITE, 16)
    except ValueError: code = None
    if code and code.hex() == INPUT_CODE: break
    g.interrupt(); time.sleep(0.5); g.buf = b""
assert code and code.hex() == INPUT_CODE
g.cmd("Z1,%x,1" % INPUT_SITE); assert g.cmd("Z2,%x,4" % a.addr) == "OK"
polls = 0; hits = 0; deadline = time.time() + a.seconds
g.send("c")
try:
    while time.time() < deadline and hits < a.max_hits:
        stop = g.recv(max(0.2, deadline - time.time()))
        if stop is None: break
        if not re.match(r"[ST]", stop): continue
        regs = bytearray(bytes.fromhex(g.cmd("g")))
        eip = struct.unpack_from("<I", regs, 32)[0]; esp = struct.unpack_from("<I", regs, 16)[0]
        if eip == INPUT_SITE:
            st = g.read(esp, 12); r = struct.unpack_from("<I", st, 0)[0]; state = struct.unpack_from("<I", st, 8)[0]
            pad = bytearray(22)
            if a.start_poll <= polls < a.start_poll + a.hold or (a.start2_poll >= 0 and a.start2_poll <= polls < a.start2_poll + a.hold): struct.pack_into("<H", pad, 4, 0x10)
            struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0)
            g.write(state, bytes(pad))
            struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (esp + 12) & 0xFFFFFFFF)
            struct.pack_into("<I", regs, 32, r)
            assert g.cmd("G" + regs.hex()) == "OK"; polls += 1; g.send("c"); continue
        if polls >= a.min_poll:
            hits += 1
            val = struct.unpack("<I", g.read(a.addr, 4))[0]
            stk = g.read(esp, 96) or b""
            rets = []
            for off in range(0, len(stk) - 3, 4):
                v = struct.unpack_from("<I", stk, off)[0]
                if 0x11000 <= v < 0x225CA0:
                    prev = g.read(v - 5, 5)
                    if prev and prev[0] == 0xE8: rets.append(fn(v))
            print("poll %d hit %d: %s writes %#x  stack-callers: %s" % (polls, hits, fn(eip), val, " < ".join(rets[:4])), flush=True)
        g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    g.cmd("z2,%x,4" % a.addr); g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
