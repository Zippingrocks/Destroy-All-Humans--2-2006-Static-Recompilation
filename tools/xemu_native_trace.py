"""After the first call of a given Lua native in retail, log calls to chosen guest functions.

  py -3 tools/xemu_native_trace.py --port 1256 --qmp-port 4466 --start2-poll 700 --native 0x1116C0 \
      --watch 0x1AF0E0 --watch 0x106490 --watch 0x101FE0 --count 40
Each watched hit prints esp+4.. (first args), the Lua stack top/base from the Lua state in esi/ecx when it looks like one."""
import argparse, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--native", type=lambda x: int(x, 0), required=True)
ap.add_argument("--watch", action="append", type=lambda x: int(x, 0), required=True)
ap.add_argument("--count", type=int, default=40); ap.add_argument("--min-poll", type=int, default=0)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
ap.add_argument("--start2-poll", type=int, default=-1); ap.add_argument("--seconds", type=float, default=2400)
a = ap.parse_args()
subprocess.run([sys.executable, str(Path(__file__).parent / "xemu_hmp.py"), "--qmp-port", str(a.qmp_port), "loadvm " + a.snapshot], capture_output=True); time.sleep(3)
g = Rsp(a.port); g.cmd("qSupported:multiprocess+;swbreak+")
code = None
for _ in range(6):
    try: code = g.read(INPUT_SITE, 16)
    except ValueError: code = None
    if code and code.hex() == INPUT_CODE: break
    g.interrupt(); time.sleep(0.5); g.buf = b""
assert code and code.hex() == INPUT_CODE
g.cmd("Z1,%x,1" % INPUT_SITE); g.cmd("Z0,%x,1" % a.native)
polls = 0; armed = False; n = 0; deadline = time.time() + a.seconds
def rd32(addr):
    d = g.read(addr, 4); return struct.unpack("<I", d)[0] if d else None
g.send("c")
try:
    while time.time() < deadline and n < a.count:
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
        ecx = struct.unpack_from("<I", regs, 4)[0]; edx = struct.unpack_from("<I", regs, 8)[0]
        if eip == a.native and not armed and polls >= a.min_poll:
            armed = True; print("native %#x hit at poll %d" % (a.native, polls), flush=True)
            for w in a.watch: g.cmd("Z0,%x,1" % w)
        elif eip in a.watch and armed:
            n += 1
            args = [rd32(esp + 4 * k) for k in range(5)]
            L = ecx if 0x80000000 <= ecx < 0x90000000 else None
            ext = ""
            if L:
                base = rd32(L + 0x10); top = rd32(L)
                ext = " L=%08x base=%s top=%s" % (L, base and hex(base), top and hex(top))
            print("%3d %#x ret=%08x ecx=%08x edx=%08x args=%s%s" % (n, eip, args[0] or 0, ecx, edx, " ".join("%08x" % (x or 0) for x in args[1:]), ext), flush=True)
        g.cmd("z0,%x,1" % eip); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % eip); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    for w in a.watch + [a.native]: g.cmd("z0,%x,1" % w)
    g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
