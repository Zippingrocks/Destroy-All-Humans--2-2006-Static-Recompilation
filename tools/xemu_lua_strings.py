"""Log string arguments of selected Lua natives (default print=0x214aa0 and tostring=0x215320) in retail.

  py -3 tools/xemu_lua_strings.py --port 1256 --qmp-port 4466 --natives 0x214aa0 --until-poll 130 --out strings.json
At each call: L=esi, args are the TValues from L->base... the last two TValues below L->top; strings
are read through the TString pointer (chars at +20)."""
import argparse, json, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--out", type=Path, required=True)
ap.add_argument("--natives", default="0x214aa0"); ap.add_argument("--until-poll", type=int, default=130)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
ap.add_argument("--seconds", type=float, default=600)
a = ap.parse_args(); want = {int(x, 0) for x in a.natives.split(",")}
SITE = 0x2117FB
subprocess.run([sys.executable, str(Path(__file__).parent / "xemu_hmp.py"), "--qmp-port", str(a.qmp_port), "loadvm " + a.snapshot], capture_output=True); time.sleep(3)
g = Rsp(a.port); g.cmd("qSupported:multiprocess+;swbreak+")
code = None
for _ in range(6):
    try: code = g.read(INPUT_SITE, 16)
    except ValueError: code = None
    if code and code.hex() == INPUT_CODE: break
    g.interrupt(); time.sleep(0.5); g.buf = b""
assert code and code.hex() == INPUT_CODE
g.cmd("Z1,%x,1" % INPUT_SITE); g.cmd("Z0,%x,1" % SITE)
polls = 0; log = []; deadline = time.time() + a.seconds
def tstr(ptr):
    if not (0x80000000 <= ptr < 0x90000000): return None
    d = g.read(ptr + 20, 48) or b""
    return d.split(bytes(1))[0].decode("latin1")
g.send("c")
try:
    while time.time() < deadline and polls < a.until_poll:
        stop = g.recv(max(0.2, deadline - time.time()))
        if stop is None: break
        if not re.match(r"[ST]", stop): continue
        regs = bytearray(bytes.fromhex(g.cmd("g")))
        eip = struct.unpack_from("<I", regs, 32)[0]; esp = struct.unpack_from("<I", regs, 16)[0]
        if eip == INPUT_SITE:
            st = g.read(esp, 12); r = struct.unpack_from("<I", st, 0)[0]; state = struct.unpack_from("<I", st, 8)[0]
            pad = bytearray(22)
            if a.start_poll <= polls < a.start_poll + a.hold: struct.pack_into("<H", pad, 4, 0x10)
            struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0)
            g.write(state, bytes(pad))
            struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (esp + 12) & 0xFFFFFFFF)
            struct.pack_into("<I", regs, 32, r)
            assert g.cmd("G" + regs.hex()) == "OK"; polls += 1; g.send("c"); continue
        ebx = struct.unpack_from("<I", regs, 12)[0]; esi = struct.unpack_from("<I", regs, 24)[0]
        tgt = struct.unpack_from("<I", g.read(ebx, 4), 0)[0]
        if tgt in want:
            top = struct.unpack_from("<I", g.read(esi, 4), 0)[0]; base = struct.unpack_from("<I", g.read(esi + 4, 4), 0)[0]
            args = []
            for p in range(base, top, 8):
                tv = g.read(p, 8) or bytes(8); tag, val = struct.unpack("<II", tv)
                args.append([tag, val, tstr(val) if tag == 4 else None])
            log.append([polls, tgt, args]); print(polls, hex(tgt), [x[2] if x[2] is not None else (x[0], hex(x[1])) for x in args][:4], flush=True)
        g.cmd("z0,%x,1" % SITE); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % SITE); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    g.cmd("z0,%x,1" % SITE); g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
a.out.write_text(json.dumps(log))
