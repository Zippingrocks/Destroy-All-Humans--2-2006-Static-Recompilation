"""Log retail Lua VM instruction words after the first native call to --anchor (default 0xC2720).

  py -3 tools/xemu_vmops.py --port 1256 --qmp-port 4466 --out vmops.json [--ops 400]
loadvm, inject Start, break on the anchor native's entry; then break on the VM dispatch
(0x218DF1) and record {pc pointer, instruction word} for --ops instructions."""
import argparse, json, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--out", type=Path, required=True)
ap.add_argument("--anchor", type=lambda x: int(x, 0), default=0xC2720); ap.add_argument("--ops", type=int, default=400); ap.add_argument("--anchor-skip", type=int, default=0)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
ap.add_argument("--seconds", type=float, default=900); ap.add_argument("--min-poll", type=int, default=22); ap.add_argument("--start2-poll", type=int, default=-1)
a = ap.parse_args()
DISPATCH = 0x218DF1
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
g.cmd("Z1,%x,1" % INPUT_SITE); g.cmd("Z0,%x,1" % a.anchor)
polls = 0; anchor_seen = 0; armed = False; ops = []; deadline = time.time() + a.seconds
g.send("c")
try:
    while time.time() < deadline and len(ops) < a.ops:
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
        if eip == a.anchor and not armed and polls >= a.min_poll and anchor_seen < a.anchor_skip:
            anchor_seen += 1
            g.cmd("z0,%x,1" % eip); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % eip); g.send("c"); continue
        if eip == a.anchor and not armed and polls >= a.min_poll:
            armed = True; print("anchor hit at poll", polls, flush=True)
            g.cmd("z0,%x,1" % a.anchor); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % DISPATCH); g.send("c"); continue
        if eip == a.anchor:
            g.cmd("z0,%x,1" % eip); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % eip); g.send("c"); continue
        if eip == DISPATCH:
            pcp = struct.unpack_from("<I", g.read(esp + 0x10, 4), 0)[0]
            ins = struct.unpack_from("<I", g.read(pcp, 4), 0)[0]
            row = [pcp, ins]
            if ins & 63 == 32:       # EQ-and-jump: record the two TValues below the VM stack top (ebp)
                top = struct.unpack_from("<I", regs, 20)[0]
                tv = g.read(top - 16, 16) or bytes(16)
                row += list(struct.unpack("<4I", tv))
            ops.append(row)
            g.cmd("z0,%x,1" % DISPATCH); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % DISPATCH); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    for b in (a.anchor, DISPATCH): g.cmd("z0,%x,1" % b)
    g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
a.out.write_text(json.dumps({"ops": ops})); print(len(ops), "VM ops")
