"""Log file opens/reads made by retail DAH2 (NtCreateFile/NtOpenFile/NtReadFile) in an OWNED private xemu.

  py -3 tools/xemu_fileops.py --port 1256 --qmp-port 4466 --start2-poll 700 --until-poll 900 --out fileops.json
Breakpoints go on the kernel functions the game's import thunks resolve to."""
import argparse, json, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--out", type=Path, required=True)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
ap.add_argument("--start2-poll", type=int, default=-1); ap.add_argument("--until-poll", type=int, default=900)
ap.add_argument("--seconds", type=float, default=2400)
a = ap.parse_args()
THUNKS = {"NtCreateFile": 0x29b57c, "NtOpenFile": 0x29b548, "NtReadFile": 0x29b504}
subprocess.run([sys.executable, str(Path(__file__).parent / "xemu_hmp.py"), "--qmp-port", str(a.qmp_port), "loadvm " + a.snapshot], capture_output=True); time.sleep(3)
g = Rsp(a.port); g.cmd("qSupported:multiprocess+;swbreak+")
code = None
for _ in range(6):
    try: code = g.read(INPUT_SITE, 16)
    except ValueError: code = None
    if code and code.hex() == INPUT_CODE: break
    g.interrupt(); time.sleep(0.5); g.buf = b""
assert code and code.hex() == INPUT_CODE
targets = {}
for name, slot in THUNKS.items():
    targets[struct.unpack("<I", g.read(slot, 4))[0]] = name
print({hex(k): v for k, v in targets.items()}, flush=True)
g.cmd("Z1,%x,1" % INPUT_SITE)
for t in targets: g.cmd("Z0,%x,1" % t)
polls = 0; log = []; deadline = time.time() + a.seconds
def rd32(addr): return struct.unpack("<I", g.read(addr, 4))[0]
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
            if a.start_poll <= polls < a.start_poll + a.hold or (a.start2_poll >= 0 and a.start2_poll <= polls < a.start2_poll + a.hold): struct.pack_into("<H", pad, 4, 0x10)
            struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0)
            g.write(state, bytes(pad))
            struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (esp + 12) & 0xFFFFFFFF)
            struct.pack_into("<I", regs, 32, r)
            assert g.cmd("G" + regs.hex()) == "OK"; polls += 1; g.send("c"); continue
        name = targets.get(eip)
        if name in ("NtCreateFile", "NtOpenFile"):
            oa = rd32(esp + 12); nameptr = rd32(oa + 4)
            ln, mx, buf = struct.unpack("<HHI", g.read(nameptr, 8)); s = (g.read(buf, ln) or b"").decode("latin1")
            log.append([polls, name, s])
        elif name == "NtReadFile":
            log.append([polls, name, rd32(esp + 4), rd32(esp + 28), rd32(esp + 32) and struct.unpack("<q", g.read(rd32(esp + 32), 8))[0]])
        g.cmd("z0,%x,1" % eip); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % eip); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    for t in targets: g.cmd("z0,%x,1" % t)
    g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
a.out.write_text(json.dumps(log)); print(len(log), "file ops over", polls, "polls")
