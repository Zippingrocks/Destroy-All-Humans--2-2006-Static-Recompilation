"""Break at guest addresses in an OWNED private xemu after replaying Start, print registers + memory.

  py -3 tools/xemu_probe.py --port 1256 --qmp-port 4466 --snapshot title0 \
      --bp 0xC2744 --bp 0xC274B --min-poll 60 --max-hits 8 --mem "esp:32" --mem "eax:32"

--mem REG:LEN reads LEN bytes at a register's value (or an absolute 0xADDR:LEN) and prints
dwords + ASCII. Breakpoints step off and re-arm, so the same address can hit repeatedly."""
import argparse, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE

REGS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--bp", action="append", type=lambda x: int(x, 0), required=True)
ap.add_argument("--min-poll", type=int, default=0); ap.add_argument("--max-hits", type=int, default=10)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
ap.add_argument("--mem", action="append", default=[]); ap.add_argument("--seconds", type=float, default=90)
ap.add_argument("--skip", type=int, default=0, help="ignore this many hits first"); ap.add_argument("--arm-bp", type=lambda x: int(x, 0), default=0); ap.add_argument("--arm-nth", type=int, default=1); ap.add_argument("--start2-poll", type=int, default=-1)
a = ap.parse_args()
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
g.cmd("Z1,%x,1" % INPUT_SITE)
for b in a.bp + ([a.arm_bp] if a.arm_bp else []): g.cmd("Z0,%x,1" % b)
arm_hits = 0
polls = hits = skipped = 0; deadline = time.time() + a.seconds
g.send("c")
try:
    while time.time() < deadline and hits < a.max_hits:
        stop = g.recv(max(0.2, deadline - time.time()))
        if stop is None: break
        if not re.match(r"[ST]", stop): continue
        regs = bytearray(bytes.fromhex(g.cmd("g")))
        r = dict(zip(REGS, struct.unpack_from("<9I", regs, 0)))
        if r["eip"] == INPUT_SITE:
            st = g.read(r["esp"], 12); ret = struct.unpack_from("<I", st, 0)[0]; state = struct.unpack_from("<I", st, 8)[0]
            pad = bytearray(22)
            if a.start_poll <= polls < a.start_poll + a.hold or (a.start2_poll >= 0 and a.start2_poll <= polls < a.start2_poll + a.hold): struct.pack_into("<H", pad, 4, 0x10)
            struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0)
            g.write(state, bytes(pad))
            struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (r["esp"] + 12) & 0xFFFFFFFF)
            struct.pack_into("<I", regs, 32, ret)
            assert g.cmd("G" + regs.hex()) == "OK"; polls += 1; g.send("c"); continue
        eip = r["eip"]
        if a.arm_bp and eip == a.arm_bp:
            arm_hits += 1
            g.cmd("z0,%x,1" % eip); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % eip); g.send("c"); continue
        if a.arm_bp and arm_hits < a.arm_nth:
            g.cmd("z0,%x,1" % eip); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % eip); g.send("c"); continue
        if polls >= a.min_poll:
            if skipped < a.skip: skipped += 1
            else:
                hits += 1
                print("== hit %d at %#x poll %d  " % (hits, eip, polls) + " ".join("%s=%08x" % (k, r[k]) for k in REGS[:8]))
                for spec in a.mem:
                    base, ln = spec.split(":")
                    if base.startswith("*"):    # *reg+off: dereference the dword at reg+off first
                        rr, _, oo = base[1:].partition("+"); ea = r[rr] + (int(oo, 0) if oo else 0)
                        addr = struct.unpack_from("<I", g.read(ea, 4), 0)[0]
                    else: addr = r[base] if base in r else int(base, 0)
                    d = g.read(addr, int(ln, 0)) or b""
                    print("   [%s]=%08x: %s | %s" % (base, addr, " ".join("%08x" % struct.unpack_from("<I", d, i)[0] for i in range(0, len(d) - 3, 4)),
                          re.sub(rb"[^\x20-\x7e]", b".", d).decode()))
        g.cmd("z0,%x,1" % eip); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % eip); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    for b in a.bp + ([a.arm_bp] if a.arm_bp else []): g.cmd("z0,%x,1" % b)
    g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
