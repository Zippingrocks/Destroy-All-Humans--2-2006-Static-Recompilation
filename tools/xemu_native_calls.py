"""Log the Lua native-function call sequence of retail DAH2 in an OWNED private xemu.

  py -3 tools/xemu_native_calls.py --port 1256 --qmp-port 4466 --snapshot title0 --out calls.json

loadvm, inject a Start press, break at 0x2117FB (the `call [ebx]` inside the Lua native
thunk sub_002117C0) and record (poll, target=[ebx], ebx, [esp+8]) per call. The recomp's
equivalent log is g_fnt_nat in a DAH2_FN_TRACE build (tools/dump_fn_nat.py)."""
import argparse, json, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE

CALL_SITE = 0x2117FB
RET_SITE = 0x2117FD
ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--snapshot", default="title0"); ap.add_argument("--out", type=Path, required=True)
ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
ap.add_argument("--until-poll", type=int, default=150); ap.add_argument("--start2-poll", type=int, default=-1); ap.add_argument("--results", action="store_true"); ap.add_argument("--strings", action="store_true"); ap.add_argument("--seconds", type=float, default=120)
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
g.cmd("Z1,%x,1" % INPUT_SITE); g.cmd("Z0,%x,1" % CALL_SITE)
if a.results: g.cmd("Z0,%x,1" % RET_SITE)
proto_cache = {}
def proto_info(function):
    if function not in proto_cache:
        d = g.read(function, 0x44) or bytes(0x44)
        f08, code, count, so = struct.unpack_from("<I", d, 8)[0], struct.unpack_from("<I", d, 0x18)[0], struct.unpack_from("<I", d, 0x1C)[0], struct.unpack_from("<I", d, 0x40)[0]
        name = b""
        if 0x80000000 <= so < 0x90000000:
            name = (g.read(so + 20, 12) or b"")
        proto_cache[function] = (f08, code, count, so, name)
    return proto_cache[function]
def resolve(esp):
    st = g.read(esp, 1024) or b""
    w = struct.unpack("<%dI" % (len(st) // 4), st[:len(st) // 4 * 4])
    for k in range(2, min(256, len(w))):
        function = w[k]
        if not (0x80000000 <= function < 0x90000000): continue
        f08, code, count, so, name = proto_info(function)
        pc = w[k - 2]
        if w[k - 1] != f08 or pc < code or pc > code + (count * 4 if count else 4): continue
        if not (0x80000000 <= so < 0x90000000) or not name or not (0x20 <= name[0] <= 0x7E): continue
        return function, (pc - code) // 4, name
    return 0, 0, b""
args_log = []; strs_log = []
polls = 0; log = []; deadline = time.time() + a.seconds
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
        if eip == RET_SITE:
            esi_ = struct.unpack_from("<I", regs, 24)[0]; eax_ = struct.unpack_from("<I", regs, 0)[0]
            top_ = struct.unpack_from("<I", g.read(esi_, 4), 0)[0]
            tv_ = g.read(top_ - 8, 8) or bytes(8)
            log[-1] += [eax_, *struct.unpack("<2I", tv_), top_]
            g.cmd("z0,%x,1" % RET_SITE); g.send("s"); g.recv(3.0); g.cmd("Z0,%x,1" % RET_SITE); g.send("c"); continue
        ebx = struct.unpack_from("<I", regs, 12)[0]
        tgt = struct.unpack_from("<I", g.read(ebx, 4), 0)[0]
        arg0 = struct.unpack_from("<I", g.read(esp + 8, 4), 0)[0]
        pf, pci, nm = resolve(esp)
        nm = nm.ljust(12, bytes(1))[:12]
        esi_c = struct.unpack_from("<I", regs, 24)[0]
        base_ = struct.unpack_from("<I", g.read(esi_c + 0x10, 4), 0)[0]; top_c = struct.unpack_from("<I", g.read(esi_c, 4), 0)[0]
        av = [0xFFFFFFFF] * 8
        if 0x80000000 <= base_ <= top_c < 0x90000000:
            raw_ = g.read(base_, min(24, top_c - base_)) or b""
            for q_ in range(len(raw_) // 8): av[q_ * 2], av[q_ * 2 + 1] = struct.unpack_from("<II", raw_, q_ * 8)
            av[6] = (top_c - base_) // 8
        log.append([polls, tgt, esp, pf, pci] + list(struct.unpack("<3I", nm)))
        args_log.append(av)
        if a.strings:
            sv = []
            for q_ in range(3):
                if av[q_ * 2] == 3 and 0x80000000 <= av[q_ * 2 + 1] < 0x90000000:
                    sv.append((g.read(av[q_ * 2 + 1] + 0x14, 40) or b"").split(bytes(1))[0].decode("latin1"))
                else: sv.append(None)
            strs_log.append(sv)
        g.cmd("z0,%x,1" % CALL_SITE); g.send("s"); g.recv(3.0)      # step off the breakpoint, then re-arm
        g.cmd("Z0,%x,1" % CALL_SITE); g.send("c")
finally:
    g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
    g.cmd("z0,%x,1" % CALL_SITE); g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
a.out.write_text(json.dumps({"start_poll": a.start_poll, "polls": polls, "calls": log, "args": args_log, "strs": strs_log}))
print("%d native calls over %d polls" % (len(log), polls))
