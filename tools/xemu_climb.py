"""Climb the retail call chain above a function, one real caller per xemu run.

  py -3 tools/xemu_climb.py --port 1256 --qmp-port 4466 --snapshot title0 --target 0x1A7920 \
        --executed recomp_fnt.json [--min-poll 23]

Each iteration: loadvm <snapshot>, inject Start at the XInputGetState hook, break on the
target function's entry, read the return address at [esp] (the true direct caller, no stack
scanning), resolve it to the containing generated function, then repeat with that caller as
the new target. Stops when the caller is a function the recomp executes in the stuck state
(--executed = dump_fn_trace.py JSON), because that is where the two paths diverge."""
import argparse, bisect, json, re, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE, function_index

def run_once(port, qmp, snap, target, min_poll, start_poll, hold, seconds):
    subprocess.run([sys.executable, str(Path(__file__).parent / "xemu_hmp.py"), "--qmp-port", str(qmp), "loadvm " + snap],
                   capture_output=True); time.sleep(3)
    g = Rsp(port); g.cmd("qSupported:multiprocess+;swbreak+")
    code = None
    for _ in range(6):
        try: code = g.read(INPUT_SITE, 16)
        except ValueError: code = None
        if code and code.hex() == INPUT_CODE: break
        g.interrupt(); time.sleep(0.5); g.buf = b""
    assert code and code.hex() == INPUT_CODE
    g.cmd("Z1,%x,1" % INPUT_SITE); g.cmd("Z0,%x,1" % target)
    polls = 0; ret = None; stack = b""; deadline = time.time() + seconds
    g.send("c")
    try:
        while time.time() < deadline:
            stop = g.recv(max(0.2, deadline - time.time()))
            if stop is None: break
            if not re.match(r"[ST]", stop): continue
            regs = bytearray(bytes.fromhex(g.cmd("g")))
            eip = struct.unpack_from("<I", regs, 32)[0]; esp = struct.unpack_from("<I", regs, 16)[0]
            if eip == INPUT_SITE:
                st = g.read(esp, 12); r = struct.unpack_from("<I", st, 0)[0]; state = struct.unpack_from("<I", st, 8)[0]
                pad = bytearray(22)
                if start_poll <= polls < start_poll + hold: struct.pack_into("<H", pad, 4, 0x10)
                struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0)
                g.write(state, bytes(pad))
                struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (esp + 12) & 0xFFFFFFFF)
                struct.pack_into("<I", regs, 32, r)
                assert g.cmd("G" + regs.hex()) == "OK"; polls += 1; g.send("c"); continue
            if eip == target and polls >= min_poll:
                ret = struct.unpack_from("<I", g.read(esp, 4), 0)[0]; stack = g.read(esp, 64) or b""
                break
            g.send("c")
    finally:
        g.s.sendall(b"\x03"); g.recv(3.0); g.buf = b""
        g.cmd("z0,%x,1" % target); g.cmd("z1,%x,1" % INPUT_SITE); g.send("c"); time.sleep(0.3); g.s.close()
    return ret, polls

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True); ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--snapshot", default="title0"); ap.add_argument("--target", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--executed", type=Path); ap.add_argument("--min-poll", type=int, default=23)
    ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
    ap.add_argument("--depth", type=int, default=12); ap.add_argument("--seconds", type=float, default=60)
    a = ap.parse_args()
    starts = function_index()
    executed = set(int(k, 16) for k in json.loads(a.executed.read_text())["functions"]) if a.executed else set()
    def owner(addr):
        i = bisect.bisect_right(starts, addr) - 1
        return starts[i] if i >= 0 else None
    target = a.target
    for level in range(a.depth):
        ret, polls = run_once(a.port, a.qmp_port, a.snapshot, target, a.min_poll, a.start_poll, a.hold, a.seconds)
        if ret is None:
            print("level %d: target %#x not hit after Start (polls=%d)" % (level, target, polls)); return
        caller = owner(ret)
        print("sub_%08X  <- called from %#x = sub_%08X+0x%X   %s (poll %d)" % (
            target, ret, caller or 0, ret - (caller or 0), "[recomp RUNS this]" if caller in executed else "[recomp never ran it]", polls), flush=True)
        if caller is None or caller in executed: print("divergence: recomp runs sub_%08X but the retail path continues into sub_%08X" % (caller or 0, target)); return
        target = caller
if __name__ == "__main__":
    main()
