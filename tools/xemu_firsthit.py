"""First-hit function trace of an OWNED private xemu running DAH2, with Start injected.

  py -3 tools/xemu_firsthit.py --port 1256 --out firsthit.json [--start-poll 20] [--seconds 60]

Sets a software breakpoint on every recompiled function start (from the generated
sources), runs the guest, injects a logical Start press through the XInputGetState hook,
and records the poll number + order of each function's FIRST entry (the breakpoint is
removed after it fires, so each function costs one stop). Compare with a
DAH2_FN_TRACE recomp run via tools/compare_fn_traces.py."""
import argparse, json, re, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, INPUT_CODE, function_index

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True); ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--start-poll", type=int, default=20); ap.add_argument("--hold", type=int, default=10)
    ap.add_argument("--seconds", type=float, default=60); ap.add_argument("--stop-at", default="")
    ap.add_argument("--settle-polls", type=int, default=60, help="keep tracing this many polls after --stop-at fires")
    a = ap.parse_args()
    starts = [x for x in function_index() if 0x11000 <= x < 0x225CA0]   # game .text only (DSOUND/D3D/XMV sections run the audio/GPU hardware paths)
    g = Rsp(a.port); g.cmd("qSupported:multiprocess+;swbreak+")
    code = None
    for _ in range(6):
        try: code = g.read(INPUT_SITE, 16)
        except ValueError: code = None
        if code and code.hex() == INPUT_CODE: break
        g.interrupt(); time.sleep(0.5); g.buf = b""
    assert code and code.hex() == INPUT_CODE
    assert g.cmd("Z1,%x,1" % INPUT_SITE) == "OK"
    # Pipelined insertion: send many Z0 packets before reading the acks.
    t0 = time.time(); live = set(starts)
    for i in range(0, len(starts), 200):
        batch = starts[i:i + 200]
        for ad in batch: g.send("Z0,%x,1" % ad)
        for ad in batch:
            r = g.recv(10.0)
            if r != "OK": live.discard(ad)
    print("inserted %d/%d breakpoints in %.1fs" % (len(live), len(starts), time.time() - t0), flush=True)
    stop_at = int(a.stop_at, 0) if a.stop_at else None
    hits = {}; polls = 0; order = 0; stop_poll = None
    deadline = time.time() + a.seconds
    g.send("c")
    try:
        while time.time() < deadline:
            stop = g.recv(max(0.2, deadline - time.time()))
            if stop is None: break
            if not re.match(r"[ST]", stop): continue
            regs = bytearray(bytes.fromhex(g.cmd("g")))
            eip = struct.unpack_from("<I", regs, 32)[0]; esp = struct.unpack_from("<I", regs, 16)[0]
            if eip == INPUT_SITE:
                st = g.read(esp, 12); ret = struct.unpack_from("<I", st, 0)[0]; state = struct.unpack_from("<I", st, 8)[0]
                pad = bytearray(22)
                if a.start_poll <= polls < a.start_poll + a.hold: struct.pack_into("<H", pad, 4, 0x10)
                struct.pack_into("<I", pad, 0, 1 if any(pad[4:]) else 0)
                g.write(state, bytes(pad))
                struct.pack_into("<I", regs, 0, 0); struct.pack_into("<I", regs, 16, (esp + 12) & 0xFFFFFFFF)
                struct.pack_into("<I", regs, 32, ret)
                assert g.cmd("G" + regs.hex()) == "OK"
                polls += 1
                if stop_poll is not None and polls >= stop_poll: break
                g.send("c"); continue
            if eip not in hits:
                order += 1; hits[eip] = [polls, order]
                if stop_at is not None and eip == stop_at and stop_poll is None:
                    stop_poll = polls + a.settle_polls
                    print("reached %#x at poll %d" % (eip, polls), flush=True)
            if g.cmd("z0,%x,1" % eip) != "OK": pass
            g.send("c")
    finally:
        try:
            g.s.sendall(b"\x03"); g.recv(3.0)
            for ad in list(live - set(hits)): g.send("z0,%x,1" % ad)
            g.cmd("z1,%x,1" % INPUT_SITE)
            time.sleep(1.0); g.buf = b""
            g.send("c"); time.sleep(0.3)
        except Exception as e: print("cleanup:", e)
        g.s.close()
    a.out.write_text(json.dumps({"start_poll": a.start_poll, "polls": polls,
                                 "functions": {"0x%08X" % k: v for k, v in hits.items()}}))
    print("%d functions first-entered over %d polls" % (len(hits), polls))
if __name__ == "__main__":
    main()
