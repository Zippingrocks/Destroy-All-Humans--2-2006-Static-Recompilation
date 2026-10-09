"""Inject a logical Start press into an OWNED private xemu (XInputGetState hook, same
mechanism as parity_xemu_input_replay.mjs) and print a stack-scan backtrace at chosen
guest breakpoints.

  py -3 tools/xemu_bt.py --port 1254 --break 0x1A7920 [--start-poll 30] [--seconds 60]

Backtrace = every stack word that points just after a CALL inside the recompiled text
range, resolved to the generated sub_XXXXXXXX that contains it (heuristic: stale words
can appear, so read it top-down and sanity-check against the code).
"""
import argparse, bisect, glob, re, socket, struct, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT_SITE = 0x296224
INPUT_CODE = "535633dbff1510b629008b54240c8b8a"


def cs(s): return sum(s.encode()) & 0xFF


class Rsp:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10); self.buf = b""

    def _fill(self, t):
        self.s.settimeout(t)
        try: d = self.s.recv(65536)
        except socket.timeout: return False
        if not d: raise ConnectionError("closed")
        self.buf += d; return True

    def recv(self, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            while self.buf[:1] in (b"+", b"-"): self.buf = self.buf[1:]
            i = self.buf.find(b"$"); j = self.buf.find(b"#", i + 1) if i >= 0 else -1
            if i >= 0 and j >= 0 and len(self.buf) >= j + 3:
                body = self.buf[i + 1:j].decode(errors="replace"); self.buf = self.buf[j + 3:]
                self.s.sendall(b"+"); return body
            self._fill(0.2)
        return None

    def cmd(self, p, timeout=5.0):
        self.s.sendall(("$%s#%02x" % (p, cs(p))).encode()); return self.recv(timeout)

    def send(self, p): self.s.sendall(("$%s#%02x" % (p, cs(p))).encode())
    def interrupt(self): self.s.sendall(b"\x03"); return self.recv(5.0)
    def read(self, a, n):
        r = self.cmd("m%x,%x" % (a, n))
        while r and r[0] in "ST" and len(r) < 8: r = self.recv(2.0)      # stale stop reply
        return bytes.fromhex(r) if r and not r.startswith("E") else None
    def write(self, a, d): return self.cmd("M%x,%x:%s" % (a, len(d), d.hex())) == "OK"


def function_index():
    starts = []
    for f in glob.glob(str(ROOT / "src/recomp/gen/*.c")) + [str(ROOT / "src/recomp_manual.c")]:
        for m in re.finditer(r"^(?:void|static void|uint32_t) (?:safe_|override_)?sub_([0-9A-F]{8})\(", open(f, errors="replace").read(), re.M):
            starts.append(int(m.group(1), 16))
    starts = sorted(set(starts)); return starts


def save_front(g, path):
    from PIL import Image
    start = struct.unpack("<I", g.read(0xFD600800, 4))[0]
    raw = b"".join(g.read(0x80000000 + start + off, 2560 * 8) for off in range(0, 480 * 2560, 2560 * 8))
    Image.frombuffer("RGBA", (640, 480), raw, "raw", "BGRA", 2560, 1).convert("RGB").save(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--break", dest="brk", action="append", default=[], help="guest address (hex)")
    ap.add_argument("--start-poll", type=int, default=30)
    ap.add_argument("--hold", type=int, default=10)
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--stack-bytes", type=int, default=2048)
    ap.add_argument("--max-hits", type=int, default=3)
    ap.add_argument("--grab-polls", default="", help="comma list of poll numbers at which to export the front surface")
    ap.add_argument("--run", type=Path, help="xemu run dir (for --grab-polls)")
    ap.add_argument("--qmp-port", type=int)
    ap.add_argument("--tag", default="g")
    ap.add_argument("--dump-polls", default="", help="comma list of polls at which to dump --dump-range")
    ap.add_argument("--dump-range", default="0x2A0000:0xA0000", help="VA:LENGTH")
    a = ap.parse_args()
    starts = function_index()
    def fn(addr):
        i = bisect.bisect_right(starts, addr) - 1
        return "sub_%08X+0x%X" % (starts[i], addr - starts[i]) if i >= 0 else "?"
    g = Rsp(a.port)
    g.cmd("qSupported:multiprocess+;swbreak+")
    code = None
    for attempt in range(6):
        try: code = g.read(INPUT_SITE, 16)
        except ValueError: code = None
        if code is not None and code.hex() == INPUT_CODE: break
        g.interrupt(); time.sleep(0.5); g.buf = b""
    assert code and code.hex() == INPUT_CODE, "game not loaded yet: %r" % (code and code.hex())
    brks = [INPUT_SITE] + [int(x, 0) for x in a.brk]
    for b in brks: assert g.cmd("Z1,%x,1" % b) == "OK", "bp %x rejected" % b
    grab = {int(x) for x in a.grab_polls.split(",") if x}
    dump = {int(x) for x in a.dump_polls.split(",") if x}
    dva, dlen = (int(x, 0) for x in a.dump_range.split(":"))
    import subprocess
    polls = hits = 0; deadline = time.time() + a.seconds
    g.send("c")
    try:
        while time.time() < deadline and hits < a.max_hits:
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
                if polls in grab:      # read the scan-out surface through the same GDB session
                    try: save_front(g, a.run / ("fb_%s%04d.png" % (a.tag, polls)))
                    except Exception as e: print("grab poll %d failed: %s" % (polls, e))
                if polls in dump:
                    buf = b"".join((g.read(dva + o, min(0x800, dlen - o)) or bytes(min(0x800, dlen - o))) for o in range(0, dlen, 0x800))
                    (a.run / ("mem_%s%04d.bin" % (a.tag, polls))).write_bytes(buf)
                    print("dumped poll %d (%d bytes)" % (polls, len(buf)))
                polls += 1; g.send("c"); continue
            hits += 1
            print("=== HIT %#x after %d polls  eax=%08x ecx=%08x edx=%08x esp=%08x" % (eip, polls, *struct.unpack_from("<III", regs, 0)[:1], struct.unpack_from("<I", regs, 4)[0], struct.unpack_from("<I", regs, 8)[0], esp))
            stack = g.read(esp, a.stack_bytes) or b""
            lo = starts[0]; hi = starts[-1] + 0x4000
            for off in range(0, len(stack) - 3, 4):
                v = struct.unpack_from("<I", stack, off)[0]
                if lo <= v < hi:
                    prev = g.read(v - 5, 5)           # CALL rel32 / CALL [..] right before the return address
                    if prev and (prev[0] == 0xE8 or (len(prev) >= 2 and prev[3] == 0xFF)):
                        print("  [esp+%03x] %08x  %s%s" % (off, v, fn(v), "  <call>" if prev[0] == 0xE8 else "  <icall?>"))
            names = g.read(esp, 96) or b""
            print("  ascii:", re.sub(rb"[^\x20-\x7e]", b".", names).decode())
            g.send("c")
    finally:
        g.s.sendall(b"\x03"); g.recv(3.0)
        for b in brks: g.cmd("z1,%x,1" % b)
        g.send("c"); time.sleep(0.2); g.s.close()
main()
