"""Send keys to the owned private xemu through QMP and optionally grab a frame.
  py -3 tools/xemu_keys.py --qmp-port 4466 --keys ret --hold-ms 120
Keys are QMP qcodes (ret, spc, up, down, left, right, a, s, d, f, q, w, x, z, esc)."""
import argparse, json, socket, time
ap = argparse.ArgumentParser(); ap.add_argument("--qmp-port", type=int, default=4466)
ap.add_argument("--keys", required=True); ap.add_argument("--hold-ms", type=int, default=120); ap.add_argument("--repeat", type=int, default=1)
ap.add_argument("--gap-ms", type=int, default=400); a = ap.parse_args()
s = socket.create_connection(("127.0.0.1", a.qmp_port), 5); f = s.makefile("rb"); f.readline()
seq = [0]
def ex(cmd, args=None):
    seq[0] += 1; req = {"execute": cmd, "id": seq[0]}
    if args: req["arguments"] = args
    s.sendall(json.dumps(req).encode() + b"\r\n")
    while True:
        r = json.loads(f.readline())
        if r.get("id") == seq[0]: return r
ex("qmp_capabilities")
for n in range(a.repeat):
    r = ex("send-key", {"keys": [{"type": "qcode", "data": k} for k in a.keys.split("+")], "hold-time": a.hold_ms})
    print(n, r.get("return", r.get("error")))
    time.sleep(a.gap_ms / 1000.0)
s.close()
