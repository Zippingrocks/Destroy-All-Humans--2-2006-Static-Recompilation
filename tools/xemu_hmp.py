"""Send one HMP command to an OWNED private xemu via QMP (savevm / loadvm / info snapshots).
   py -3 tools/xemu_hmp.py --qmp-port 4466 "savevm title0"
"""
import argparse, json, socket
ap = argparse.ArgumentParser(); ap.add_argument("--qmp-port", type=int, required=True); ap.add_argument("cmd")
a = ap.parse_args()
s = socket.create_connection(("127.0.0.1", a.qmp_port), 5); f = s.makefile("rb"); f.readline()
def ex(c, args=None):
    r = {"execute": c}
    if args: r["arguments"] = args
    s.sendall(json.dumps(r).encode() + b"\r\n"); s.settimeout(120)
    while True:
        x = json.loads(f.readline())
        if "return" in x or "error" in x: return x
ex("qmp_capabilities"); print(ex("human-monitor-command", {"command-line": a.cmd}))
