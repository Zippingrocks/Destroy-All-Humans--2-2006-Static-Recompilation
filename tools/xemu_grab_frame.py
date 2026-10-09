"""Pause an OWNED private xemu, export its front surface through parity_framebuffer, resume.

    py -3 tools/xemu_grab_frame.py --run diagnostics/.../xemu_runs/kx1 --qmp-port 4460 --gdb-port 1250 --tag t60

Writes <run>/fb_<tag>.{json,raw,png}. Only for instances this session launched itself
(kx_* runs): it issues QMP stop/cont, which the read-only parity_probe wrapper forbids.
"""
import argparse, json, socket, subprocess, sys
from pathlib import Path

def qmp(port, cmd):
    s = socket.create_connection(("127.0.0.1", port), 5)
    f = s.makefile("rb"); f.readline()
    def ex(c):
        s.sendall(json.dumps({"execute": c}).encode() + b"\r\n")
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r: return r
    ex("qmp_capabilities"); r = ex(cmd); s.close(); return r

ap = argparse.ArgumentParser()
ap.add_argument("--run", type=Path, required=True)
ap.add_argument("--qmp-port", type=int, required=True)
ap.add_argument("--gdb-port", type=int, required=True)
ap.add_argument("--tag", required=True)
a = ap.parse_args()
here = Path(__file__).parent
qmp(a.qmp_port, "stop")
try:
    p = subprocess.run([sys.executable, str(here / "parity_framebuffer.py"), "capture",
        "--manifest", str(a.run / "background.json"), "--qmp-port", str(a.qmp_port),
        "--gdb-port", str(a.gdb_port), "--output", str(a.run / f"fb_{a.tag}")],
        capture_output=True, text=True)
finally:
    qmp(a.qmp_port, "cont")
print(p.returncode, (p.stdout or p.stderr)[-300:].replace("\n", " "))
