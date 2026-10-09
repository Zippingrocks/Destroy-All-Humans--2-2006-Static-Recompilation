"""Arm the trace build's hardware write watch once the native-call index reaches N.
  py -3 tools/hw_arm_at_native.py --pid P --map M --native 10400 --addr 0x851000E4"""
import argparse, ctypes, struct, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--native", type=int, required=True); ap.add_argument("--addr", type=lambda x: int(x, 0), required=True); ap.add_argument("--timeout", type=float, default=600)
a = ap.parse_args()
r = Reader(a.pid, suspend=False); idx = r.base + symbol_rva(a.map, "g_fnt_nat_idx"); t0 = time.time()
while time.time() - t0 < a.timeout:
    if struct.unpack("<I", r.read(idx, 4))[0] >= a.native: break
    time.sleep(0.002)
subprocess.run([sys.executable, str(Path(__file__).parent / "write_global32.py"), "--pid", str(a.pid), "--map", str(a.map), "g_fnt_hw_addr", hex(a.addr)])
print("armed at native idx", struct.unpack("<I", r.read(idx, 4))[0])
