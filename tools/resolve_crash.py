"""Print the guest-function call chain from a run's stdout.log [CRASH] block (resolves NATIVE-FRAME RVAs via the map).
   py -3 tools/resolve_crash.py RUN_DIR"""
import bisect, re, sys
from pathlib import Path
run = Path(sys.argv[1])
log = (run / "stdout.log").read_text(errors="replace")
i = log.find("[CRASH]")
blk = log[i:i + 6000]
print("\n".join(blk.splitlines()[:6]))
rows = []; started = False
for l in (run / "dah2_recomp.map").read_text(errors="replace").splitlines():
    if "Rva+Base" in l: started = True; continue
    if not started: continue
    p = l.split()
    if len(p) >= 3 and p[0].startswith("0001:"):
        try: rows.append((int(p[2], 16) - 0x140000000, p[1]))
        except ValueError: pass
rows.sort(); keys = [r[0] for r in rows]
frames = [int(m.group(1), 16) for m in re.finditer(r"NATIVE-FRAME\] \d+ RVA=([0-9A-F]+)", blk)]
print("call chain (innermost first):")
last = None
for r in frames[:40]:
    j = bisect.bisect_right(keys, r) - 1; n = rows[j][1] if j >= 0 else "?"
    if n != last: print("  ", n); last = n
