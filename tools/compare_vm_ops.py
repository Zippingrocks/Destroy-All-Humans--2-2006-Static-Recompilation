"""Compare two Lua VM instruction streams (retail xemu_vmops.py vs recomp dump_fn_nat.py *.vm.json).
Reports the first index where the instruction WORDS differ, with context. Heap pc pointers are ignored."""
import argparse, json
ap = argparse.ArgumentParser(); ap.add_argument("retail"); ap.add_argument("recomp")
ap.add_argument("--context", type=int, default=12); ap.add_argument("--after", type=int, default=12)
a = ap.parse_args()
X = json.load(open(a.retail))["ops"]; R = json.load(open(a.recomp))["ops"]
n = min(len(X), len(R)); k = 0
while k < n and X[k][1] == R[k][1]: k += 1
print("streams: retail %d ops, recomp %d ops; identical for %d ops" % (len(X), len(R), k))
if k < n:
    for j in range(max(0, k - a.context), min(n, k + a.after)):
        x, r = X[j], R[j]
        print("%6d retail %08x %08x op%2d | recomp %08x %08x op%2d %s" % (j, x[0], x[1], x[1] & 63, r[0], r[1], r[1] & 63, "" if x[1] == r[1] else "<<<"))
