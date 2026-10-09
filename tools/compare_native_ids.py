"""Id-only comparison of retail vs recomp Lua native streams after an anchor native.
  py -3 tools/compare_native_ids.py retail.json recomp.json [--anchor 0xc2720] [--context 6]"""
import argparse, json, struct
ap = argparse.ArgumentParser(); ap.add_argument("retail"); ap.add_argument("recomp")
ap.add_argument("--anchor", type=lambda x: int(x, 0), default=0xc2720); ap.add_argument("--context", type=int, default=6); ap.add_argument("--max", type=int, default=16)
a = ap.parse_args()
def load(p):
    rows = json.load(open(p))["calls"]
    nm = lambda r: struct.pack("<3I", *r[5:8]).split(bytes(1))[0].decode("latin1")
    return [(r[1], nm(r)) for r in rows]
X, R = load(a.retail), load(a.recomp)
xi = next(i for i, t in enumerate(X) if t[0] == a.anchor); ri = next(i for i, t in enumerate(R) if t[0] == a.anchor)
k = 0
while xi + k < len(X) and ri + k < len(R) and X[xi + k][0] == R[ri + k][0]: k += 1
print("anchors retail %d recomp %d; ids match for %d natives (retail total %d, recomp total %d)" % (xi, ri, k, len(X) - xi, len(R) - ri))
for j in range(max(0, k - a.context), k + a.max):
    x = X[xi + j] if xi + j < len(X) else None; r = R[ri + j] if ri + j < len(R) else None
    f = lambda t: ("%7x %-16s" % t) if t else " " * 24
    print("%5d retail %s | recomp %s %s" % (j, f(x), f(r), "" if x and r and x[0] == r[0] else "<<<"))
