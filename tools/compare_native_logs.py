"""Diff a retail (xemu_native_calls.py) and a recomp (dump_fn_nat.py) Lua native-call log, aligned at an anchor native.

  py -3 tools/compare_native_logs.py retail.json recomp.json --anchor 0xc2720 [--context 6] [--max 40]
Rows compare (native fn, chunk-name prefix, bytecode pc index); reports the first mismatch."""
import argparse, json, struct
ap = argparse.ArgumentParser(); ap.add_argument("retail"); ap.add_argument("recomp")
ap.add_argument("--anchor", type=lambda x: int(x, 0), required=True); ap.add_argument("--context", type=int, default=6)
ap.add_argument("--max", type=int, default=40); ap.add_argument("--start", type=int, default=0); a = ap.parse_args()
def load(p):
    rows = json.load(open(p))["calls"]
    def nm(r): return struct.pack("<3I", *r[5:8]).split(bytes(1))[0].decode("latin1")
    return [(r[1], nm(r), r[4]) for r in rows]
X, R = load(a.retail), load(a.recomp)
def anchor(seq, after=0):
    for i, t in enumerate(seq):
        if i >= after and t[0] == a.anchor: return i
xi, ri = anchor(X), anchor(R)
print("anchors: retail idx %s, recomp idx %s" % (xi, ri))
first = None
for k in range(a.start, 100000):
    if xi + k >= len(X) or ri + k >= len(R) or xi + k < 0 or ri + k < 0: break
    x, r = X[xi + k], R[ri + k]
    if x != r:
        first = k; break
print("first mismatch at offset", first)
for k in range(max(-a.context, (first or 0) - a.context), (first or 0) + a.max):
    x = X[xi + k] if 0 <= xi + k < len(X) else None; r = R[ri + k] if 0 <= ri + k < len(R) else None
    f = lambda t: t and "%7x %-14s pc=%-4d" % (t[0], t[1], t[2])
    print("%4d  retail %s | recomp %s %s" % (k, f(x), f(r), "" if x == r else "<<<"))
