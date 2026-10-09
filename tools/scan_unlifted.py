"""List functions in src/recomp/gen (and src/recomp_manual.c) that contain comment-only (unlifted) instructions.
  py -3 tools/scan_unlifted.py [--json OUT.json]  -> per-mnemonic function counts + the function list"""
import glob, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
fn_re = re.compile(r'^(?:static )?void (sub_[0-9A-F]{8})\(void\)\s*$', re.M)
pats = [re.compile(r'/\* TODO: ([a-z0-9]+) '), re.compile(r'/\* SSE: ([a-z0-9]+) '), re.compile(r'/\* ([a-z0-9]+) [^*]*\(MMX/SIMD integer\) \*/'),
        re.compile(r'/\* ([a-z0-9]+) [^*]*\*/\s*$')]
by_fn = defaultdict(Counter); where = {}
for f in sorted(glob.glob(str(ROOT / "src/recomp/gen/recomp_*.c"))):
    t = Path(f).read_bytes().decode("utf-8", "surrogateescape")
    ms = list(fn_re.finditer(t))
    for i, m in enumerate(ms):
        body = t[m.end(): ms[i + 1].start() if i + 1 < len(ms) else len(t)]
        for p in pats[:3]:
            for mm in p.finditer(body): by_fn[m.group(1)][mm.group(1)] += 1
        where[m.group(1)] = Path(f).name
tot = Counter()
for fn, c in by_fn.items():
    for k in c: tot[k] += 1
print("functions with unlifted ops:", len(by_fn))
for k, v in tot.most_common(): print("  %-10s in %d functions" % (k, v))
if "--json" in sys.argv:
    out = sys.argv[sys.argv.index("--json") + 1]
    Path(out).write_text(json.dumps({fn: dict(c) for fn, c in sorted(by_fn.items())}, indent=0))
