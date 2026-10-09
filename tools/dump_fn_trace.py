"""Dump the function-entry trace of a DAH2_FN_TRACE build.

  py -3 tools/dump_fn_trace.py --pid P --map X.map --out trace.json
JSON: {"functions": {"0x001A7920": [first_present, order, count], ...}} for every
function entered since tracing was enabled."""
import argparse, json, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser()
ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--out", type=Path, required=True)
a = ap.parse_args()
r = Reader(a.pid, suspend=False)
SPACE = 0x400000
def arr(name):
    base = r.base + symbol_rva(a.map, name)
    raw = b"".join(r.read(base + o, 0x10000) for o in range(0, SPACE * 4, 0x10000))
    return struct.unpack("<%dI" % SPACE, raw)
first, order, count = arr("g_fnt_first"), arr("g_fnt_order"), arr("g_fnt_count")
fns = {"0x%08X" % i: [first[i], order[i], count[i]] for i in range(SPACE) if order[i]}
a.out.write_text(json.dumps({"functions": fns}))
print("%d functions recorded" % len(fns))
