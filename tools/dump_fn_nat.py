"""Dump the Lua native-call log (g_fnt_nat) of a DAH2_FN_TRACE build as JSON rows [present, target, closure, arg0]."""
import argparse, json, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("--out", type=Path, required=True); a = ap.parse_args()
r = Reader(a.pid, suspend=False)
idx = struct.unpack("<I", r.read(r.base + symbol_rva(a.map, "g_fnt_nat_idx"), 4))[0]
raw = r.read(r.base + symbol_rva(a.map, "g_fnt_nat"), 65536 * 32)
rows = [list(struct.unpack_from("<8I", raw, i * 32)) for i in range(min(idx, 65536))]
if idx > 65536: rows = rows[idx % 65536:] + rows[:idx % 65536]
a.out.write_text(json.dumps({"count": idx, "calls": rows})); print("%d calls (ring holds %d)" % (idx, len(rows)))

if True:
    vidx = struct.unpack("<I", r.read(r.base + symbol_rva(a.map, "g_fnt_vm_idx"), 4))[0]
    vraw = r.read(r.base + symbol_rva(a.map, "g_fnt_vm"), 65536 * 8)
    vm = [list(struct.unpack_from("<2I", vraw, i * 8)) for i in range(min(vidx, 65536))]
    a.out.with_suffix(".vm.json").write_text(json.dumps({"count": vidx, "ops": vm})); print("%d VM ops" % vidx)

pre = r.read(r.base + symbol_rva(a.map, "g_fnt_vm_pre_snap"), 256 * 8)
a.out.with_suffix(".pre.json").write_text(json.dumps({"ops": [list(struct.unpack_from("<2I", pre, i * 8)) for i in range(256)]}))

fi = struct.unpack("<I", r.read(r.base + symbol_rva(a.map, "g_fnt_flog_idx"), 4))[0]
fl = struct.unpack("<%dI" % 16384, r.read(r.base + symbol_rva(a.map, "g_fnt_flog"), 16384 * 4))
order = list(fl[:fi]) if fi <= 16384 else list(fl[fi % 16384:]) + list(fl[:fi % 16384])   # ring: oldest .. newest
a.out.with_suffix(".flog.json").write_text(json.dumps({"count": fi, "fns": ["0x%08X" % x for x in order]})); print("%d logged function entries (ring keeps the last 16384)" % fi)

ext = r.read(r.base + symbol_rva(a.map, "g_fnt_vm_ext"), 65536 * 16)
a.out.with_suffix(".ext.json").write_text(json.dumps([list(struct.unpack_from("<4I", ext, i * 16)) for i in range(min(vidx, 65536))]))

res = r.read(r.base + symbol_rva(a.map, "g_fnt_natres"), 65536 * 16)
a.out.with_suffix(".res.json").write_text(json.dumps([list(struct.unpack_from("<4I", res, i * 16)) for i in range(min(idx, 65536))]))

arg = r.read(r.base + symbol_rva(a.map, "g_fnt_natargs"), 65536 * 32)
a.out.with_suffix(".args.json").write_text(json.dumps([list(struct.unpack_from("<8I", arg, i * 32)) for i in range(min(idx, 65536))]))

pi = struct.unpack("<I", r.read(r.base + symbol_rva(a.map, "g_fnt_probe_idx"), 4))[0]
praw = r.read(r.base + symbol_rva(a.map, "g_fnt_probe"), 8192 * 20)
a.out.with_suffix(".probe.json").write_text(json.dumps([list(struct.unpack_from("<5I", praw, i * 20)) for i in range(min(pi, 8192))]))

wi = struct.unpack("<I", r.read(r.base + symbol_rva(a.map, "g_fnt_wlog_idx"), 4))[0]
if wi:
    wraw = r.read(r.base + symbol_rva(a.map, "g_fnt_wlog"), min(wi, 1048576) * 4)
    a.out.with_suffix(".wlog.json").write_text(json.dumps([("0x%08X" % x) for x in struct.unpack("<%dI" % (len(wraw) // 4), wraw)])); print("%d windowed function entries" % wi)

wv = struct.unpack("<I", r.read(r.base + symbol_rva(a.map, "g_fnt_wvm_idx"), 4))[0]
if wv:
    wraw = r.read(r.base + symbol_rva(a.map, "g_fnt_wvm"), min(wv, 262144) * 12)
    a.out.with_suffix(".wvm.json").write_text(json.dumps([list(struct.unpack_from("<3I", wraw, i * 12)) for i in range(len(wraw) // 12)])); print("%d windowed VM ops" % wv)
