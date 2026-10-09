import os
"""Dump the guest-heap shadow checker events of a DAH2_FN_TRACE recomp: py -3 tools/dump_heap_check.py --pid P --map M"""
import argparse, bisect, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True); a = ap.parse_args()
r = Reader(a.pid, suspend=False)
_rows = []; _st = False
for _l in a.map.read_text(errors="replace").splitlines():
    if "Rva+Base" in _l: _st = True; continue
    if not _st: continue
    _p = _l.split()
    if len(_p) >= 3 and _p[0].startswith("0001:"):
        try: _rows.append((int(_p[2], 16) - 0x140000000, _p[1]))
        except ValueError: pass
_rows.sort(); _keys = [x[0] for x in _rows]
def sym(rva):
    j = bisect.bisect_right(_keys, rva) - 1
    return "%s+%x" % (_rows[j][1], rva - _rows[j][0]) if j >= 0 else "%x" % rva
def g32(n): return struct.unpack("<I", r.read(r.base + symbol_rva(a.map, n), 4))[0]
for pfx, label in (("heap", "medium pool"), ("sheap", "small pool")):
  n = g32("g_fnt_%s_ov_n" % pfx); print("==", label, "allocs", g32("g_fnt_%s_allocs" % pfx), "frees", g32("g_fnt_%s_frees" % pfx), "events", n)
  raw = r.read(r.base + symbol_rva(a.map, "g_fnt_%s_ov" % pfx), 64 * 48)
  kinds = {1: "OVERLAP", 2: "FREE-UNKNOWN", 3: "FREE-MISMATCH"}
  for i in range(min(n, 64)):
    k, ns, nsz, nra, nt, oseq, os_, osz, ora, ot, nat, seq = struct.unpack_from("<12I", raw, i * 48)
    print("%2d %-13s new %08x size %6x ra %06x tid %d | old seq %d at %08x size %6x ra %06x tid %d | native idx %d, alloc seq %d" % (i, kinds.get(k, k), ns, nsz, nra, nt, oseq, os_, osz, ora, ot, nat, seq))
n = g32("g_fnt_watch_n")
if n:
    wl = r.read(r.base + symbol_rva(a.map, "g_fnt_watch_log"), 256 * 24)
    print("== watch log (kind 1=med alloc 2=med free 3=small alloc 4=small free)")
    for i in range(min(n, 256)):
        k, ptr, sz, ra, nat, tid = struct.unpack_from("<6I", wl, i * 24)
        print("kind %d ptr %08x size %6x ra %06x native idx %d tid %d" % (k, ptr, sz, ra, nat, tid))
n = g32("g_fnt_hw_n")
if n:
    hl = r.read(r.base + symbol_rva(a.map, "g_fnt_hw_log"), 64 * 20 * 8)
    print("== hw write-watch hits")
    for i in range(min(n, 64)):
        row = struct.unpack_from("<20Q", hl, i * 160)
        print("hit %d: tid %d native idx %d value now %08x esp %08x ecx %08x RIP %s  bt: %s" % (i, row[2], row[1], row[19], row[17], row[18], sym(row[0] - r.base), " < ".join(sym(x - r.base) for x in row[3:17] if x)))
n = g32("g_fnt_chk_n")
print("== invalid children (calls %d, logged %d)" % (g32("g_fnt_chk_calls"), n))
if n:
    cr = r.read(r.base + symbol_rva(a.map, "g_fnt_chk"), 32 * 32)
    for i in range(min(n, 32)):
        s_, idx, p, vt, cnt, arr, nat, svt = struct.unpack_from("<8I", cr, i * 32)
        print("self %08x (vtbl %08x) child[%d/%d]=%08x vtbl=%08x array=%08x native idx %d" % (s_, svt, idx, cnt, p, vt, arr, nat))
n = g32("g_fnt_ib_n")
print("== bad indirect-call targets: %d" % n)
if n:
    ib = r.read(r.base + symbol_rva(a.map, "g_fnt_ib"), 32 * 56)
    for i in range(min(n, 32)):
        row = struct.unpack_from("<14I", ib, i * 56)
        print("target %08x ecx %08x edx %08x eax %08x esp %08x line %d native %d file %s" % (row[0], row[1], row[2], row[3], row[4], row[5], row[6], struct.pack("<7I", *row[7:14]).split(bytes(1))[0].decode("latin1")))
import math
sn = g32("g_fnt_sort_n")
print("== sort calls: %d" % sn)
if sn:
    sr = r.read(r.base + symbol_rva(a.map, "g_fnt_sort"), 512 * 40 * 4)
    fl = lambda w: struct.unpack("<f", struct.pack("<I", w))[0]
    rows = [(k, struct.unpack_from("<40I", sr, (k & 511) * 160)) for k in range(max(0, sn - 512), sn)]
    bad = [x for x in rows if x[1][16] >= 0xfd00 or x[1][16] == 0xDEAD]
    for k, row in (rows if len(rows) <= 80 else bad[:10] + rows[-8:]):
        print("#%d self %08x arr %08x box %08x cnt %d ra %06x native %d | id %08x ptr %08x S.count %d" % ((k,) + tuple(row[:6]) + (row[16], row[17], row[18])))
        print("   box floats:", " ".join("%g" % fl(w) for w in row[8:16]))
        print("   L2[0..3]", " ".join("%08x" % w for w in row[19:23]), "L0[0..3]", " ".join("%08x" % w for w in row[23:27]), "L1[0..3]", " ".join("%08x" % w for w in row[27:31]), "rec", " ".join("%08x" % w for w in row[31:35]))
sn2 = g32("g_fnt_sap_n"); fb = g32("g_fnt_sap_firstbad")
print("== sap validator: %d method entries, first bad = %s" % (sn2, "none" if fb == 0xFFFFFFFF else fb))
if sn2:
    sp = r.read(r.base + symbol_rva(a.map, "g_fnt_sap"), 4096 * 40)
    def row(k): return struct.unpack_from("<10I", sp, (k & 4095) * 40)
    if fb != 0xFFFFFFFF and sn2 - fb <= 4096:
        for k in range(max(0, fb - 12), min(sn2, fb + 3)):
            t_, nat_, st_, cnt_, a0_, a1_, a2_, det_, tid_, _x = row(k)
            print("%s #%d tid %d tag %06x native %d status %04x count %d args %08x %08x %08x detail %08x" % (">>" if k == fb else "  ", k, tid_, t_, nat_, st_, cnt_, a0_, a1_, a2_, det_))
    from collections import Counter
    print("method histogram:", dict(Counter(row(k)[0] for k in range(max(0, sn2 - 4096), sn2))))
if g32("g_snap_frozen_valid"):
    SZ = (16 + 36 + 3 * 514 + 260 * 4) * 4
    for nm in ("g_snap_pre", "g_snap_frozen_pre", "g_snap_frozen_post"):
        open(Path(a.map).parent / (nm + ".bin"), "wb").write(r.read(r.base + symbol_rva(a.map, nm), SZ))
    print("wrote snapshot buffers next to the map file")
nn_ = g32("g_fnt_note_n")
print("== notes: %d" % nn_)
if nn_:
    npb = r.read(r.base + symbol_rva(a.map, "g_fnt_note"), 1024 * 32)
    _shown = 0
    for k in range(max(0, nn_ - 1024), nn_):
        w = struct.unpack_from("<8I", npb, (k & 1023) * 32)
        if not (w[0] in (0x1BAD, 0x52AE) or 0x178294 <= w[0] <= 0x178C56 or k >= nn_ - 12): continue
        _shown += 1
        if _shown > 120 and k < nn_ - 12: continue
        print("note #%d tag %x native %d a=%08x b=%08x c=%08x tid %d [c]=%08x [c+4]=%08x" % ((k,) + w))
cn_ = g32("g_fnt_clob_n")
print("== callee-saved clobbers: %d distinct, %d total" % (cn_, g32("g_fnt_clob_total")))
if cn_:
    cb = r.read(r.base + symbol_rva(a.map, "g_fnt_clob"), 512 * 48)
    rows_ = [struct.unpack_from("<12I", cb, i * 48) for i in range(min(cn_, 512))]
    rows_.sort(key=lambda w: w[5 + 3 + 0] if False else w[0])
    for w in rows_[:512]:
        fn_, mask_, o0, o1, o2, n0, n1, n2, nat_, tid_, cnt_ = w[:11]
        print("sub_%08X mask %d (1=esi 2=edi 4=ebx) old %08x %08x %08x new %08x %08x %08x first native %d tid %d count %d" % (fn_, mask_, o0, o1, o2, n0, n1, n2, nat_, tid_, cnt_))
eb_ = g32("g_fnt_esp_bad")
print("== esp-delta inconsistencies: %d functions" % eb_)
if True:
    eb = r.read(r.base + symbol_rva(a.map, "g_fnt_esp"), 8192 * 32)
    import json as _json
    _all = []
    for i in range(8192):
        fn_, dl_, nat_, cnt_, bd_, bnat_, bc_, _p = struct.unpack_from("<8I", eb, i * 32)
        if fn_: _all.append([fn_, struct.unpack("<i", struct.pack("<I", dl_))[0], cnt_, struct.unpack("<i", struct.pack("<I", bd_))[0], bc_])
    (Path(a.map).parent / "esp_all.json").write_text(_json.dumps(_all))
if eb_:
    for i in range(8192):
        fn_, dl_, nat_, cnt_, bd_, bnat_, bc_, _p = struct.unpack_from("<8I", eb, i * 32)
        if fn_ and bc_:
            print("sub_%08X first delta %d (nat %d, %d calls) other delta %d (first at nat %d, %d calls)" % (fn_, struct.unpack("<i", struct.pack("<I", dl_))[0], nat_, cnt_, struct.unpack("<i", struct.pack("<I", bd_))[0], bnat_, bc_))
it_ = g32("g_fnt_it_n")
print("== unresolved indirect tail jumps: %d" % it_)
if it_:
    ib2 = r.read(r.base + symbol_rva(a.map, "g_fnt_it"), 64 * 56)
    for i in range(min(it_, 64)):
        row = struct.unpack_from("<14I", ib2, i * 56)
        print("target %08x ecx %08x edx %08x eax %08x esp %08x line %d native %d file %s count %d" % (row[0], row[1], row[2], row[3], row[4], row[5], row[6], struct.pack("<6I", *row[7:13]).split(bytes(1))[0].decode("latin1"), row[13]))
fi_ = g32("g_fnt_flog_idx")
print("== function entry tail (idx %d)" % fi_)
if fi_:
    fl = r.read(r.base + symbol_rva(a.map, "g_fnt_flog"), 16384 * 4)
    ents = [struct.unpack_from("<I", fl, ((k) & 16383) * 4)[0] for k in range(max(0, fi_ - 400), fi_)]
    print(" ".join("%x" % e for e in ents))
if eb_:
    sn_ = min(eb_, 16)
    sb = r.read(r.base + symbol_rva(a.map, "g_fnt_esp_snap"), 16 * 67 * 4)
    for i in range(sn_):
        row = struct.unpack_from("<67I", sb, i * 268)
        print("anomaly #%d sub_%08X esp_in %08x esp_out %08x; entries just before: %s" % (i, row[0], row[1], row[2], " ".join("%x" % x for x in row[3:])))
    sk = r.read(r.base + symbol_rva(a.map, "g_fnt_esp_stk"), 16 * 48 * 4)
    for i in range(sn_):
        row = struct.unpack_from("<48I", sk, i * 192)
        print("stack around esp_in for anomaly #%d (esp_in-0x90 .. esp_in+0x30):" % i)
        for j in range(0, 48, 8): print("   %s" % " ".join("%08x" % x for x in row[j:j + 8]))
pn_ = g32("g_fnt_path_n")
print("== label path tail (%d entries)" % pn_)
if pn_:
    pb = r.read(r.base + symbol_rva(a.map, "g_fnt_path"), 2048 * 12)
    tail_ = [struct.unpack_from("<III", pb, (k & 2047) * 12) for k in range(max(0, pn_ - int(os.environ.get('PATH_TAIL', '160'))), pn_)]
    print(" ".join("%x@%x:%x" % (va_, es_, ex_) for va_, es_, ex_ in tail_))
ic_ = g32("g_fnt_ics_n")
print("== recent ICALL_SAFE targets (%d)" % ic_)
if ic_:
    ib3 = r.read(r.base + symbol_rva(a.map, "g_fnt_ics"), 512 * 16)
    print(" ".join("%x(e%x,c%x,L%d)" % (struct.unpack_from("<I", ib3, ((k & 511) * 16))[0], struct.unpack_from("<I", ib3, ((k & 511) * 16) + 4)[0] & 0xFFFFF, struct.unpack_from("<I", ib3, ((k & 511) * 16) + 8)[0] & 0xFFFFFFF, struct.unpack_from("<I", ib3, ((k & 511) * 16) + 12)[0]) for k in range(max(0, ic_ - 500), ic_)))
i2_ = g32("g_fnt_ics2_n")
print("== L66411 icalls (the call in 148720): %d" % i2_)
if i2_:
    b4 = r.read(r.base + symbol_rva(a.map, "g_fnt_ics2"), 64 * 24)
    for k in range(max(0, i2_ - 24), i2_):
        w = struct.unpack_from("<6I", b4, (k & 63) * 24)
        print("  #%d target %x esp %x ecx(this) %x [this]=%x arg=%x" % (w[5], w[0], w[1], w[2], w[3], w[4]))
sys.exit(0)
raw = None
kinds = {1: "OVERLAP", 2: "FREE-UNKNOWN", 3: "FREE-MISMATCH"}
for i in range(min(n, 64)):
    k, ns, nsz, nra, nt, oseq, os_, osz, ora, ot, nat, seq = struct.unpack_from("<12I", raw, i * 48)
    print("%2d %-13s new blk %08x size %6x ra %06x tid %d | old seq %d blk %08x size %6x ra %06x tid %d | native idx %d, alloc seq %d" % (i, kinds.get(k, k), ns, nsz, nra, nt, oseq, os_, osz, ora, ot, nat, seq))
