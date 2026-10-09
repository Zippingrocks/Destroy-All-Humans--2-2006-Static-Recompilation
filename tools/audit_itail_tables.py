"""Audit indirect tail jumps / switch fallbacks in src/recomp/gen for jump-table targets that are not dispatchable.

A lifted `jmp [reg*4 + TABLE]` becomes `RECOMP_ITAIL(MEM32(reg*4 + TABLE))` (or a switch whose default falls back to ITAIL). When the table
targets are labels inside a sibling generated function (a false split of one retail function) the dispatch lookup fails and the C function
returns early without running the retail epilogue -- clobbering callee-saved registers.  This lists every site whose table holds a code
address that is not an entry in recomp_dispatch.c.

  py -3 tools/audit_itail_tables.py [--json OUT]"""
import glob, json, re, struct, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
xbe = (ROOT / "game_files/default.xbe").read_bytes()
TEXT_LO, TEXT_HI = 0x11000, 0x225CA0
def dw(va): return struct.unpack_from("<I", xbe, va - 0x11000 + 0x1000)[0]
disp = set(int(x, 16) for x in re.findall(r"\{ 0x([0-9A-F]{8})u, \(recomp_func_t\)", (ROOT / "src/recomp/gen/recomp_dispatch.c").read_text(errors="replace")))
fn_re = re.compile(r"^(?:static )?void (sub_[0-9A-F]{8})\(void\)\s*$", re.M)
site_re = re.compile(r"RECOMP_ITAIL\(MEM32\(\w+ \* 4 \+ 0x([0-9A-F]+)\)\)|MEM32\(\w+ \* 4 \+ 0x([0-9A-F]+)\); /\* switch: (\d+) entries")
report = {}
for f in sorted(glob.glob(str(ROOT / "src/recomp/gen/recomp_*.c"))):
    t = Path(f).read_bytes().decode("utf-8", "surrogateescape")
    ms = list(fn_re.finditer(t))
    for i, m in enumerate(ms):
        body = t[m.end(): ms[i + 1].start() if i + 1 < len(ms) else len(t)]
        labels = set(int(x, 16) for x in re.findall(r"^loc_([0-9A-F]{8}): ;", body, re.M))
        for sm in site_re.finditer(body):
            tab = int(sm.group(1) or sm.group(2), 16)
            n = int(sm.group(3)) if sm.group(3) else None
            tg = []
            k = 0
            while True:
                if n is not None and k >= n: break
                if n is None and k >= 64: break
                if not (TEXT_LO <= tab + 4 * k < TEXT_HI): break
                v = dw(tab + 4 * k)
                if not (TEXT_LO <= v < TEXT_HI): break
                if n is None and abs(v - tab) > 0x2000: break
                tg.append(v); k += 1
            bad = [v for v in tg if v not in labels and v not in disp]
            if bad:
                report.setdefault(m.group(1), []).append({"table": hex(tab), "targets": len(tg), "bad": [hex(v) for v in bad][:12]})
print("functions with non-dispatchable jump-table targets:", len(report))
for fn, sites in report.items():
    for s in sites[:3]: print(fn, s)
if "--json" in sys.argv: Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps(report, indent=1))
