"""Lift explicit VAs -- indirect-jump / jump-table targets that sit inside another generated function -- as interior-entry functions
and register them in recomp_dispatch.c, so RECOMP_ITAIL / RECOMP_ICALL find them.

  py -3 tools/lift_itail_targets.py --vas 0x1CCFAD,0x1EF1A3 [--apply] [--out recomp_interior_entries_itail.c]

A generated function whose `jmp [table + idx*4]` lands in code that belongs to another generated function (shared tails, split switch
dispatchers) used to return without running the retail code.  Each such target is lifted as a function of its own (end = furthest
reachable byte) that inherits the caller's frame through g_seh_ebp, exactly like the entries tools/lift_interior_entries.py makes.
Derived from tools/lift_interior_entries.py."""
import argparse, json, os, re, struct, sys, tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP
ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser(); ap.add_argument("--vas", required=True); ap.add_argument("--apply", action="store_true")
ap.add_argument("--report", default=""); ap.add_argument("--out", default="recomp_interior_entries_itail.c"); a = ap.parse_args()
def rd(f):
    with open(f, encoding="utf-8", errors="surrogateescape", newline="") as h: return h.read()
def wr(f, t):
    with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="") as h: h.write(t)
xbe_bytes = (ROOT / "game_files/default.xbe").read_bytes()
TEXT_LO, TEXT_HI = 0x11000, 0x225CA0
def off(va): return va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
targets = sorted({int(x, 0) for x in a.vas.split(",") if x.strip()})
funcs = json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())
fstart_set = {int(f["start"], 16) for f in funcs}
def read_dword_va(va):
    return struct.unpack_from("<I", xbe_bytes, off(va))[0] if TEXT_LO <= va < 0x2A0000 else None
def walk(start, limit=0x3000):
    seen = {}; work = [start]; hi = start; ok_ret = False
    while work:
        pc = work.pop()
        while pc not in seen and start <= pc < start + limit and TEXT_LO <= pc < TEXT_HI:
            ins = next(md.disasm(xbe_bytes[off(pc):off(pc) + 16], pc), None)
            if ins is None: return None
            seen[pc] = ins; hi = max(hi, pc + ins.size); m = ins.mnemonic
            if m in ("ret", "retf"): ok_ret = True; break
            if m in ("int3", "hlt", "ud2"): break
            if ins.group(CS_GRP_JUMP):
                op = ins.operands[0] if ins.operands else None
                if op is not None and op.type == 2:
                    if start <= op.imm < start + limit and (op.imm == start or op.imm not in fstart_set): work.append(op.imm)
                elif op is not None and op.type == 3 and op.mem.index and op.mem.scale == 4 and op.mem.disp:
                    t = op.mem.disp; n = 0
                    while n < 512:
                        v = read_dword_va(t + 4 * n)
                        if v is None or not (start <= v < start + limit): break
                        if v == start or v not in fstart_set: work.append(v)
                        n += 1
                if m == "jmp": break
            pc += ins.size
    return seen, hi, ok_ret
os.chdir(ROOT / "xboxrecomp"); sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import BatchTranslator
from tools.recomp.__main__ import find_data_files
xbe = str(ROOT / "game_files/default.xbe")
data = find_data_files(disasm_dir=None, func_id_dir=None, abi_dir=None, overrides={"functions": None, "labels": None, "identified": None, "abi": None})
config.configure_from_xbe(xbe)
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
    json.dump(json.loads((ROOT / "seeds/verified_function_extents.json").read_text()), t); mpath = t.name
bt = BatchTranslator(xbe_path=xbe, func_json_path=data["functions"], labels_json_path=data.get("labels"),
                     identified_json_path=data.get("identified"), abi_json_path=data.get("abi"),
                     output_dir=tempfile.mkdtemp(), trace_functions=None, function_extents_path=mpath)
bt.translator.owned_function_starts.clear()
out_blocks = []; report = {"lifted": [], "failed": []}
import glob as _glob
defined = set()
for _f in _glob.glob(str(ROOT / "src/recomp/gen/*.c")) + [str(ROOT / "src/recomp_manual.c")]:
    if _f.endswith("recomp_interior_entries_itail.c"): continue
    defined |= {int(m.group(1), 16) for m in re.finditer(r"^void sub_([0-9A-F]{8})\(void\)[ \t]*(?:\{|\r?\n\{)", rd(_f), re.M)}
queue = list(targets); queued = set(queue)
while queue:
    s = queue.pop(0)
    w = walk(s)
    if w is None: report["failed"].append(("0x%08X" % s, "decode failed")); continue
    seen, hi, ok = w
    # a record may already exist from functions.json (an old split piece that was dropped as "owned"): replace it with the
    # control-flow extent so the lifted body runs all the way to its return
    rec = {"start": "0x%08X" % s, "end": hi, "size": hi - s, "name": "sub_%08X" % s, "section": ".text",
           "confidence": 0.5, "detection_method": "interior_entry", "num_instructions": len(seen),
           "has_prologue": False, "calls_to": [], "called_by": [], "_addr": s}
    bt.func_db[s] = rec
    bt.abi_db.setdefault(s, {"address": "0x%08X" % s, "calling_convention": "cdecl", "estimated_params": 0,
                             "return_hint": "int_or_void", "frame_type": "fpo_leaf", "stack_frame_size": 0,
                             "heuristic_confidence": 0.5, "heuristic_notes": "interior entry"})
    bt.classification_db.setdefault(s, {"start": "0x%08X" % s, "end": "0x%08X" % hi, "size": hi - s, "name": "sub_%08X" % s,
                                        "section": ".text", "category": "unknown", "confidence": 0.0, "method": "none"})
    try:
        code = bt.translate_single(s)
    except Exception as e:
        del bt.func_db[s]; report["failed"].append(("0x%08X" % s, "lift error %r" % e)); continue
    if not code: del bt.func_db[s]; report["failed"].append(("0x%08X" % s, "empty")); continue
    out_blocks.append(code); report["lifted"].append(("0x%08X" % s, hi - s, ok))
    for m in re.finditer(r"sub_([0-9A-F]{8})\(\);", code):
        ref = int(m.group(1), 16)
        if TEXT_LO <= ref < TEXT_HI and ref not in defined and ref not in queued:
            queued.add(ref); queue.append(ref)
print({k: len(v) for k, v in report.items()})
for f in report["failed"][:20]: print("  failed", f)
if a.report: Path(a.report).write_text(json.dumps(report, indent=1))
if a.apply and out_blocks:
    hdr = ("/* Jump-table / indirect-jump targets that live inside another generated function, lifted as functions of their own by\n"
           " * tools/lift_itail_targets.py so RECOMP_ITAIL resolves them. */\n#define RECOMP_GENERATED_CODE\n#include \"recomp_funcs.h\"\n"
           "#include <windows.h>\n#include <math.h>\n\n")
    protos = "/* prototypes */\n" + "".join("void sub_%08X(void);\n" % int(x[0], 16) for x in report["lifted"]) + "\n"
    wr(ROOT / "src/recomp/gen" / a.out, hdr + protos + "\n\n".join(b.rstrip() + "\n" for b in out_blocks))
    # a one-line unresolved-call stub for the same address would win the link (first definition) or be ignored: remove it
    stub_re = re.compile(r"^void sub_([0-9A-F]{8})\(void\) \{[^\n]*\}\r?\n", re.M)
    done = {int(x[0], 16) for x in report["lifted"]}
    for sf in (ROOT / "src/recomp/gen/recomp_stubs_unresolved.c", ROOT / "src/recomp/gen/recomp_extent_stubs.c"):
        if not sf.exists(): continue
        st = rd(sf); n0 = len(st)
        st = stub_re.sub(lambda m: "" if int(m.group(1), 16) in done else m.group(0), st)
        if len(st) != n0: wr(sf, st); print("removed %d bytes of stubs from %s" % (n0 - len(st), sf.name))
    disp = ROOT / "src/recomp/gen/recomp_dispatch.c"
    t = rd(disp)
    ent = re.compile(r"    \{ 0x([0-9A-F]{8})u, \(recomp_func_t\)(\w+) \},\r?\n")
    existing = {int(m.group(1), 16): m.group(2) for m in ent.finditer(t)}
    new = {int(x[0], 16): "sub_%08X" % int(x[0], 16) for x in report["lifted"] if int(x[0], 16) not in existing}
    allv = dict(existing); allv.update(new)
    nl = "\r\n" if "\r\n" in t else "\n"
    s0 = t.index("static const recomp_entry_t g_recomp_table[] = {"); e0 = t.index("};", s0)
    decl = "".join("extern void %s(void);%s" % (n, nl) for va, n in sorted(new.items()))
    body = "".join("    { 0x%08Xu, (recomp_func_t)%s },%s" % (va, n, nl) for va, n in sorted(allv.items()))
    t = t[:s0] + decl + "static const recomp_entry_t g_recomp_table[] = {" + nl + body + t[e0:]
    wr(disp, t)
    print("dispatch table: %d entries (+%d)" % (len(allv), len(new)))
