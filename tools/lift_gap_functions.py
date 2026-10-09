"""Lift guest code that no generated function covers, and register it for indirect calls.

The disassembler missed ~460 stretches of real code (function-pointer targets in vtables / Lua C-function
tables with no direct callers, e.g. math.min/max at 0x213430).  An indirect call to such an address finds
no function and silently returns 0.  This tool finds every uncovered, non-padding stretch of .text,
splits it into functions by control flow, lifts them into src/recomp/gen/recomp_gap_functions.c and rebuilds
the dispatch table (recomp_dispatch.c) so ICALLs resolve them (it also adds the interior-entry functions).

  py -3 tools/lift_gap_functions.py [--apply]
"""
import argparse, glob, json, os, re, struct, sys, tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP

ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--apply", action="store_true")
ap.add_argument("--report", default="")
a = ap.parse_args()


def rd(f):
    with open(f, encoding="utf-8", errors="surrogateescape", newline="") as h:
        return h.read()


def wr(f, t):
    with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="") as h:
        h.write(t)


xbe_bytes = (ROOT / "game_files/default.xbe").read_bytes()
TEXT_LO, TEXT_HI = 0x11000, 0x225CA0


def off(va):
    return va - 0x11000 + 0x1000


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# coverage = every "Original: S - E" range present in the generated sources
cov = []
for f in glob.glob(str(ROOT / "src/recomp/gen/recomp_*.c")):
    if f.endswith("recomp_gap_functions.c"):
        continue            # our own output: regenerate from scratch each run
    for m in re.finditer(r"Original: 0x([0-9A-Fa-f]{8}) - 0x([0-9A-Fa-f]{8})", rd(f)):
        cov.append((int(m.group(1), 16), int(m.group(2), 16)))
cov.sort()
merged = []
for s, e in cov:
    if merged and s <= merged[-1][1]:
        merged[-1][1] = max(merged[-1][1], e)
    else:
        merged.append([s, e])
gaps = []
prev = TEXT_LO
for s, e in merged:
    if s > prev:
        gaps.append((prev, min(s, TEXT_HI)))
    prev = max(prev, e)
if prev < TEXT_HI:
    gaps.append((prev, TEXT_HI))
PAD = {0xCC, 0x90, 0x00}


def read_dword_va(va):
    return struct.unpack_from("<I", xbe_bytes, off(va))[0] if TEXT_LO <= va < 0x2A0000 else None


def walk(start, hard_end, limit=0x6000):
    seen = {}
    work = [start]
    hi = start
    lim = min(hard_end, start + limit)
    while work:
        pc = work.pop()
        while pc not in seen and start <= pc < lim:
            ins = next(md.disasm(xbe_bytes[off(pc):off(pc) + 16], pc), None)
            if ins is None:
                return None
            seen[pc] = ins
            hi = max(hi, pc + ins.size)
            m = ins.mnemonic
            if m in ("ret", "retf", "int3", "hlt", "ud2"):
                break
            if ins.group(CS_GRP_JUMP):
                op = ins.operands[0] if ins.operands else None
                if op is not None and op.type == 2:
                    if start <= op.imm < lim:
                        work.append(op.imm)
                elif op is not None and op.type == 3 and op.mem.index and op.mem.scale == 4 and op.mem.disp:
                    t = op.mem.disp
                    n = 0
                    while n < 512:
                        v = read_dword_va(t + 4 * n)
                        if v is None or not (start <= v < lim):
                            break
                        work.append(v)
                        n += 1
                if m == "jmp":
                    break
            pc += ins.size
    return seen, hi


cands = []
skipped = []
for ga, gb in gaps:
    pc = ga
    while pc < gb:
        while pc < gb and xbe_bytes[off(pc)] in PAD:
            pc += 1
        if pc >= gb:
            break
        w = walk(pc, gb)
        if w is None:
            skipped.append((pc, "decode failed"))
            while pc < gb and xbe_bytes[off(pc)] not in PAD:
                pc += 1
            continue
        seen, hi = w
        cands.append((pc, hi))
        pc = max(hi, pc + 1)
print("%d gaps -> %d candidate functions (%d skipped)" % (len(gaps), len(cands), len(skipped)))

os.chdir(ROOT / "xboxrecomp")
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import BatchTranslator
from tools.recomp.__main__ import find_data_files

xbe = str(ROOT / "game_files/default.xbe")
data = find_data_files(disasm_dir=None, func_id_dir=None, abi_dir=None,
                       overrides={"functions": None, "labels": None, "identified": None, "abi": None})
config.configure_from_xbe(xbe)
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
    json.dump(json.loads((ROOT / "seeds/verified_function_extents.json").read_text()), t)
    mpath = t.name
bt = BatchTranslator(xbe_path=xbe, func_json_path=data["functions"], labels_json_path=data.get("labels"),
                     identified_json_path=data.get("identified"), abi_json_path=data.get("abi"),
                     output_dir=tempfile.mkdtemp(), trace_functions=None, function_extents_path=mpath)
bt.translator.owned_function_starts.clear()
blocks = []
names = []
failed = []
for s, hi in cands:
    if s in bt.func_db:
        failed.append(("0x%08X" % s, "already in func_db"))
        continue
    bt.func_db[s] = {"start": "0x%08X" % s, "end": hi, "size": hi - s, "name": "sub_%08X" % s, "section": ".text",
                     "confidence": 0.4, "detection_method": "gap_function", "num_instructions": 1,
                     "has_prologue": False, "calls_to": [], "called_by": [], "_addr": s}
    bt.abi_db.setdefault(s, {"address": "0x%08X" % s, "calling_convention": "cdecl", "estimated_params": 0,
                             "return_hint": "int_or_void", "frame_type": "fpo_leaf", "stack_frame_size": 0,
                             "heuristic_confidence": 0.4, "heuristic_notes": "gap function"})
    bt.classification_db.setdefault(s, {"start": "0x%08X" % s, "end": "0x%08X" % hi, "size": hi - s,
                                        "name": "sub_%08X" % s, "section": ".text", "category": "unknown",
                                        "confidence": 0.0, "method": "none"})
    try:
        code = bt.translate_single(s)
    except Exception as e:
        del bt.func_db[s]
        failed.append(("0x%08X" % s, repr(e)[:80]))
        continue
    if not code:
        del bt.func_db[s]
        failed.append(("0x%08X" % s, "empty"))
        continue
    blocks.append(code)
    names.append(s)
print("lifted %d gap functions, %d failed" % (len(names), len(failed)))
for f in failed[:10]:
    print("  failed", f)
if a.report:
    Path(a.report).write_text(json.dumps({"lifted": ["0x%08X" % s for s in names], "failed": failed,
                                          "skipped": [("0x%08X" % p, w) for p, w in skipped]}, indent=1))

if a.apply and blocks:
    hdr = ("/* Code the disassembler never discovered (function-pointer targets with no direct callers), lifted by\n"
           " * tools/lift_gap_functions.py so indirect calls (Lua C-function tables, vtables) resolve. */\n"
           "#define RECOMP_GENERATED_CODE\n#include \"recomp_funcs.h\"\n#include <windows.h>\n#include <math.h>\n\n")
    wr(ROOT / "src/recomp/gen/recomp_gap_functions.c", hdr + "\n\n".join(b.rstrip() + "\n" for b in blocks))
    disp = ROOT / "src/recomp/gen/recomp_dispatch.c"
    t = rd(disp)
    ent = re.compile(r"    \{ 0x([0-9A-F]{8})u, \(recomp_func_t\)(\w+) \},\r?\n")
    existing = {int(m.group(1), 16): m.group(2) for m in ent.finditer(t)}
    extra = {s: "sub_%08X" % s for s in names}
    for f in glob.glob(str(ROOT / "src/recomp/gen/recomp_interior_entries*.c")):
        for m in re.finditer(r"^void (sub_([0-9A-F]{8}))\(void\)", rd(f), re.M):
            extra[int(m.group(2), 16)] = m.group(1)
    new = {va: n for va, n in extra.items() if va not in existing}
    allv = dict(existing)
    allv.update(new)
    nl = "\r\n" if "\r\n" in t else "\n"
    start = t.index("static const recomp_entry_t g_recomp_table[] = {")
    end = t.index("};", start)
    decl = "".join("extern void %s(void);%s" % (n, nl) for va, n in sorted(new.items()))
    body = "".join("    { 0x%08Xu, (recomp_func_t)%s },%s" % (va, n, nl) for va, n in sorted(allv.items()))
    t = t[:start] + decl + "static const recomp_entry_t g_recomp_table[] = {" + nl + body + t[end:]
    wr(disp, t)
    print("dispatch table: %d entries (+%d)" % (len(allv), len(new)))
