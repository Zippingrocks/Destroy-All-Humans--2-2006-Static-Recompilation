"""Lift "unresolved call target" stubs (interior entry points / shared tail blocks) as real functions.

The recompiler turns every branch target that lies outside the current function's extent into a call of
sub_<target>().  When <target> is in the middle of another function (shared epilogs, tail-merged blocks,
switch arms) no function exists for it, and the generated stub just pops a return address -- silently
skipping the real code (restores of saved registers, `ret N`, ...).  This tool lifts those targets as
functions of their own (end = furthest reachable byte) into src/recomp/gen/recomp_interior_entries.c and
removes the replaced stubs.

  py -3 tools/lift_interior_entries.py [--only 0x1C5434,...] [--apply]"""
import argparse, bisect, json, os, re, struct, sys, tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP
ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser(); ap.add_argument("--only", default=""); ap.add_argument("--apply", action="store_true")
ap.add_argument("--report", default=""); ap.add_argument("--out", default="recomp_interior_entries.c"); a = ap.parse_args()
def rd(f):
    with open(f, encoding="utf-8", errors="surrogateescape", newline="") as h: return h.read()
def wr(f, t):
    with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="") as h: h.write(t)
xbe_bytes = (ROOT / "game_files/default.xbe").read_bytes()
TEXT_LO, TEXT_HI = 0x11000, 0x225CA0
def off(va): return va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
stub_files = [ROOT / "src/recomp/gen/recomp_stubs_unresolved.c", ROOT / "src/recomp/gen/recomp_extent_stubs.c"]
stub_re = re.compile(r"^void sub_([0-9A-F]{8})\(void\) \{[^\n]*\}\r?\n", re.M)
stubs = []
for f in stub_files:
    if f.exists(): stubs += [int(m.group(1), 16) for m in stub_re.finditer(rd(f))]
stubs = sorted(set(stubs))
if a.only: stubs = [s for s in stubs if s in {int(x, 0) for x in a.only.split(",")}]
funcs = json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())
fstarts = sorted(int(f["start"], 16) for f in funcs)
fstart_set = set(fstarts)
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
sample_abi = next(iter(bt.abi_db.values())) if getattr(bt, "abi_db", None) else None
for s in stubs:
    if s in bt.func_db: report["failed"].append(("0x%08X" % s, "already in func_db")); continue
    w = walk(s)
    if w is None: report["failed"].append(("0x%08X" % s, "decode failed")); continue
    seen, hi, ok = w
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
print({k: len(v) for k, v in report.items()})
for f in report["failed"][:15]: print("  failed", f)
if a.report: Path(a.report).write_text(json.dumps(report, indent=1))
if a.apply and out_blocks:
    hdr = ("/* Interior entry points lifted as functions by tools/lift_interior_entries.py.\n"
           " * Each is a branch target inside another function (shared epilog / tail-merged block) that the\n"
           " * recompiler used to turn into a no-op stub. */\n#define RECOMP_GENERATED_CODE\n#include \"recomp_funcs.h\"\n#include <windows.h>\n#include <math.h>\n\n")
    protos = "/* prototypes */\n" + "".join("void sub_%08X(void);\n" % int(x[0], 16) for x in report["lifted"]) + "\n"
    wr(ROOT / "src/recomp/gen" / a.out, hdr + protos + "\n\n".join(b.rstrip() + "\n" for b in out_blocks))
    done = {int(x[0], 16) for x in report["lifted"]}
    for f in stub_files:
        if not f.exists(): continue
        t = rd(f); n0 = len(t)
        t = stub_re.sub(lambda m: "" if int(m.group(1), 16) in done else m.group(0), t)
        wr(f, t)
    print("applied: %d lifted, stubs removed" % len(done))
