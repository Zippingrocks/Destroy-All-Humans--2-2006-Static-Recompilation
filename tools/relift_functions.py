"""Re-lift named guest functions and splice them into src/recomp/gen when safe.

  py -3 tools/relift_functions.py baseline NAMES.json OUT.json    # lift with the CURRENT lifter, remember texts
  py -3 tools/relift_functions.py apply NAMES.json BASELINE.json [FORCE.json]  # lift again (after a lifter change); replace a
                                                                   # function only if its checked-in text equals the baseline
Functions not in functions.json (interior entries / gap functions) get a synthetic record from a control-flow walk,
exactly as tools/lift_interior_entries.py does."""
import json, os, re, struct, sys, tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP
ROOT = Path(__file__).resolve().parent.parent
mode, names_path, aux = sys.argv[1], sys.argv[2], sys.argv[3]
force = set(json.loads(Path(sys.argv[4]).read_text())) if len(sys.argv) > 4 else set()
def rd(f):
    with open(f, encoding="utf-8", errors="surrogateescape", newline="") as h: return h.read()
def wr(f, t):
    with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="") as h: h.write(t)
names = json.loads(Path(names_path).read_text())
xbe_bytes = (ROOT / "game_files/default.xbe").read_bytes()
TEXT_LO, TEXT_HI = 0x11000, 0x225CA0
def off(va): return va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
funcs_json = json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())
fstart_set = {int(f["start"], 16) for f in funcs_json}
def read_dword_va(va):
    return struct.unpack_from("<I", xbe_bytes, off(va))[0] if TEXT_LO <= va < 0x2A0000 else None
def walk(start, limit=0x6000):
    seen = {}; work = [start]; hi = start; lim = start + limit
    while work:
        pc = work.pop()
        while pc not in seen and start <= pc < lim and TEXT_LO <= pc < TEXT_HI:
            ins = next(md.disasm(xbe_bytes[off(pc):off(pc) + 16], pc), None)
            if ins is None: return None
            seen[pc] = ins; hi = max(hi, pc + ins.size); m = ins.mnemonic
            if m in ("ret", "retf", "int3", "hlt", "ud2"): break
            if ins.group(CS_GRP_JUMP):
                op = ins.operands[0] if ins.operands else None
                if op is not None and op.type == 2:
                    if start <= op.imm < lim and (op.imm == start or op.imm not in fstart_set): work.append(op.imm)
                elif op is not None and op.type == 3 and op.mem.index and op.mem.scale == 4 and op.mem.disp:
                    t = op.mem.disp; n = 0
                    while n < 512:
                        v = read_dword_va(t + 4 * n)
                        if v is None or not (start <= v < lim): break
                        if v == start or v not in fstart_set: work.append(v)
                        n += 1
                if m == "jmp": break
            pc += ins.size
    return seen, hi
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
def lift(name):
    s = int(name[4:], 16)
    if s not in bt.func_db:
        w = walk(s)
        if w is None: return None
        hi = w[1]
        bt.func_db[s] = {"start": "0x%08X" % s, "end": hi, "size": hi - s, "name": name, "section": ".text", "confidence": 0.4,
                         "detection_method": "relift", "num_instructions": 1, "has_prologue": False, "calls_to": [], "called_by": [], "_addr": s}
        bt.abi_db.setdefault(s, {"address": "0x%08X" % s, "calling_convention": "cdecl", "estimated_params": 0, "return_hint": "int_or_void",
                                 "frame_type": "fpo_leaf", "stack_frame_size": 0, "heuristic_confidence": 0.4, "heuristic_notes": "relift"})
        bt.classification_db.setdefault(s, {"start": "0x%08X" % s, "end": "0x%08X" % hi, "size": hi - s, "name": name, "section": ".text",
                                            "category": "unknown", "confidence": 0.0, "method": "none"})
    try: return bt.translate_single(s)
    except Exception as e: return None
def norm(t): return "\n".join(l.rstrip() for l in t.replace("\r\n", "\n").split("\n")).strip()
if mode == "baseline":
    out = {n: lift(n) for n in names}
    Path(aux).write_text(json.dumps(out)); print("baseline lifted %d (%d failed)" % (sum(v is not None for v in out.values()), sum(v is None for v in out.values())))
else:
    base = json.loads(Path(aux).read_text())
    gen = sorted((ROOT / "src/recomp/gen").glob("recomp_*.c"))
    text = {f: rd(f) for f in gen}
    stats = {"spliced": 0, "baseline_differs": [], "missing": [], "failed": []}
    for n in names:
        fixed = lift(n)
        if fixed is None or base.get(n) is None and n not in force: stats["failed"].append(n); continue
        pat = re.compile(r"/\*\*\r?\n \* %s\r?\n.*?\r?\n\}\r?\n" % n, re.S)
        done = False
        for f, t in text.items():
            m = pat.search(t)
            if not m: continue
            if n not in force and norm(m.group(0)) != norm(base[n]): stats["baseline_differs"].append(n); done = True; break
            repl = fixed.rstrip("\n") + "\n"
            if "\r\n" in t: repl = repl.replace("\n", "\r\n")
            text[f] = t[:m.start()] + repl + t[m.end():]; stats["spliced"] += 1; done = True; break
        if not done: stats["missing"].append(n)
    for f, t in text.items():
        if t != rd(f): wr(f, t)
    print({k: (v if isinstance(v, int) else len(v)) for k, v in stats.items()})
    for k in ("baseline_differs", "missing", "failed"):
        if stats[k]: print(k, stats[k][:20])
