"""Re-lift guest functions whose checked-in C still carries comment-only MMX / rdtsc / movntps instructions (older lifter), and
splice the new text in when the ONLY differences are those instructions (so hand patches and other drift are never overwritten).

  py -3 tools/relift_mmx.py report [--json OUT]   # classify every candidate (dry run)
  py -3 tools/relift_mmx.py apply [--force sub_X,sub_Y]   # splice the clean ones (and the forced ones)

Candidates are the functions whose gen text holds a comment-only instruction that Lifter._lift_mmx now handles."""
import difflib, json, os, re, struct, sys, tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP
ROOT = Path(__file__).resolve().parent.parent
mode = sys.argv[1]
force = set(x.strip() for x in sys.argv[sys.argv.index("--force") + 1].split(",")) if "--force" in sys.argv else set()
outjson = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else ""
def rd(f):
    with open(f, encoding="utf-8", errors="surrogateescape", newline="") as h: return h.read()
def wr(f, t):
    with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="") as h: h.write(t)
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp.lifter import MMX_MNEMONICS
MM = set(MMX_MNEMONICS) | {"movq", "movntq", "emms", "rcl", "rcr"}
fn_re = re.compile(r'^void (sub_[0-9A-F]{8})\(void\)\s*$', re.M)
cands = {}
for f in sorted((ROOT / "src/recomp/gen").glob("recomp_*.c")):
    t = rd(f); ms = list(fn_re.finditer(t))
    for i, m in enumerate(ms):
        body = t[m.end(): ms[i + 1].start() if i + 1 < len(ms) else len(t)]
        hit = set()
        for mm in re.finditer(r'/\* (?:TODO: |SSE: )([a-z0-9]+) ', body):
            if mm.group(1) in MM: hit.add(mm.group(1))
        for mm in re.finditer(r'/\* ([a-z0-9]+) [^*]*\(MMX/SIMD integer\) \*/', body): hit.add(mm.group(1))
        if hit: cands[m.group(1)] = (f, sorted(hit))
print("candidates:", len(cands))

# ---- lifting machinery (same as tools/relift_functions.py) ----
xbe_bytes = (ROOT / "game_files/default.xbe").read_bytes()
TEXT_LO, TEXT_HI = 0x11000, 0x225CA0
def off(va): return va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
funcs_json = json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())
fstart_set = {int(f["start"], 16) for f in funcs_json}
def read_dword_va(va): return struct.unpack_from("<I", xbe_bytes, off(va))[0] if TEXT_LO <= va < 0x2A0000 else None
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
os.chdir(ROOT / "xboxrecomp")
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
    except Exception as e:
        print("lift failed", name, e); return None
PUB_INLINE = re.compile(r"g_seh_ebp = g_ebp = ebp; |g_seh_ebp = ebp; |ebp = g_seh_ebp; g_ebp = ebp;|g_ebp = ebp; ")
PUB_ONLY = ("/* frame stays current across calls */", "/* publish frame for frameless callees */", "/* publish frame to SEH helper */",
            "/* read back frame from SEH helper */", "ebp = g_seh_ebp;", "g_seh_ebp = g_ebp = ebp;", "g_seh_ebp = ebp;", "g_ebp = ebp;")
def norm_lines(t):
    out = []
    for l in t.replace("\r\n", "\n").split("\n"):
        l = PUB_INLINE.sub("", l.rstrip()).rstrip()
        if l.strip() in PUB_ONLY: continue
        out.append(l)
    return out
EXPECTED_OLD = re.compile(r'^\s*/\* (?:TODO: |SSE: )?([a-z0-9]+) .*\*/\s*$')
def classify(old, new):
    a, b = norm_lines(old), norm_lines(new)
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    bad = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal": continue
        for l in a[i1:i2]:
            m = EXPECTED_OLD.match(l)
            if not (m and (m.group(1) in MM or "(MMX/SIMD integer)" in l)): bad.append("- " + l)
        for l in b[j1:j2]:
            if not ("MMX_" in l or "XMM_CVT" in l or "recomp_rdtsc" in l or "movntps" in l or "movntq" in l or "SMEM64" in l
                    or "XMM_STORE" in l or "_cf" in l or "_rv" in l or l.strip().startswith("/*") or l.strip() == "" or "mm" in l or "rdtsc" in l): bad.append("+ " + l)
    return bad
report = {}
gen = sorted((ROOT / "src/recomp/gen").glob("recomp_*.c")); text = {f: rd(f) for f in gen}
nsp = 0
for n in sorted(cands):
    new = lift(n)
    f, hit = cands[n]
    pat = re.compile(r"/\*\*\r?\n \* %s\r?\n.*?\r?\n\}\r?\n" % n, re.S)
    m = pat.search(text[f])
    if new is None or not m:
        report[n] = {"status": "nolift" if new is None else "nomatch", "ops": hit}; continue
    bad = classify(m.group(0), new)
    report[n] = {"status": "clean" if not bad else "differs", "ops": hit, "bad": bad[:12], "nbad": len(bad)}
    if mode == "apply" and (not bad or n in force):
        repl = new.rstrip("\n") + "\n"
        if "\r\n" in text[f]: repl = repl.replace("\n", "\r\n")
        text[f] = text[f][:m.start()] + repl + text[f][m.end():]; nsp += 1
from collections import Counter
print(Counter(r["status"] for r in report.values()))
for n, r in report.items():
    if r["status"] != "clean": print(n, r["status"], r["ops"], r.get("nbad"), (r.get("bad") or [])[:4])
if mode == "apply":
    for f, t in text.items():
        if t != rd(f): wr(f, t)
    print("spliced", nsp)
if outjson: Path(outjson).write_text(json.dumps(report, indent=1))
