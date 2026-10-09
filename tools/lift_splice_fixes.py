"""Lift selected guest functions with corrected extents and splice them into src/recomp/gen.

  py -3 tools/lift_splice_fixes.py PLAN.json [--only sub_000C11D0,...] [--check] [--apply]

For each planned function it lifts (a) a baseline with the project's current verified extents and
(b) the fixed version with the planned extent added.  A function is spliced only if the baseline equals
the text already in src/recomp/gen (so no hand patch or tool-version drift is overwritten); otherwise it
is reported for manual merge.  New extents are appended to seeds/verified_function_extents.json
(only with --apply)."""
import argparse, json, os, re, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
def rd(f):
    with open(f, encoding="utf-8", errors="surrogateescape", newline="") as h: return h.read()
def wr(f, t):
    with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="") as h: h.write(t)
ap = argparse.ArgumentParser(); ap.add_argument("plan"); ap.add_argument("--only", default="")
ap.add_argument("--apply", action="store_true"); ap.add_argument("--check", action="store_true")
ap.add_argument("--report", default=""); ap.add_argument("--diffdir", default=""); ap.add_argument("--force", default=""); a = ap.parse_args()
os.chdir(ROOT / "xboxrecomp"); sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import BatchTranslator
from tools.recomp.__main__ import find_data_files
xbe = str(ROOT / "game_files/default.xbe")
plan = json.loads(Path(a.plan).read_text())["plan"]
if a.only:
    want = {x.strip().upper().replace("SUB_", "") for x in a.only.split(",")}
    plan = [p for p in plan if p["start"][2:].upper() in want]
base_manifest = json.loads((ROOT / "seeds/verified_function_extents.json").read_text())
data = find_data_files(disasm_dir=None, func_id_dir=None, abi_dir=None, overrides={"functions": None, "labels": None, "identified": None, "abi": None})
config.configure_from_xbe(xbe)
def make(manifest):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
        json.dump(manifest, t); path = t.name
    bt = BatchTranslator(xbe_path=xbe, func_json_path=data["functions"], labels_json_path=data.get("labels"),
                         identified_json_path=data.get("identified"), abi_json_path=data.get("abi"),
                         output_dir=tempfile.mkdtemp(), trace_functions=None, function_extents_path=path)
    bt.translator.owned_function_starts.clear()    # == --include-owned used for the checked-in gen
    return bt
known = {int(f["start"], 16) for f in json.loads(Path(data["functions"]).read_text())}
unknown = [p["start"] for p in plan if int(p["start"], 16) not in known]
plan = [p for p in plan if int(p["start"], 16) in known]
if unknown: print("skipping %d starts absent from functions.json: %s" % (len(unknown), unknown[:8]))
new_manifest = json.loads(json.dumps(base_manifest))
have = {e["start"].upper() for e in new_manifest["functions"]}
for p in plan:
    if p["start"].upper() not in have:
        new_manifest["functions"].append({"start": p["start"], "end": p["end"], "num_instructions": p["num_instructions"],
            "sha256": p["sha256"], "reason": "Generated body fell off its end: control flow reaches 0x%s but the detected extent stopped at 0x%s (false interior boundary)." % (p["end"][2:], (p["old_end"] or "?")),
            "verification": "tools/audit_c_fallthrough.py"})
base_bt, new_bt = make(base_manifest), make(new_manifest)
gen_files = sorted((ROOT / "src/recomp/gen").glob("recomp_0*.c")) + [ROOT / "src/recomp/gen/recomp_missing_complete.c"]
gen_text = {f: rd(f) for f in gen_files}
def block_re(name):
    return re.compile(r"/\*\*\r?\n \* %s\r?\n.*?\r?\n\}\r?\n" % name, re.S)
_EBP_PUB = re.compile(r"g_seh_ebp = g_ebp = ebp;|g_seh_ebp = ebp;|(?<!= )g_ebp = ebp;")
_EBP_NOISE = ("/* frame stays current across calls */", "/* publish frame for frameless callees */")
def norm(t):
    # ignore the ebp-publishing convention (tools/patch_ebp_publish.py re-applies it after a splice)
    out = []
    for l in t.replace("\r\n", "\n").split("\n"):
        l = _EBP_PUB.sub("", l).rstrip()
        if l.strip() in _EBP_NOISE or not l.strip(): continue
        out.append(re.sub(r"\s+", " ", l.strip()))
    return "\n".join(out)
stats = {"spliced": [], "baseline_differs": [], "not_found": [], "lift_failed": []}
for p in plan:
    s = int(p["start"], 16); name = "sub_%08X" % s
    old_block = None; owner = None
    for f, t in gen_text.items():
        m = block_re(name).search(t)
        if m: old_block, owner = m, f; break
    if old_block is None: stats["not_found"].append(name); continue
    try:
        base = base_bt.translate_single(s); fixed = new_bt.translate_single(s)
    except Exception as e:
        stats["lift_failed"].append((name, repr(e))); continue
    if not base or not fixed: stats["lift_failed"].append((name, "empty lift")); continue
    if norm(base) != norm(old_block.group(0)):
        if name not in {x.strip() for x in a.force.split(",") if x.strip()}:
            stats["baseline_differs"].append(name)
            if a.diffdir:
                import difflib
                Path(a.diffdir).mkdir(parents=True, exist_ok=True)
                Path(a.diffdir, name + ".diff").write_text(chr(10).join(difflib.unified_diff(norm(old_block.group(0)).split(chr(10)), norm(fixed).split(chr(10)), "checked-in", "fixed-lift", lineterm="")))
            continue
    crlf = "\r\n" in gen_text[owner]
    repl = fixed.rstrip("\n") + "\n"
    if crlf: repl = repl.replace("\n", "\r\n")
    gen_text[owner] = gen_text[owner][:old_block.start()] + repl + gen_text[owner][old_block.end():]
    stats["spliced"].append(name)
print({k: len(v) for k, v in stats.items()})
if stats["baseline_differs"]: print("baseline differs (not spliced):", stats["baseline_differs"][:30])
if stats["lift_failed"]: print("lift failed:", stats["lift_failed"][:10])
if a.report: Path(a.report).write_text(json.dumps(stats, indent=1))
if a.apply and stats["spliced"]:
    for f, t in gen_text.items():
        if t != rd(f):
            wr(f, t)
    done = {"0x%08X" % int(n[4:], 16) for n in stats["spliced"]}
    mf = ROOT / "seeds/verified_function_extents.json"
    m = json.loads(mf.read_text())
    for e in new_manifest["functions"]:
        if e["start"].upper() in {d.upper() for d in done} and e["start"].upper() not in {x["start"].upper() for x in m["functions"]}:
            m["functions"].append(e)
    mf.write_text(json.dumps(m, indent=2) + "\n")
    print("applied: %d functions spliced, manifest now has %d entries" % (len(stats["spliced"]), len(m["functions"])))
