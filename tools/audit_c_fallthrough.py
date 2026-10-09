"""Find generated C functions whose body can fall off the closing brace without returning.

A translated guest function must end every path in `return;` / a tail call / a goto. If the last
statement is anything else, the recompiler truncated the body (e.g. at a false function-boundary
seed): execution falls out of the C function with the guest stack unbalanced and the rest of the
original code never runs.  py -3 tools/audit_c_fallthrough.py [--json out]"""
import argparse, glob, json, re
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser(); ap.add_argument("--json"); a = ap.parse_args()
manual = (ROOT / "src/recomp_manual.c").read_text(errors="replace")
manual_names = set(re.findall(r"^void (sub_[0-9A-F]{8})\(void\)", manual, re.M))
func_re = re.compile(r"^void (sub_[0-9A-F]{8})\(void\)\n\{\n(.*?)^\}\n", re.M | re.S)
orig_re = re.compile(r"Original: 0x([0-9A-Fa-f]{8}) - 0x([0-9A-Fa-f]{8})")
bad = []; total = 0
for f in sorted(glob.glob(str(ROOT / "src/recomp/gen/recomp_0*.c")) + glob.glob(str(ROOT / "src/recomp/gen/recomp_interior_entries*.c")) +
                glob.glob(str(ROOT / "src/recomp/gen/recomp_gap_functions.c")) + [str(ROOT / "src/recomp/gen/recomp_missing_complete.c")]):
    t = Path(f).read_text(errors="replace")
    for m in func_re.finditer(t):
        total += 1
        name, body = m.group(1), m.group(2)
        lines = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith(("/*", "#", "*")) and l.strip() not in ("*/", "}")]
        if not lines: continue
        last = lines[-1]
        code = re.sub(r"/\*.*?\*/", "", last).strip()
        # An `if (...) { ...; return; }` is conditional: the not-taken path still falls off the end,
        # so only an unconditional top-level return / goto / __debugbreak terminates the function.
        if not code.startswith("if ") and (re.search(r"\breturn\b", code) or code.startswith("goto ")
                                           or code.startswith("__debugbreak")):
            continue
        # preceding comment block gives the byte range
        head = t[max(0, m.start() - 400):m.start()]
        o = orig_re.findall(head)
        rng = o[-1] if o else None
        bad.append({"fn": name, "last_stmt": code[:80], "range": rng, "file": Path(f).name, "manual_override": name in manual_names})
print("%d of %d generated functions end without return/goto" % (len(bad), total))
print("  with manual override in recomp_manual.c:", sum(b["manual_override"] for b in bad))
for b in bad[:30]: print(" ", b["fn"], b["range"], "|", b["last_stmt"], "(manual)" if b["manual_override"] else "")
if a.json: Path(a.json).write_text(json.dumps(bad, indent=1))
