"""Make the fused comiss/ucomiss + jcc branches in src/recomp/gen honour unordered (NaN) operands.

COMISS/UCOMISS set CF=ZF=PF=1 for unordered operands, so jbe/jb/je are TAKEN and jne is NOT taken when either operand is NaN.  Older
lifter output translated them as plain C relational tests (`if ((a <= b)) goto ...`), which are false for NaN -- the wrong branch for
every NaN/uninitialised-float input (the current lifter, xboxrecomp/tools/recomp/lifter.py, already emits the correct form).  This
rewrites the old shape in place without re-lifting, so hand patches in those functions survive.  Idempotent.

  py -3 tools/patch_comiss_nan.py [--check]"""
import glob, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
check = "--check" in sys.argv
OP = r"(?:xmm\d\.[fd]\[0\]|MEM[FD]\([^()]*\))"
pat = re.compile(r"if \(\((" + OP + r") (<=|<|==|!=) (" + OP + r")\)\) goto (loc_[0-9A-F]+); (/\* j[a-z]+: [^*]*\*/)")
total = {"<=": 0, "<": 0, "==": 0, "!=": 0}
def rewrite(m):
    a, op, b, label, tail = m.groups()
    unordered = "(isnan(%s) || isnan(%s))" % (a, b)
    total[op] += 1
    if op == "!=":
        return "if (((%s != %s) && !%s)) goto %s; %s" % (a, b, unordered, label, tail)
    return "if (((%s %s %s) || %s)) goto %s; %s" % (a, op, b, unordered, label, tail)
files = sorted(glob.glob(str(ROOT / "src/recomp/gen/*.c"))) + [str(ROOT / "src/recomp_manual.c")]
changed = 0
for f in files:
    t = Path(f).read_bytes().decode("utf-8", "surrogateescape")
    # only lines that follow a comiss/ucomiss comment within a few lines are rewritten
    out = []; lines = t.split("\n"); recent = -100; n_in_file = 0
    for i, l in enumerate(lines):
        if re.search(r"/\* u?comis[sd] .*sets EFLAGS \*/", l): recent = i
        if i - recent <= 6 and "isnan(" not in l:
            nl = pat.sub(rewrite, l)
            if nl != l: n_in_file += 1; l = nl
        out.append(l)
    if n_in_file:
        changed += n_in_file
        if not check: Path(f).write_bytes("\n".join(out).encode("utf-8", "surrogateescape"))
print("rewrote %d branches %s" % (changed, total), "(check only)" if check else "")
