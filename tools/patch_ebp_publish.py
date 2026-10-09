"""Idempotently apply the frameless-callee ebp publishing convention to src/recomp/gen/*.c.

A frameless / fpo_leaf guest helper inherits the *hardware* ebp of its caller.  The runtime models that with
two globals (g_ebp for translator-frameless callees, g_seh_ebp for fpo_leaf callees), so every call or tail
transfer made by a function that has an ebp local must publish both.  Applied after any splice/regeneration:

  py -3 tools/patch_ebp_publish.py [--check]"""
import glob, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
check = "--check" in sys.argv
tail_re = re.compile(r'g_seh_ebp = ebp; (?=sub_[0-9A-F]{8}\(\); return;|RECOMP_ITAIL)')
call_re = re.compile(r'^(\s*)((?:PUSH32\(esp, 0x[0-9A-F]+u\); (?:sub_[0-9A-F]{8}\(\);|RECOMP_ICALL\w*\()|\{ uint32_t _icall_target = ))')
seh_a, seh_b = "g_seh_ebp = ebp; /* publish frame to SEH helper */", "g_seh_ebp = g_ebp = ebp; /* publish frame to SEH helper */"
seh_c, seh_d = "ebp = g_seh_ebp; /* read back frame from SEH helper */", "ebp = g_seh_ebp; g_ebp = ebp; /* read back frame from SEH helper */"
pub_re = re.compile(r'(?<!= )g_ebp = ebp;')
tot = {"tail": 0, "call": 0, "seh": 0, "pub": 0}
for f in sorted(glob.glob(str(ROOT / "src/recomp/gen/*.c"))):
    if Path(f).name == "recomp_dispatch.c": continue
    b = Path(f).read_bytes().decode("utf-8", "surrogateescape"); o = b
    tot["tail"] += len(tail_re.findall(b)); b = tail_re.sub("g_seh_ebp = g_ebp = ebp; ", b)
    tot["seh"] += b.count(seh_a) + b.count(seh_c); b = b.replace(seh_a, seh_b).replace(seh_c, seh_d)
    tot["pub"] += len(pub_re.findall(b)); b = pub_re.sub("g_seh_ebp = g_ebp = ebp;", b)
    out = []; has_ebp = False; prev = ""
    for ln in b.split("\n"):
        if ln.startswith("void sub_"): has_ebp = False
        s = ln.strip()
        if s == "uint32_t ebp;": has_ebp = True
        if has_ebp:
            m = call_re.match(ln)
            if m and "g_ebp = ebp;" not in prev and "g_ebp = ebp;" not in ln:
                ln = m.group(1) + "g_seh_ebp = g_ebp = ebp; " + ln[len(m.group(1)):]; tot["call"] += 1
        if s: prev = s
        out.append(ln)
    b = "\n".join(out)
    if b != o and not check: Path(f).write_bytes(b.encode("utf-8", "surrogateescape"))
print(tot, "(check only)" if check else "")
