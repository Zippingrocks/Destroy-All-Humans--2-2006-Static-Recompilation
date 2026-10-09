"""Find generated guest functions whose last emitted instruction falls through (no ret / jmp / hlt).

Each generated function's header says `Original: 0xSTART - 0xEND`. If the instruction that ends right
before END is not a terminator, the recompiler cut the function short (typically at a false interior
function seed) and the C body silently falls off its end. Lists those functions, whether another
function starts at END, and how far the real body runs.

  py -3 tools/audit_fallthrough_functions.py [--json out.json]"""
import argparse, glob, json, re, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, x86

ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser(); ap.add_argument("--json"); a = ap.parse_args()
xbe = (ROOT / "game_files/default.xbe").read_bytes()
def off(va): return va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = False
head = re.compile(r"Original: 0x([0-9A-Fa-f]{8}) - 0x([0-9A-Fa-f]{8}) \((\d+) bytes, (\d+) insns\)\n(?: \*[^\n]*\n)*? \*/\nvoid (sub_[0-9A-F]{8})\(void\)")
manual = (ROOT / "src/recomp_manual.c").read_text(errors="replace")
manual_names = set(re.findall(r"^void (sub_[0-9A-F]{8})\(void\)", manual, re.M))
funcs = {}
for f in sorted(glob.glob(str(ROOT / "src/recomp/gen/recomp_0*.c")) + [str(ROOT / "src/recomp/gen/recomp_missing_complete.c")]):
    t = Path(f).read_text(errors="replace")
    for m in head.finditer(t):
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        funcs[m.group(5)] = (s, e, Path(f).name)
starts = sorted(set(s for s, _, _ in funcs.values()))
TERM = {"ret", "retf", "jmp", "hlt", "int3", "ud2", "iret"}
bad = []
for name, (s, e, fn) in funcs.items():
    if not (0x11000 <= s < 0x225CA0) or e <= s: continue
    data = xbe[off(s):off(e)]
    last = None
    for i in md.disasm(data, s): last = i
    if last is None: continue
    if last.mnemonic in TERM and not (last.mnemonic == "jmp" and False): continue
    # conditional jumps etc. also fall through
    nxt = None
    for i in md.disasm(xbe[off(e):off(e) + 0x400], e):
        nxt = i
        if i.mnemonic in ("ret", "retf", "int3") or (i.mnemonic == "jmp" and not i.op_str.startswith("0x") is False and i.op_str.startswith("0x")): break
    bad.append({"fn": name, "start": "0x%08X" % s, "end": "0x%08X" % e, "last": "%s %s" % (last.mnemonic, last.op_str),
                "next_is_function": e in starts, "overridden_by_manual": name in manual_names, "file": fn,
                "real_end_guess": "0x%08X" % (nxt.address + nxt.size) if nxt else None})
print("%d generated functions fall off their end (of %d)" % (len(bad), len(funcs)))
print("  of which next address is a separate function start: %d; overridden by recomp_manual.c: %d" % (
    sum(b["next_is_function"] for b in bad), sum(b["overridden_by_manual"] for b in bad)))
for b in bad[:40]: print(" ", b["fn"], b["start"], b["end"], b["last"], "-> real end ~", b["real_end_guess"], "(manual)" if b["overridden_by_manual"] else "")
if a.json: Path(a.json).write_text(json.dumps(bad, indent=1))
