"""Compute true extents for generated functions that fall off their end (see audit_c_fallthrough.py).

For each flagged function, walks the real control flow of the retail bytes (direct jcc/jmp targets and
simple jump tables) from the function start, takes the furthest reachable byte as the end, and checks that a
linear decode of [start, end) lands on instruction boundaries and finishes with RET -- the form the lifter's
verified-extents manifest accepts.  Emits candidate manifest entries; never edits sources.

  py -3 tools/plan_function_extents.py cfall.json --out plan.json"""
import argparse, hashlib, json, struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_RET
ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser(); ap.add_argument("audit"); ap.add_argument("--out", required=True)
ap.add_argument("--limit", type=int, default=0x3000); a = ap.parse_args()
xbe = (ROOT / "game_files/default.xbe").read_bytes()
sha = hashlib.sha256(xbe).hexdigest()
TEXT_LO, TEXT_HI = 0x11000, 0x225CA0
def off(va): return va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
funcs = json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())
starts = sorted(int(f["start"], 16) for f in funcs)
import bisect
def next_start(s):
    i = bisect.bisect_right(starts, s); return starts[i] if i < len(starts) else 0x225CA0
def read_dword_va(va):
    if 0x11000 <= va < 0x225CA0: return struct.unpack_from("<I", xbe, off(va))[0]
    return None
def walk(start):
    seen = {}; work = [start]; hi = start
    while work:
        pc = work.pop()
        while True:
            if pc in seen or not (start <= pc < start + a.limit) or not (TEXT_LO <= pc < TEXT_HI): break
            ins = next(md.disasm(xbe[off(pc):off(pc) + 16], pc), None)
            if ins is None: return None
            seen[pc] = ins; hi = max(hi, pc + ins.size)
            m = ins.mnemonic
            if m in ("int3", "hlt", "ud2"):
                if m == "int3":      # alignment padding is not part of the function
                    seen.pop(pc, None); hi = max([i.address + i.size for i in seen.values()] + [start])
                break
            if m in ("ret", "retf"): break
            if ins.group(CS_GRP_JUMP):
                op = ins.operands[0] if ins.operands else None
                if op is not None and op.type == 2:      # immediate target
                    tgt = op.imm
                    if tgt != next_start(start) or tgt < start + a.limit:
                        if start <= tgt < start + a.limit: work.append(tgt)
                elif op is not None and op.type == 3 and op.mem.index and op.mem.scale == 4 and op.mem.disp:
                    t = op.mem.disp; n = 0
                    while n < 512:
                        v = read_dword_va(t + 4 * n)
                        if v is None or not (start <= v < start + a.limit): break
                        work.append(v); n += 1
                if m == "jmp": break
            pc += ins.size
    return seen, hi
audit = json.loads(Path(a.audit).read_text())
plan = []; skipped = []
for b in audit:
    s = int(b["fn"][4:], 16)
    if not (TEXT_LO <= s < TEXT_HI): continue
    r = walk(s)
    if r is None: skipped.append((b["fn"], "decode failed")); continue
    seen, hi = r
    old_end = int(b["range"][1], 16) if b.get("range") else None
    # linear check
    lin = list(md.disasm(xbe[off(s):off(hi)], s))
    ok = bool(lin) and lin[-1].address + lin[-1].size == hi and (lin[-1].mnemonic in ("ret", "jmp") or (lin[-1].mnemonic == "call" and xbe[off(hi)] == 0xCC)) and sum(i.size for i in lin) == hi - s
    if not ok:
        skipped.append((b["fn"], "linear decode of 0x%X-0x%X does not end on RET/JMP (last %s)" % (s, hi, lin[-1].mnemonic if lin else None))); continue
    if old_end is not None and hi <= old_end:
        skipped.append((b["fn"], "walk end 0x%X <= current end 0x%X" % (hi, old_end))); continue
    plan.append({"start": "0x%08X" % s, "end": "0x%08X" % hi, "num_instructions": len(lin),
                 "sha256": hashlib.sha256(xbe[off(s):off(hi)]).hexdigest(), "old_end": b["range"][1] if b.get("range") else None,
                 "executed_hint": b["fn"]})
Path(a.out).write_text(json.dumps({"xbe_sha256": sha, "plan": plan, "skipped": skipped}, indent=1))
print("%d extents planned, %d skipped" % (len(plan), len(skipped)))
for fn, why in skipped[:25]: print("  skip", fn, why)
