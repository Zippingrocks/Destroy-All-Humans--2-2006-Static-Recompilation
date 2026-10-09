"""Compare the esp deltas a trace run observed (esp_all.json from dump_heap_check.py) with the `ret N` forms in the retail bytes.

A function whose every `ret` is `ret N` must return with esp = entry esp + 4 + N.  A different observed delta means the lifted function
(or something it called) left the stack unbalanced.  Functions are limited to the extents the lifter used (functions.json + the verified
extents manifest).

  py -3 tools/check_esp_static.py RUN_DIR [--all]"""
import json, struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
ROOT = Path(__file__).resolve().parent.parent
run = Path(sys.argv[1])
obs = json.loads((run / "esp_all.json").read_text())
xbe = (ROOT / "game_files/default.xbe").read_bytes()
off = lambda va: va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = False
funcs = {int(f["start"], 16): (int(f["end"], 16) if isinstance(f["end"], str) else f["end"]) for f in json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())}
man = json.loads((ROOT / "seeds/verified_function_extents.json").read_text())
for k, v in man.items():
    if isinstance(v, list):
        for e in v:
            if isinstance(e, dict) and "start" in e and "end" in e: funcs[int(e["start"], 16)] = int(e["end"], 16)
bad = 0
for fn, d, cnt, d2, c2 in sorted(obs):
    end = funcs.get(fn)
    if not end or end <= fn or end - fn > 0x4000: continue
    rets = set()
    for ins in md.disasm(xbe[off(fn):off(end)], fn):
        if ins.mnemonic == "ret":
            rets.add(4 + (int(ins.op_str, 0) if ins.op_str else 0))
    if not rets: continue
    seen = {d} | ({d2} if c2 else set())
    if not seen <= rets:
        bad += 1
        print("sub_%08X observed delta(s) %s (%d/%d calls) but retail returns pop %s" % (fn, sorted(seen), cnt, c2, sorted(rets)))
print("%d functions checked, %d mismatches" % (len(obs), bad))
