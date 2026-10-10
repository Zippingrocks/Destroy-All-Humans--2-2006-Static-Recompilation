from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "xboxrecomp"))
from tools.recomp.disasm import Disassembler
from tools.recomp.lifter import _make_condition

# Retail DAH2 executes COMISS xmm2,[esp+14h], several non-flag-setting
# instructions, POP ESI, then JBE. The branch must consume the comparison-time
# CF/ZF/PF snapshot; after POP, the same effective address names caller data.
instruction = Disassembler().disassemble_function(
    bytes.fromhex("0f2f542414"), 0x0013B681, 0x0013B686
)[0]
expression, _ = _make_condition("jbe", "comiss", instruction.operands)
if expression != "(g_fp_cmp != 1)":
    raise SystemExit(f"COMISS/JBE does not consume the saved flags: {expression}")
if "MEM" in expression or "xmm" in expression:
    raise SystemExit(f"COMISS/JBE re-reads mutable operands: {expression}")

source = (root / "src/recomp/gen/recomp_0008.c").read_text(encoding="utf-8")
start = source.index("loc_0013B681:")
end = source.index("loc_0013B6A1:", start)
segment = source[start:end]
required = (
    "g_fp_cmp = RECOMP_FCMP(xmm2.f[0], MEMF(esp + 0x14));",
    "POP32(esp, esi);",
    "if ((g_fp_cmp != 1)) goto loc_0013B6B2;",
)
for statement in required:
    if statement not in segment:
        raise SystemExit(f"missing generated controller-heading sequence: {statement}")
if segment.index(required[0]) > segment.index(required[1]):
    raise SystemExit("controller heading comparison was not captured before POP ESI")
print("PASS: DAH2 controller heading preserves the retail pre-POP COMISS flags")