from pathlib import Path

root = Path(__file__).resolve().parents[1]
sites = (
    ("recomp_0007.c", "loc_00113112:",
     "g_fp_cmp = RECOMP_FCMP(xmm0.f[0], MEMF(esi + 0xB4));",
     "xmm0 = XMM_SCALAR(MEMF(esi + 0xB4));",
     "if ((g_fp_cmp != 1)) goto loc_00113151;"),
    ("recomp_0008.c", "loc_0013B681:",
     "g_fp_cmp = RECOMP_FCMP(xmm2.f[0], MEMF(esp + 0x14));",
     "POP32(esp, esi);",
     "if ((g_fp_cmp != 1)) goto loc_0013B6B2;"),
    ("recomp_0008.c", "loc_0013D0F0:",
     "g_fp_cmp = RECOMP_FCMP(xmm1.f[0], MEMF(eax));",
     "xmm1 = XMM_SCALAR(MEMF(eax));",
     "if ((g_fp_cmp != 1)) goto loc_0013D108;"),
    ("recomp_0009.c", "loc_00168800:",
     "g_fp_cmp = RECOMP_FCMP(xmm0.f[0], MEMF(esp + 0x34));",
     "PUSH32(esp, edi);",
     "if ((g_fp_cmp == -1 || g_fp_cmp == 2)) goto loc_0016881E;"),
)
for filename, label, compare, mutation, branch in sites:
    source = (root / "src/recomp/gen" / filename).read_text(encoding="utf-8")
    begin = source.index(label)
    end = source.find("\nloc_", begin + len(label))
    if end < 0:
        end = begin + 4096
    block = source[begin:end]
    for statement in (compare, mutation, branch):
        if statement not in block:
            raise SystemExit(f"{filename}:{label} missing {statement}")
    if not block.index(compare) < block.index(mutation) < block.index(branch):
        raise SystemExit(f"{filename}:{label} did not snapshot flags before operand mutation")
print(f"PASS: {len(sites)} DAH2 SSE branches preserve instruction-time flags across stack/register mutation")