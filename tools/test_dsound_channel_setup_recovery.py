from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BODY = (ROOT / "src/recomp/gen/recomp_missing_complete.c").read_text()
DISPATCH = (ROOT / "src/recomp/gen/recomp_dispatch.c").read_text()
HEADER = (ROOT / "src/recomp/gen/recomp_funcs.h").read_text()

assert "void sub_0026AAD5(void)" in BODY
assert "SET_LO8(eax, MEM8(esi + 0x12));" in BODY
assert "eax = ZX8(MEM8(eax + 0xE));" in BODY
assert "SET_LO8(eax, LO8(eax) + 1);" in BODY
assert "sub_002687EF();" in BODY
assert "sub_0026A7C6();" in BODY
assert "{ 0x0026AAD5u, (recomp_func_t)sub_0026AAD5 }" in DISPATCH
assert "void sub_0026AAD5(void);" in HEADER
print("PASS: recovered DSOUND vtable channel-setup entry 0x0026AAD5")
