from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "xboxrecomp/src/kernel/kernel_rtl.c").read_text(encoding="utf-8")

assert "XBOX_SHADOW_CS_MAX" in SOURCE
assert "xbox_shadow_cs_get" in SOURCE
assert "EnterCriticalSection(&s_shadow_cs_guard);" in SOURCE
assert "InitializeCriticalSection(&s_shadow_cs[i].native);" in SOURCE
assert "if (native) EnterCriticalSection(native);" in SOURCE
assert "if (native) LeaveCriticalSection(native);" in SOURCE
assert "No-op: single-threaded execution" not in SOURCE

print("PASS: guest critical sections use keyed native synchronization")
