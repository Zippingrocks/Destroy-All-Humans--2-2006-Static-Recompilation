from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "xboxrecomp/src/kernel/kernel_bridge.c").read_text(encoding="utf-8")

assert "static void bridge_NtReleaseMutant(void)" in SOURCE
assert "case 221: return bridge_NtReleaseMutant;" in SOURCE
assert "static void bridge_NtWaitForMultipleObjectsEx(void)" in SOURCE
assert "case 235: return bridge_NtWaitForMultipleObjectsEx;" in SOURCE
assert "native_handles[i] = bridge_resolve_handle(token);" in SOURCE
assert "count, native_handles, wait_type" in SOURCE
assert "uint32_t wait_mode = STACK_ARG(3);" in SOURCE
assert "uint32_t alertable = STACK_ARG(4);" in SOURCE
assert "uint32_t timeout_va = STACK_ARG(5);" in SOURCE
assert "case 235: return 24;" in SOURCE

single_ex = SOURCE.split("static void bridge_NtWaitForSingleObjectEx(void)", 1)[1]
single_ex = single_ex.split("static void bridge_NtWaitForMultipleObjectsEx(void)", 1)[0]
assert "fallback_timeout" not in single_ex
assert "bounded to 5s" not in single_ex

print("PASS: mutant release and native-width multiple-wait bridges are routed")
