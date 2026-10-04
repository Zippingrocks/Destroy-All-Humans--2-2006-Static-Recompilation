from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "xboxrecomp/src/kernel/kernel_bridge.c").read_text(encoding="utf-8")

assert "uint32_t create_suspended = STACK_ARG(7);" in SOURCE
assert "create_suspended ? CREATE_SUSPENDED : 0" in SOURCE
assert "create_suspended != 0);" in SOURCE
assert "case 224: return bridge_NtResumeThread;" in SOURCE
assert "case 192: return bridge_NtCreateMutant;" in SOURCE

print("PASS: system-thread suspended creation and resume/mutant bridges are routed")
