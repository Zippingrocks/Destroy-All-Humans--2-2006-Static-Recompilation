"""Guard the performance-safe default for generated bring-up diagnostics."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/main.c").read_text(encoding="utf-8")
control = (ROOT / "src/trace_control.c").read_text(encoding="utf-8")

condition = 'if (!g_dah2_verbose_trace && getenv("DAH2_INPUT_TRACE") == NULL) {'
assert source.count(condition) == 1, "default-quiet condition missing"
assert source.index("dah2_trace_initialize();") < source.index(condition)
assert source.index(condition) < source.index('freopen_s(&quiet_stderr, "NUL", "w", stderr);')
assert 'getenv("DAH2_VERBOSE_TRACE") != NULL' in control
assert 'getenv("DAH2_QUIET_TRACE") == NULL' in control

veh = source.split("static LONG CALLBACK veh_handler", 1)[1].split("/* ── WinMain", 1)[0]
non_av, access_violation = veh.split(
    "if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)", 1
)
assert "fprintf(stderr," in non_av and "fprintf(stdout," not in non_av
assert "fprintf(stderr," not in access_violation
assert "fprintf(stdout," in access_violation and "fflush(stdout);" in access_violation

print("PASS: generated hot-path tracing is quiet by default and explicitly recoverable")
