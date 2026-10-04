"""Guard the performance-safe default for generated bring-up diagnostics."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/main.c").read_text(encoding="utf-8")

condition = (
    'if (getenv("DAH2_VERBOSE_TRACE") == NULL ||\n'
    '        getenv("DAH2_QUIET_TRACE") != NULL) {'
)
assert source.count(condition) == 1, "default-quiet/verbose-opt-in condition missing"
assert source.index(condition) < source.index('freopen_s(&quiet_stderr, "NUL", "w", stderr);')

print("PASS: generated hot-path tracing is quiet by default and explicitly recoverable")
