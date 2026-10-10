from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "\n".join(
    path.read_text(encoding="utf-8", errors="replace")
    for path in (ROOT / "src/recomp/gen").glob("recomp_*.c")
)

EXPECTED = {
    "sub_0004E250": 4,
    "sub_0004E2C0": 22,
    "sub_0004E840": 19,
    "sub_000BED70": 15,
    "sub_001160E0": 8,
    "sub_0013B6C0": 1,
    "sub_0013C3C0": 2,
}

for name, expected in EXPECTED.items():
    match = re.search(rf"/\*\*\n \* {name}\n.*?\n\}}\n", SOURCE, re.S)
    if not match:
        raise SystemExit(f"missing generated controller function: {name}")
    actual = match.group(0).count("RECOMP_X87_APPLY_PRECISION")
    if actual != expected:
        raise SystemExit(
            f"{name}: expected {expected} guest-precision operations, found {actual}"
        )

print(
    "PASS: DAH2 controller interpolation, smoother, quaternion, heading, "
    f"and physics paths contain {sum(EXPECTED.values())} XBE-precision operations"
)