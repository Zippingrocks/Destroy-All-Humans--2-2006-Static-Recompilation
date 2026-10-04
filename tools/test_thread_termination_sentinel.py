from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/recomp/gen/recomp_0006.c").read_text(encoding="utf-8")

for label in ("loc_000FC661: ;", "loc_000FC790: ;"):
    tail = SOURCE.split(label, 1)[1].lstrip()
    assert tail.startswith("/* PsTerminateSystemThread is noreturn on Xbox.")
    assert "return;" in tail[:400]
    assert "__debugbreak()" not in tail[:400]

print("PASS: noreturn thread termination sentinels unwind host workers safely")
