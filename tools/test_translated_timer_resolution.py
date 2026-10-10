"""Guard precise Sleep pacing for the real translated game lifecycle."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/main.c").read_text(encoding="utf-8")
MANUAL = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
begin = SOURCE.index("timer_period_result = timeBeginPeriod(1);")
entry = SOURCE.index("xbe_entry_point();", begin)
end = SOURCE.index("timeEndPeriod(1);", entry)
assert begin < entry < end
assert "timer_period_result == TIMERR_NOERROR" in SOURCE[entry:end]

clock_begin = MANUAL.index("void sub_0013D4B0(void)")
clock_end = MANUAL.index("\n}", clock_begin)
clock = MANUAL[clock_begin:clock_end]
assert "recomp_rdtsc() * 3ull" in clock
assert "/ 0x2191C0ull" in clock
assert "GetTickCount" not in clock
assert "if (xbox_va == 0x0013D4B0) return sub_0013D4B0;" in MANUAL
print("PASS: translated lifecycle has 1 ms host pacing and the retail 733 MHz high-resolution game clock")
