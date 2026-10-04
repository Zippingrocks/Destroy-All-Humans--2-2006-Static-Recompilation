"""Guard precise Sleep pacing for the real translated game lifecycle."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/main.c").read_text(encoding="utf-8")
begin = SOURCE.index("timer_period_result = timeBeginPeriod(1);")
entry = SOURCE.index("xbe_entry_point();", begin)
end = SOURCE.index("timeEndPeriod(1);", entry)
assert begin < entry < end
assert "timer_period_result == TIMERR_NOERROR" in SOURCE[entry:end]
print("PASS: translated lifecycle brackets execution with 1 ms timer resolution")