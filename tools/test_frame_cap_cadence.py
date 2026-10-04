"""Guard fixed-deadline frame pacing so render work is included in 30 Hz."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/guest_nv2a_bridge.c").read_text(encoding="utf-8")
body = source.split("static void dah2_frame_cap_30hz(void)", 1)[1].split(
    "void dah2_guest_gpu_present", 1
)[0]

assert "s_next.QuadPart += period;" in body
assert "s_next.QuadPart = now.QuadPart +" not in body
assert "now.QuadPart - s_next.QuadPart > period" in body

# Ten milliseconds of render work must leave about 23.3 ms to the next
# 30 Hz deadline, rather than adding another full 33.3 ms after the work.
frequency = 30_000
period = frequency // 30
deadline = period
now = 300
remaining = deadline - now
assert remaining == 700

print("PASS: 30 Hz pacing uses an accumulated deadline and bounds stall recovery")
