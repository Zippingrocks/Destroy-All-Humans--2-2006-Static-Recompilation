from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
seeds = json.loads((ROOT / "seeds/manual_functions.json").read_text(encoding="utf-8"))

assert "void sub_001A7E30(void)" in source
assert "void sub_001A7EB0(void)" in source
assert "if (xbox_va == 0x001A7E30) return sub_001A7E30;" in source
assert "if (xbox_va == 0x001A7EB0) return sub_001A7EB0;" in source
assert "PUSH32(esp, 0x001A7EACu); sub_000D5A50();" in source
assert "PUSH32(esp, 0x001A7F37u); sub_000D5940();" in source
for offset in ("", " + 4", " + 8", " + 0xC"):
    assert f"MEM32(esi{offset}) =" in source
assert "PUSH32(esp, 0x001A7938u); sub_001A7FF0();" in source
assert "0x001A7933u" not in source
starts = {entry["start"] for entry in seeds}
assert {"0x001A7E30", "0x001A7EB0"} <= starts

print("PASS: retail title-surface callbacks and title-ready ABI are persistent")
