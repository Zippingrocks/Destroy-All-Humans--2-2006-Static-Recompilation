"""Pin the retail DAH2 XInputGetState boundary used by parity input replay."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config

XBE = ROOT / "game_files/default.xbe"
config.configure_from_xbe(str(XBE))
image = XBE.read_bytes()


def bytes_at(va: int, size: int) -> bytes:
    section = next(s for s in config._SECTIONS if s.va <= va < s.va + s.raw_size)
    offset = section.raw_addr + va - section.va
    return image[offset:offset + size]


entry = bytes.fromhex("535633dbff1510b629008b54240c8b8a")
assert bytes_at(0x00296224, len(entry)) == entry
assert bytes_at(0x00296294, 3) == bytes.fromhex("c20800")

# XDK imports can relocate across builds; this retail image must contain one
# exact verified entry, or the debugger tool must refuse to synthesize input.
hits = []
for section in config._SECTIONS:
    data = image[section.raw_addr:section.raw_addr + section.raw_size]
    start = 0
    while True:
        index = data.find(entry, start)
        if index < 0:
            break
        hits.append(section.va + index)
        start = index + 1
assert hits == [0x00296224], [hex(hit) for hit in hits]
print("PASS: unique DAH2 retail XInputGetState entry and stdcall ret 8 boundary")