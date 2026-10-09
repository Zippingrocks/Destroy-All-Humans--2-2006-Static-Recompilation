"""Verify the eight retail Bink MOVSX BP operations remain sign-extending."""

from pathlib import Path
from struct import unpack_from


ROOT = Path(__file__).resolve().parents[1]
XBE = ROOT / "game_files" / "default.xbe"
GENERATED = ROOT / "src" / "recomp" / "gen" / "recomp_missing_complete.c"
SITES = (
    (0x0028B5D8, "ebx", bytes.fromhex("0fbfdd")),
    (0x0028B918, "ebx", bytes.fromhex("0fbfdd")),
    (0x0028BD19, "ebx", bytes.fromhex("0fbfdd")),
    (0x0028C232, "ebp", bytes.fromhex("0fbfed")),
    (0x0028C2E6, "ebp", bytes.fromhex("0fbfed")),
    (0x0028C39A, "ebp", bytes.fromhex("0fbfed")),
    (0x0028C44F, "ebp", bytes.fromhex("0fbfed")),
    (0x0028C4D1, "ebp", bytes.fromhex("0fbfed")),
)


def main() -> None:
    image = XBE.read_bytes()
    base = unpack_from("<I", image, 0x104)[0]
    count = unpack_from("<I", image, 0x11C)[0]
    table = unpack_from("<I", image, 0x120)[0] - base
    sections = []
    for index in range(count):
        header = table + index * 56
        sections.append((
            unpack_from("<I", image, header + 4)[0],
            unpack_from("<I", image, header + 12)[0],
            unpack_from("<I", image, header + 16)[0],
        ))

    generated = GENERATED.read_text(encoding="utf-8")
    for address, destination, opcode in SITES:
        section = next(
            (item for item in sections
             if item[0] <= address and address + len(opcode) <= item[0] + item[2]),
            None,
        )
        assert section is not None, f"0x{address:08X} is outside XBE sections"
        file_offset = section[1] + address - section[0]
        assert image[file_offset:file_offset + len(opcode)] == opcode
        statement = (
            f"{destination} = SX16(LO16(ebp)); "
            f"/* MOVSX 0x{address:08X}: movsx {destination}, bp */"
        )
        assert generated.count(statement) == 1, f"missing exact restoration {statement}"

    print("PASS: all eight Bink MOVSX BP sites match the retail XBE and sign-extend")


if __name__ == "__main__":
    main()
