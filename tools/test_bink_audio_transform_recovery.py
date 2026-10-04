from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config

SOURCE = (ROOT / "src/recomp/gen/recomp_0013.c").read_text()
XBE = ROOT / "game_files/default.xbe"
config.configure_from_xbe(str(XBE))
image = XBE.read_bytes()

start, end = 0x00208AE0, 0x00208EDD
offset = config.va_to_file_offset(start)
instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + end - start], start))
branches = {(ins.address, ins.mnemonic, ins.op_str) for ins in instructions}

assert (0x00208C0A, "jge", "0x208e49") in branches
assert (0x00208C1A, "jge", "0x208e3a") in branches
assert "goto loc_00208E49" in SOURCE
assert "goto loc_00208E3A" in SOURCE
assert "loc_00208E49: ;" in SOURCE
assert "loc_00208E3A: ;" in SOURCE
assert "sub_00208E49(); return" not in SOURCE
assert "sub_00208E3A(); return" not in SOURCE
assert "loc_00208ECB: ;" in SOURCE
assert "esp = esp + 0x18;" in SOURCE

start, end = 0x00208EE0, 0x00209372
offset = config.va_to_file_offset(start)
instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + end - start], start))
branches = {(ins.address, ins.mnemonic, ins.op_str) for ins in instructions}

assert (0x00208EF6, "jle", "0x209025") in branches
assert (0x00208F08, "jge", "0x209016") in branches
assert (0x00208F94, "jge", "0x209007") in branches
for target in ("00209007", "00209016", "00209025", "0020936A"):
    assert f"loc_{target}: ;" in SOURCE
    assert f"sub_{target}(); return" not in SOURCE

print("PASS: recovered complete Bink audio transform helpers through 0x00209372")
