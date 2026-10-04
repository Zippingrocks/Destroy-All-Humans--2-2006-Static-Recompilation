from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config

SOURCE = (ROOT / "src/recomp/gen/recomp_missing_complete.c").read_text()
XBE = ROOT / "game_files/default.xbe"
config.configure_from_xbe(str(XBE))
image = XBE.read_bytes()

start, end = 0x000FC93B, 0x000FC95B
offset = config.va_to_file_offset(start)
instructions = list(
    Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset : offset + end - start], start)
)
decoded = [(ins.address, ins.mnemonic, ins.op_str) for ins in instructions]

assert decoded[0] == (0x000FC93B, "push", "0")
assert (0x000FC941, "call", "dword ptr [0x29b5d0]") in decoded
assert (0x000FC949, "jl", "0xfc950") in decoded
assert decoded[-1] == (0x000FC958, "ret", "4")

begin = SOURCE.index("void sub_000FC93B(void)")
finish = SOURCE.index("void sub_000FCA83(void)", begin)
body = SOURCE[begin:finish]
assert "RECOMP_ICALL_SAFE" in body
assert "loc_000FC950: ;" in body
assert "sub_000FB003();" in body
assert "esp += 8; return; /* ret 4 */" in body

print("PASS: recovered complete Bink wait thunk through its ret 4")
