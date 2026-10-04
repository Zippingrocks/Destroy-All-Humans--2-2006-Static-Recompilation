"""Verify the recovered 2B000 intrusive-list removal continuation."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.recomp import config

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
data = (ROOT / "game_files/default.xbe").read_bytes()
section = next(s for s in config._SECTIONS if s.va <= 0x2B000 < s.va + s.raw_size)
offset = section.raw_addr + 0x2B000 - section.va
insns = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(data[offset:offset + 0x4A], 0x2B000))
assert [(i.address, i.mnemonic, i.op_str) for i in insns[-2:]] == [
    (0x2B046, "pop", "esi"),
    (0x2B047, "ret", "4"),
]

source = (ROOT / "src/recomp/gen/recomp_0000.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_0002B000\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert "loc_0002B010:" in body and "loc_0002B01B:" in body
assert "loc_0002B021:" in body and "loc_0002B046:" in body
assert "sub_0002B01B();" not in body
assert "MEM32(eax + 0x24) = MEM32(eax + 0x24) - 1;" in body
assert "POP32(esp, esi);" in body
assert "esp += 8; return; /* ret 4 */" in body
print("PASS: retail 2B000..2B049 list removal and register restoration verified")
