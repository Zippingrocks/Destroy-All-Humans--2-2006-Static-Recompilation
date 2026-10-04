"""Verify the recovered 94D70 list-cleanup continuation and empty-list ABI."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.recomp import config

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
data = (ROOT / "game_files/default.xbe").read_bytes()
section = next(s for s in config._SECTIONS if s.va <= 0x94D70 < s.va + s.raw_size)
offset = section.raw_addr + 0x94D70 - section.va
insns = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(data[offset:offset + 0x4F], 0x94D70))
assert insns[-5].address == 0x94DB8 and insns[-5].mnemonic == "pop" and insns[-5].op_str == "edi"
assert [(i.mnemonic, i.op_str) for i in insns[-4:]] == [
    ("pop", "ebp"), ("pop", "esi"), ("pop", "ebx"), ("ret", "8")
]

source = (ROOT / "src/recomp/gen/recomp_0003.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_00094D70\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert "goto loc_00094DBA" in body
assert "loc_00094DA2:" in body and "loc_00094DAD:" in body
assert "loc_00094DB8:" in body and "loc_00094DBA:" in body
assert "sub_00094DBA();" not in body
assert "POP32(esp, esi);" in body and "POP32(esp, ebx);" in body
assert "esp += 12; return; /* ret 8 */" in body
print("PASS: retail 94D70..94DBF continuation and empty-list register restoration verified")
