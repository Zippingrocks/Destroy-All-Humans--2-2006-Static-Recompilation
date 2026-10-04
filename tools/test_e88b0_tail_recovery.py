"""Verify the recovered E88B0 aligned-frame cleanup tail."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.recomp import config

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
data = (ROOT / "game_files/default.xbe").read_bytes()
section = next(s for s in config._SECTIONS if s.va <= 0xE88B0 < s.va + s.raw_size)
offset = section.raw_addr + 0xE88B0 - section.va
insns = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(data[offset:offset + 0xBE], 0xE88B0))
tail = [(i.address, i.mnemonic, i.op_str) for i in insns[-6:]]
assert tail == [
    (0xE8965, "pop", "edi"),
    (0xE8966, "pop", "esi"),
    (0xE8967, "pop", "ebx"),
    (0xE8968, "mov", "esp, ebp"),
    (0xE896A, "pop", "ebp"),
    (0xE896B, "ret", "8"),
]

source = (ROOT / "src/recomp/gen/recomp_0006.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_000E88B0\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert "goto loc_000E8965" in body
assert "goto loc_000E8950" in body
assert "loc_000E8907:" in body and "loc_000E8950:" in body
assert "loc_000E8965:" in body
assert "sub_000E8950();" not in body and "sub_000E8965();" not in body
assert "esp = ebp;" in body and "POP32(esp, ebp);" in body
assert "esp += 12; return; /* ret 8 */" in body
print("PASS: retail E88B0..E896D continuation and aligned-frame restoration verified")
