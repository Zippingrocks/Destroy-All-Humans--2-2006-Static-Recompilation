"""Audit five manual render calls against actual retail XBE instructions.

This checks call-site argument setup and return-address pushes, not whether the
entire translated callees are complete. Each omission is also reintroduced in
memory to prove the audit detects the historical defect. No process is launched.
"""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "xboxrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.recomp import config

xbe_path = root / "game_files/default.xbe"
config.configure_from_xbe(str(xbe_path))
data = xbe_path.read_bytes()
source = (root / "src/recomp_manual.c").read_text(encoding="utf-8")
decoder = Cs(CS_ARCH_X86, CS_MODE_32)


def disassemble(start, end):
    section = next(s for s in config._SECTIONS if s.va <= start < s.va + s.raw_size)
    offset = section.raw_addr + start - section.va
    return list(decoder.disasm(data[offset:offset + end - start], start))


def body(text, name):
    match = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", text, re.M | re.S)
    assert match, name
    return match.group()


# Caller, original CALL instruction, preceding register argument setup.
sites = [
    ("sub_0015E740", 0x15E769, "ecx = edi;"),
    ("sub_0015E740", 0x15E770, "ecx = edi;"),
    ("sub_0015E740", 0x15E77A, "ecx = esi + 0x50;\n    edx = edi;"),
    ("sub_0015E740", 0x15E788, "ecx = esi + 0x90;\n    edx = edi + 0x40;"),
    ("sub_0015ECA0", 0x15ED5F, "ecx = MEM32(esi + 0xEC);"),
]


def verify_site(text, caller, address, setup):
    instruction = disassemble(address, address + 5)[0]
    assert instruction.mnemonic == "call" and instruction.size == 5
    target = int(instruction.op_str, 16)
    return_va = instruction.address + instruction.size
    expected = setup + f"\nPUSH32(esp, 0x{return_va:08X}u);\nsub_{target:08X}();"
    normalized = re.sub(r"\s+", "", body(text, caller))
    assert re.sub(r"\s+", "", expected) in normalized, f"0x{address:08X}: argument/return push mismatch"
    return return_va, target


for caller, address, setup in sites:
    return_va, target = verify_site(source, caller, address, setup)
    omitted = source.replace(f"PUSH32(esp, 0x{return_va:08X}u);", "", 1)
    try:
        verify_site(omitted, caller, address, setup)
    except AssertionError:
        pass
    else:
        raise AssertionError(f"Audit missed omitted return push at {address:08X}")
    print(f"PASS: retail CALL {address:08X} -> {target:08X}, return {return_va:08X}; omission rejected")

for start, end in [(0x15CD50, 0x15CE90), (0x15CE90, 0x15CF0B),
                   (0x13B8F0, 0x13B900), (0x177FB0, 0x178CDE)]:
    returns = [i for i in disassemble(start, end) if i.mnemonic == "ret"]
    assert returns and all(not i.op_str for i in returns), f"Unexpected stack arguments: {start:08X}"
print("PASS: all four retail callees use plain RET; five call sites preserve their register arguments")
