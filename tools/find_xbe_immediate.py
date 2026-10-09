"""Find x86 instructions in the retail XBE that reference a 32-bit immediate.

This is a read-only diagnostic used to locate push-buffer packet emitters when
the linked XDK symbol address is unavailable. It reports only instructions
whose decoded immediate operand exactly matches the requested value.
"""

import argparse
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86_const import X86_OP_IMM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("value", type=lambda text: int(text, 0))
    parser.add_argument("--xbe", type=Path, default=Path("game_files/default.xbe"))
    args = parser.parse_args()

    config.configure_from_xbe(str(args.xbe))
    image = args.xbe.read_bytes()
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    wanted = args.value & 0xFFFFFFFF

    for section in config._SECTIONS:
        data = image[section.raw_addr : section.raw_addr + section.raw_size]
        for instruction in decoder.disasm(data, section.va):
            if any(
                operand.type == X86_OP_IMM and (operand.imm & 0xFFFFFFFF) == wanted
                for operand in instruction.operands
            ):
                print(
                    f"0x{instruction.address:08X}: "
                    f"{instruction.mnemonic} {instruction.op_str}"
                )


if __name__ == "__main__":
    main()
