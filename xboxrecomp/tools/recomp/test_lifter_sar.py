import unittest

from .disasm import BasicBlock, Instruction, Operand
from .lifter import Lifter, lift_basic_block


class ArithmeticShiftLifterTest(unittest.TestCase):
    @staticmethod
    def lift(register: str) -> str:
        instruction = Instruction(0, 4, "sar", f"{register}, 4", "")
        instruction.operands = [
            Operand(type="reg", reg=register),
            Operand(type="imm", imm=4),
        ]
        lifted, _ = lift_basic_block(
            Lifter(), BasicBlock(start=0, instructions=[instruction]))
        return "\n".join(lifted)

    def test_word_sar_sign_extends_bit_15(self):
        self.assertIn("(int16_t)LO16(esi) >> 4", self.lift("si"))

    def test_byte_sar_sign_extends_bit_7(self):
        self.assertIn("(int8_t)LO8(eax) >> 4", self.lift("al"))

    def test_dword_sar_sign_extends_bit_31(self):
        self.assertIn("(int32_t)eax >> 4", self.lift("eax"))


if __name__ == "__main__":
    unittest.main()
