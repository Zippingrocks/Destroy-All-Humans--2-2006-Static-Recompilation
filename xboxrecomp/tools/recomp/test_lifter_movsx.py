import unittest

from .disasm import Instruction, Operand
from .lifter import Lifter


class MovsxLifterTest(unittest.TestCase):
    @staticmethod
    def lift(destination: str, source: str) -> str:
        instruction = Instruction(0, 3, "movsx", f"{destination}, {source}", "")
        instruction.operands = [
            Operand(type="reg", reg=destination),
            Operand(type="reg", reg=source),
        ]
        return "\n".join(Lifter().lift_instruction(instruction))

    def test_movsx_ebp_bp_sign_extends(self):
        self.assertEqual("ebp = SX16(LO16(ebp));", self.lift("ebp", "bp"))

    def test_movsx_ebx_bp_sign_extends(self):
        self.assertEqual("ebx = SX16(LO16(ebp));", self.lift("ebx", "bp"))

    def test_movsx_esp_sp_sign_extends(self):
        self.assertEqual("esp = SX16(LO16(esp));", self.lift("esp", "sp"))


if __name__ == "__main__":
    unittest.main()
