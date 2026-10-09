import unittest

from .disasm import Instruction, Operand
from .lifter import Lifter


def _insn(mnemonic, op_str, operands):
    instruction = Instruction(0, 4, mnemonic, op_str, "")
    instruction.operands = operands
    return instruction


def _mm(name):
    return Operand(type="reg", reg=name)


def _mem(base=None, disp=0):
    return Operand(type="mem", mem_base=base, mem_disp=disp, mem_size=8)


class MmxMoveLifterTest(unittest.TestCase):
    def test_movq_loads_all_eight_bytes(self):
        self.assertEqual(
            Lifter().lift_instruction(
                _insn("movq", "mm1, qword ptr [esi + 4]",
                      [_mm("mm1"), _mem("esi", 4)])),
            ["mm1 = (uint64_t)SMEM64(esi + 4); /* movq */"],
        )

    def test_movntq_stores_all_eight_bytes(self):
        self.assertEqual(
            Lifter().lift_instruction(
                _insn("movntq", "qword ptr [edi + 8], mm1",
                      [_mem("edi", 8), _mm("mm1")])),
            ["SMEM64(edi + 8) = (int64_t)mm1; /* movntq */"],
        )


if __name__ == "__main__":
    unittest.main()