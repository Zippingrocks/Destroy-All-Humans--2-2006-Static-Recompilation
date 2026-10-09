"""Disassemble guest code from game_files/default.xbe by guest VA (.text only).
   py -3 tools/disasm_xbe.py 0x1BEBC0 [bytes=96]"""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
va = int(sys.argv[1], 0); n = int(sys.argv[2], 0) if len(sys.argv) > 2 else 96
data = open("game_files/default.xbe", "rb").read()
off = va - 0x11000 + 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for i in md.disasm(data[off:off + n], va):
    print("%08x  %-24s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
