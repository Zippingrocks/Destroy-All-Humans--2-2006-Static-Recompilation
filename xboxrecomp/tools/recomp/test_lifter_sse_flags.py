"""Regression tests for the bounded adjacent SSE compare + LAHF idiom.

The native test compiles the actual emitted statements and compares their AH
byte against real COMISS/UCOMISS/COMISD/UCOMISD followed by LAHF on the host.
No game processes or generated game functions are modified.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from .disasm import BasicBlock, Disassembler, Instruction, Operand
from .lifter import Lifter, lift_basic_block


ROOT = Path(__file__).resolve().parents[3]
VCVARS = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")


def compare_block(mnemonic, memory=False):
    prefix = "66" if mnemonic.endswith("sd") else ""
    opcode = "2e" if mnemonic.startswith("u") else "2f"
    modrm = "00" if memory else "c1"
    raw = bytes.fromhex(prefix + "0f" + opcode + modrm + "9f")
    instructions = Disassembler().disassemble_function(raw, 0x1000, 0x1000 + len(raw))
    return BasicBlock(start=0x1000, instructions=instructions)


def lifted(mnemonic, memory=False):
    statements, state = lift_basic_block(Lifter(), compare_block(mnemonic, memory))
    return "\n".join(statements), state


class SseFlagsLifterTest(unittest.TestCase):
    def test_adjacent_compare_lahf_materializes_only_ah(self):
        for mnemonic in ("comiss", "ucomiss", "comisd", "ucomisd"):
            with self.subTest(mnemonic=mnemonic):
                code, state = lifted(mnemonic)
                self.assertIn("SET_HI8(eax, _sse_lahf_ah)", code)
                for flag_byte in ("0x02u", "0x03u", "0x42u", "0x47u"):
                    self.assertIn(flag_byte, code)
                self.assertIn("isnan(_sse_lahf_a) || isnan(_sse_lahf_b)", code)
                self.assertEqual(state[0], mnemonic)
                lane = "d" if mnemonic.endswith("sd") else "f"
                self.assertIn(f"xmm0.{lane}[0]", code)
                self.assertIn(f"xmm1.{lane}[0]", code)

    def test_memory_read_is_snapshotted_before_ah_changes_eax(self):
        for mnemonic in ("ucomiss", "ucomisd"):
            code, _ = lifted(mnemonic, memory=True)
            memory_read = "MEMD(eax)" if mnemonic.endswith("sd") else "MEMF(eax)"
            self.assertEqual(code.count(memory_read), 1)
            self.assertLess(code.index(memory_read), code.index("SET_HI8"))

    def test_nonadjacent_and_cross_block_lahf_are_not_guessed(self):
        block = compare_block("ucomiss")
        middle = Instruction(0x1003, 3, "xorps", "xmm0, xmm0", "0f57c0")
        middle.operands = [Operand(type="reg", reg="xmm0"), Operand(type="reg", reg="xmm0")]
        block.instructions.insert(1, middle)
        statements, _ = lift_basic_block(Lifter(), block)
        self.assertNotIn("SET_HI8", "\n".join(statements))
        adjacent = compare_block("ucomiss")
        _, state = lift_basic_block(Lifter(), BasicBlock(
            start=adjacent.start, instructions=adjacent.instructions[:1]))
        statements, _ = lift_basic_block(Lifter(), BasicBlock(
            start=adjacent.instructions[1].address, instructions=adjacent.instructions[1:]), state)
        self.assertNotIn("SET_HI8", "\n".join(statements))

    def test_invalid_memory_width_does_not_match(self):
        for mnemonic, wrong_width in (("ucomiss", 8), ("ucomisd", 4)):
            block = compare_block(mnemonic, memory=True)
            block.instructions[0].operands[1].mem_size = wrong_width
            statements, _ = lift_basic_block(Lifter(), block)
            self.assertNotIn("SET_HI8", "\n".join(statements))

    @unittest.skipUnless(os.name == "nt" and VCVARS.exists(),
                         "native hardware parity requires the installed Windows x64 MSVC tools")
    def test_native_emitted_behavior_matches_hardware_lahf(self):
        names = ("comiss", "ucomiss", "comisd", "ucomisd")
        functions = []
        assembly = [".code"]
        for mnemonic in names:
            for memory in (False, True):
                code, _ = lifted(mnemonic, memory)
                suffix = "mem" if memory else "reg"
                functions.append(f"static void lifted_{mnemonic}_{suffix}(void) {{\n{code}\n}}")
            assembly.extend([
                f"reference_{mnemonic} PROC",
                f"    {mnemonic} xmm0, xmm1",
                "    lahf",
                "    movzx eax, ah",
                "    ret",
                f"reference_{mnemonic} ENDP",
            ])
        assembly.append("END")
        native = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(3);}}while(0)
typedef union RecompXmm {float f[4];double d[2];uint32_t u[4];uint64_t q[2];} RecompXmm;
static uint32_t eax,ebx,ecx,edx,esi,edi,ebp,esp;
static RecompXmm xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,memory_rhs;
static unsigned memf_reads,memd_reads;static uint32_t memory_address;
static float readf(uint32_t address){memf_reads++;memory_address=address;return memory_rhs.f[0];}
static double readd(uint32_t address){memd_reads++;memory_address=address;return memory_rhs.d[0];}
#define MEMF(address) readf((uint32_t)(address))
#define MEMD(address) readd((uint32_t)(address))
#define SET_HI8(r,v) ((r)=((r)&0xFFFF00FFu)|(((uint32_t)(uint8_t)(v))<<8))
FUNCTIONS
extern unsigned reference_comiss(float,float),reference_ucomiss(float,float);
extern unsigned reference_comisd(double,double),reference_ucomisd(double,double);
typedef void (*Lifted)(void);
static const Lifted single[4]={lifted_comiss_reg,lifted_comiss_mem,lifted_ucomiss_reg,lifted_ucomiss_mem};
static const Lifted dual[4]={lifted_comisd_reg,lifted_comisd_mem,lifted_ucomisd_reg,lifted_ucomisd_mem};
typedef struct FCase {uint32_t a,b;unsigned ah;} FCase;
typedef struct DCase {uint64_t a,b;unsigned ah;} DCase;
static const FCase singles[]={
 {0x3F800000u,0x40000000u,0x03},{0x40000000u,0x3F800000u,0x02},
 {0x3F800000u,0x3F800000u,0x42},{0x00000000u,0x80000000u,0x42},
 {0x7F800000u,0x7F800000u,0x42},{0xFF800000u,0x7F800000u,0x03},
 {0x7F800000u,0xFF800000u,0x02},{0x00000001u,0x00000000u,0x02},
 {0x80000001u,0x00000000u,0x03},{0x7FC12345u,0x3F800000u,0x47},
 {0x3F800000u,0xFFC12345u,0x47},{0x7F812345u,0x40000000u,0x47},
 {0x3F800000u,0x7F812345u,0x47},{0x7FC12345u,0x7FC54321u,0x47}
};
static const DCase doubles[]={
 {0x3FF0000000000000ULL,0x4000000000000000ULL,0x03},
 {0x4000000000000000ULL,0x3FF0000000000000ULL,0x02},
 {0x3FF0000000000000ULL,0x3FF0000000000000ULL,0x42},
 {0x0000000000000000ULL,0x8000000000000000ULL,0x42},
 {0x7FF0000000000000ULL,0x7FF0000000000000ULL,0x42},
 {0xFFF0000000000000ULL,0x7FF0000000000000ULL,0x03},
 {0x7FF0000000000000ULL,0xFFF0000000000000ULL,0x02},
 {0x0000000000000001ULL,0x0000000000000000ULL,0x02},
 {0x8000000000000001ULL,0x0000000000000000ULL,0x03},
 {0x7FF8123456789ABCULL,0x3FF0000000000000ULL,0x47},
 {0x3FF0000000000000ULL,0xFFF8123456789ABCULL,0x47},
 {0x7FF0123456789ABCULL,0x4000000000000000ULL,0x47},
 {0x3FF0000000000000ULL,0x7FF0123456789ABCULL,0x47},
 /* Two doubles that cannot be distinguished by looking at float lane zero. */
 {0x3FF0000000000001ULL,0x3FF0000000000000ULL,0x02},
 {0x3FF0000000000000ULL,0x3FF0000000000001ULL,0x03}
};
static unsigned cases;
static void verify(Lifted function,int is_double,int memory,unsigned expected,uint32_t stale) {
    RecompXmm before[8]={xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7};
    eax=stale;ebx=0x12345678u;ecx=0x23456789u;edx=0x3456789Au;
    esi=0x456789ABu;edi=0x56789ABCu;ebp=0x6789ABCDu;esp=0x789ABCDEu;
    memf_reads=memd_reads=0;memory_address=0;
    function();
    CHECK(eax==((stale&0xFFFF00FFu)|(expected<<8)));
    CHECK(ebx==0x12345678u&&ecx==0x23456789u&&edx==0x3456789Au);
    CHECK(esi==0x456789ABu&&edi==0x56789ABCu&&ebp==0x6789ABCDu&&esp==0x789ABCDEu);
    RecompXmm after[8]={xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7};
    CHECK(!memcmp(before,after,sizeof(before)));
    CHECK(memf_reads==(unsigned)(memory&&!is_double));
    CHECK(memd_reads==(unsigned)(memory&&is_double));
    if(memory)CHECK(memory_address==stale);
    cases++;
}
int main(void) {
    const uint32_t stale[]={0x00000000u,0xFFFFFFFFu,0xA5A55A5Au,0x7654AB12u};
    memset(&xmm0,0xC3,sizeof(xmm0));memset(&xmm1,0xB2,sizeof(xmm1));
    memset(&xmm2,0xA1,sizeof(xmm2));memset(&xmm3,0x94,sizeof(xmm3));
    memset(&xmm4,0x85,sizeof(xmm4));memset(&xmm5,0x76,sizeof(xmm5));
    memset(&xmm6,0x67,sizeof(xmm6));memset(&xmm7,0x58,sizeof(xmm7));
    for(unsigned i=0;i<sizeof(singles)/sizeof(singles[0]);i++) {
        xmm0.u[0]=singles[i].a;xmm1.u[0]=memory_rhs.u[0]=singles[i].b;
        CHECK(reference_comiss(xmm0.f[0],xmm1.f[0])==singles[i].ah);
        CHECK(reference_ucomiss(xmm0.f[0],xmm1.f[0])==singles[i].ah);
        for(unsigned f=0;f<4;f++)for(unsigned s=0;s<4;s++)
            verify(single[f],0,f&1,singles[i].ah,stale[s]);
    }
    for(unsigned i=0;i<sizeof(doubles)/sizeof(doubles[0]);i++) {
        xmm0.q[0]=doubles[i].a;xmm1.q[0]=memory_rhs.q[0]=doubles[i].b;
        CHECK(reference_comisd(xmm0.d[0],xmm1.d[0])==doubles[i].ah);
        CHECK(reference_ucomisd(xmm0.d[0],xmm1.d[0])==doubles[i].ah);
        for(unsigned f=0;f<4;f++)for(unsigned s=0;s<4;s++)
            verify(dual[f],1,f&1,doubles[i].ah,stale[s]);
    }
    printf("PASS: %u native compare/LAHF cases match hardware AH; EAX, GPRs, XMMs and source addresses preserved\n",cases);
    return 0;
}
'''.replace("FUNCTIONS", "\n".join(functions))
        output_root = ROOT / "diagnostics/lifter_sse_flags_test"
        output_root.mkdir(exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix="run_", dir=output_root))
        (output / "test.c").write_text(native, encoding="utf-8")
        (output / "reference.asm").write_text("\n".join(assembly) + "\n", encoding="utf-8")
        command = (
            f'call "{VCVARS}" >nul && ml64 /nologo /c reference.asm && '
            'cl /nologo /O2 /fp:precise /Tctest.c reference.obj /Fe:test.exe'
        )
        compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=output,
                                  capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        result = subprocess.run([str(output / "test.exe")], cwd=output, timeout=30,
                                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(result.stdout, end="")
        print(f"Native artifacts: {output}")


if __name__ == "__main__":
    unittest.main()
