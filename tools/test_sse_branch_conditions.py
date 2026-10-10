"""Native emitted SSE conditions; stable operands only, not cross-block flags/traps."""
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp.disasm import Disassembler
from tools.recomp.lifter import COND_MAP, _make_condition
NAMES = ("comiss", "ucomiss", "comisd", "ucomisd")
ALIASES = (("ja", "jnbe"), ("jae", "jnb", "jnc"), ("jb", "jnae", "jc"),
           ("jbe", "jna"), ("je", "jz"), ("jne", "jnz"), ("jp",), ("jnp",))
ALIASES = tuple(tuple(alias for alias in group if alias in COND_MAP) for group in ALIASES)
functions, mutants, references = [], [], []
expressions = []
for name in NAMES:
    prefix = "66" if name.endswith("sd") else ""
    opcode = "2e" if name.startswith("u") else "2f"
    references.append("{" + ",".join(f"0x{v:02x}" for v in bytes.fromhex(prefix + "0f" + opcode + "c19f0fb6c4c3")) + "}")
    for memory in (False, True):
        raw = bytes.fromhex(prefix + "0f" + opcode + ("00" if memory else "c1"))
        instruction = Disassembler().disassemble_function(raw, 0x1000, 0x1000 + len(raw))[0]
        for group, aliases in enumerate(ALIASES):
            for alias in aliases:
                expression, _ = _make_condition(alias, name, instruction.operands)
                identifier = f"condition_{name}_{int(memory)}_{alias}"
                expressions.append(expression)
                functions.append(f"static int {identifier}(void) {{ return {expression}; }}")
                a = "xmm0.f[0]"
                b = "MEMD(eax)" if memory and name.endswith("sd") else "MEMF(eax)" if memory else "xmm1.f[0]"
                operator = (">", ">=", "<", "<=", "==", "!=", None, None)[group]
                historical = f"({a} {operator} {b})" if operator else str(int(group == 7))
                mutants.append(f"static int {identifier}(void) {{ return {historical}; }}")
table = []
for name in NAMES:
    for memory in (False, True):
        table.append("{" + ",".join(f"condition_{name}_{int(memory)}_{a}" for aliases in ALIASES for a in aliases) + "}")
groups = [str(group) for group, aliases in enumerate(ALIASES) for _ in aliases]
native = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <xmmintrin.h>
typedef union {float f[4];double d[2];uint32_t u[4];uint64_t q[2];} Xmm;
static Xmm xmm0,xmm1,memory_rhs;
static uint32_t eax=0x12345678;
static int g_fp_cmp;
#define MEMF(address) memory_rhs.f[0]
#define MEMD(address) memory_rhs.d[0]
FUNCTIONS
typedef int (*Condition)(void);
static Condition conditions[8][ALIAS_COUNT] = {TABLE};
static const unsigned groups[ALIAS_COUNT] = {GROUPS};
static const unsigned char reference_code[4][9] = {REFERENCES};
static const uint32_t singles[] = {0,0x80000000,0x3f800000,0xbf800000,0x40000000,
    0xc0000000,0x7f800000,0xff800000,1,0x80000001,0x7f7fffff,0xff7fffff,
    0x7fc12345,0xffc12345,0x7f812345,0xff812345};
static const uint64_t doubles[] = {0,0x8000000000000000ULL,0x3ff0000000000000ULL,
    0xbff0000000000000ULL,0x4000000000000000ULL,0xc000000000000000ULL,
    0x7ff0000000000000ULL,0xfff0000000000000ULL,1,0x8000000000000001ULL,
    0x7fefffffffffffffULL,0xffefffffffffffffULL,0x7ff8123456789abcULL,
    0xfff8123456789abcULL,0x7ff0123456789abcULL,0xfff0123456789abcULL,
    0x3ff0000000000001ULL,0x3ff0000000000002ULL};
static unsigned expected(unsigned flags,unsigned group) {
    unsigned c=flags&1,z=!!(flags&64),p=!!(flags&4);
    switch(group) {case 0:return !c&&!z;case 1:return !c;case 2:return c;case 3:return c||z;
        case 4:return z;case 5:return !z;case 6:return p;case 7:return !p;}abort();
}
int main(void) {
    unsigned csr=_mm_getcsr();_mm_setcsr(0x1f80);unsigned cases=0;
    for(unsigned op=0;op<4;op++) {
        void *code=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(!code)return 4;memcpy(code,reference_code[op],9);DWORD old;
        if(!VirtualProtect(code,4096,PAGE_EXECUTE_READ,&old))return 4;
        FlushInstructionCache(GetCurrentProcess(),code,9);
        unsigned n=op>=2 ? sizeof(doubles)/sizeof(*doubles) : sizeof(singles)/sizeof(*singles);
        for(unsigned a=0;a<n;a++)for(unsigned b=0;b<n;b++) {
            memset(&xmm0,0xa5,sizeof(xmm0));memset(&xmm1,0x5a,sizeof(xmm1));
            if(op>=2){xmm0.q[0]=doubles[a];xmm1.q[0]=doubles[b];}
            else{xmm0.u[0]=singles[a];xmm1.u[0]=singles[b];}
            memory_rhs=xmm1;Xmm before0=xmm0,before1=xmm1,beforemem=memory_rhs;
            unsigned flags=op>=2 ? ((unsigned(*)(double,double))code)(xmm0.d[0],xmm1.d[0]) :
                ((unsigned(*)(float,float))code)(xmm0.f[0],xmm1.f[0]);
            g_fp_cmp=(flags&4)?2:(flags&64)?0:(flags&1)?-1:1;
            for(unsigned memory=0;memory<2;memory++)for(unsigned alias=0;alias<ALIAS_COUNT;alias++) {
                unsigned actual=!!conditions[op*2+memory][alias]();
                if(actual!=expected(flags,groups[alias])) {
                    fprintf(stderr,"mismatch op=%u memory=%u alias=%u a=%u b=%u flags=%x\n",op,memory,alias,a,b,flags);return 3;
                }
                if(eax!=0x12345678||memcmp(&xmm0,&before0,sizeof(Xmm))||
                   memcmp(&xmm1,&before1,sizeof(Xmm))||memcmp(&memory_rhs,&beforemem,sizeof(Xmm)))return 5;
                cases++;
            }
        }
        VirtualFree(code,0,MEM_RELEASE);
    }
    _mm_setcsr(csr);
    printf("PASS: %u native SSE branch cases; 13 supported aliases, 4 compares, register/memory, NaN/Inf/signed-zero/subnormal/double-lane; input bits preserved\n",cases);return 0;
}
'''
for expression in expressions:
    assert "g_fp_cmp" in expression, expression
    assert "xmm" not in expression and "MEM" not in expression and "isnan" not in expression, expression
print("PASS: emitted SSE branches consume the instruction-time comparison snapshot")
native = native.replace("TABLE", ",".join(table)).replace("GROUPS", ",".join(groups)).replace("REFERENCES", ",".join(references)).replace("ALIAS_COUNT", str(len(groups)))
with tempfile.TemporaryDirectory(prefix="dah2-sse-branch-") as temporary:
    directory = Path(temporary)
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name, bodies in (("correct", functions), ("historical", mutants)):
        (directory / f"{name}.c").write_text(native.replace("FUNCTIONS", "\n".join(bodies)), encoding="utf-8")
        command = f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 /fp:strict {name}.c /Fe:{name}.exe'
        result = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=directory, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, result.stdout + result.stderr
        result = subprocess.run([str(directory / f"{name}.exe")], capture_output=True, text=True, timeout=25, creationflags=subprocess.CREATE_NO_WINDOW)
        if name == "correct":
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout.strip())
        else:
            assert result.returncode == 3, result.stdout + result.stderr
            print("PASS: historical ordered-only/constant-parity/wrong-double-lane condition mutant rejected")
