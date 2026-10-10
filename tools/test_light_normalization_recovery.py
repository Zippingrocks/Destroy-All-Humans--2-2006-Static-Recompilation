"""Actual 13C3C0 verified against retail bytes and native UCOMISS/LAHF flags.

No game or GUI launch. Tests all 256 incoming AH values and every x87 top.
A separate hardware instruction sequence supplies AH and TEST flags.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image = (ROOT / "game_files/default.xbe").read_bytes()
section = next(s for s in config._SECTIONS if s.va <= 0x13C3C0 < s.va + s.raw_size)
offset = section.raw_addr + 0x13C3C0 - section.va
retail = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + 0x29], 0x13C3C0))
assert [(i.mnemonic, i.op_str) for i in retail] == [
    ("movss", "xmm0, dword ptr [esp + 8]"),
    ("ucomiss", "xmm0, dword ptr [0x29b7b0]"),
    ("lahf", ""), ("test", "ah, 0x44"), ("jp", "0x13c3dc"),
    ("fld", "dword ptr [0x2b1bac]"), ("ret", "8"),
    ("fld", "dword ptr [esp + 8]"), ("fsqrt", ""),
    ("fdivr", "dword ptr [esp + 4]"), ("ret", "8"),
]
source = (ROOT / "src/recomp/gen/recomp_0008.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_0013C3C0\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert "_sse_lahf_a = xmm0.f[0]" in body

PREFIX = r'''
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v);exit(3);}}while(0)
typedef union {float f[4];uint32_t u[4];uint64_t q[2];} RecompXmm;
static uint32_t g_eax,g_esp,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp;
static RecompXmm xmm0,other_xmm[7];
static double g_fp_stack[8];
static int g_fp_top,g_fp_cmp;
static uint16_t g_fp_control_word;
static double RECOMP_X87_APPLY_PRECISION(double value,uint16_t control) {
    uint16_t precision=(uint16_t)((control>>8)&3u);
    uint16_t rounding=(uint16_t)((control>>10)&3u);
    float rounded;
    if(precision!=0u||!isfinite(value)) return value;
    rounded=(float)value;
    if(rounding==1u&&(double)rounded>value) rounded=nextafterf(rounded,-INFINITY);
    else if(rounding==2u&&(double)rounded<value) rounded=nextafterf(rounded,INFINITY);
    else if(rounding==3u) {
        if(value>0.0&&(double)rounded>value) rounded=nextafterf(rounded,-INFINITY);
        else if(value<0.0&&(double)rounded<value) rounded=nextafterf(rounded,INFINITY);
    }
    return (double)rounded;
}
static unsigned char memory[0x300000],expected_memory[0x300000];
static uint32_t branch_test_byte;
static int branch_parity;
#define eax g_eax
#define esp g_esp
#define MEMF(a) (*(float *)(memory+(uint32_t)(a)))
#define MEM32(a) (*(uint32_t *)(memory+(uint32_t)(a)))
#define HI8(r) (((uint32_t)(r)>>8)&0xFFu)
#define SET_HI8(r,v) ((r)=((r)&0xFFFF00FFu)|(((uint32_t)(uint8_t)(v))<<8))
#define RECOMP_FCMP(a,b) (((a)!=(a)||(b)!=(b))?2:(a)<(b)?-1:(a)>(b)?1:0)
static RecompXmm XMM_SCALAR(float value) {
    RecompXmm r;r.q[0]=r.q[1]=0;r.f[0]=value;return r;
}
static int parity_probe(uint32_t value) {
    unsigned bits=0;branch_test_byte=value&0xFFu;
    for(unsigned i=0;i<8;++i) bits+=(value>>i)&1u;
    branch_parity=(bits&1u)==0;return branch_parity;
}
#define RECOMP_PARITY8(v) parity_probe(v)
'''

SUFFIX = r'''
/* Windows x64 ABI: ECX=EAX seed,RDX=denominator pointer,R8=flags output.
 * Hardware compare/LAHF/TEST with +0 as the retail comparison operand. */
static const unsigned char reference_code[]={
    0x8B,0xC1,                         /* mov eax,ecx */
    0xF3,0x0F,0x10,0x02,               /* movss xmm0,[rdx] */
    0x0F,0x57,0xC9,                    /* xorps xmm1,xmm1 */
    0x0F,0x2E,0xC1,                    /* ucomiss xmm0,xmm1 */
    0x9F,                              /* lahf */
    0xF6,0xC4,0x44,                    /* test ah,44h */
    0x9C,0x41,0x59,                    /* pushfq;pop r9 */
    0x45,0x89,0x08,                    /* mov [r8],r9d */
    0xC3                               /* ret */
};
typedef uint32_t (*FlagReference)(uint32_t,const float *,uint32_t *);
static FlagReference reference;
static unsigned cases;
static float from_bits(uint32_t value) {float f;memcpy(&f,&value,4);return f;}
static void check(float numerator,float denominator)
{
    for(unsigned ah=0;ah<256;++ah) for(unsigned top=0;top<8;++top) {
        uint32_t incoming=0xA5C3007Bu|(ah<<8),native_flags;
        uint32_t expected_eax=reference(incoming,&denominator,&native_flags);
        double old_stack[8];
        memset(memory,0xA7,sizeof(memory));
        MEM32(0x100)=0xDEADBEEFu;
        MEMF(0x104)=numerator;MEMF(0x108)=denominator;
        MEMF(0x29B7B0)=0.0f;MEMF(0x2B1BAC)=1048576.0f;
        memcpy(expected_memory,memory,sizeof(memory));
        g_eax=incoming;g_esp=0x100;g_ebx=0x11223344;g_ecx=0x22334455;
        g_edx=0x33445566;g_esi=0x44556677;g_edi=0x55667788;g_ebp=0x66778899;
        g_fp_top=top;g_fp_cmp=-1;g_fp_control_word=0x037F;
        for(unsigned i=0;i<8;++i) old_stack[i]=g_fp_stack[i]=100.25+i;
        memset(&xmm0,0xA5,sizeof(xmm0));memset(other_xmm,0x6C,sizeof(other_xmm));
        sub_0013C3C0();
        CHECK(g_eax==expected_eax&&g_esp==0x10C);
        CHECK(g_ebx==0x11223344&&g_ecx==0x22334455&&g_edx==0x33445566);
        CHECK(g_esi==0x44556677&&g_edi==0x55667788&&g_ebp==0x66778899);
        CHECK(g_fp_top==((top+7u)&7u)&&g_fp_cmp==-1&&g_fp_control_word==0x037F);
        CHECK(memcmp(memory,expected_memory,sizeof(memory))==0);
        CHECK(xmm0.u[0]==MEM32(0x108)&&!xmm0.u[1]&&!xmm0.u[2]&&!xmm0.u[3]);
        for(unsigned i=0;i<7;++i) for(unsigned j=0;j<4;++j)
            CHECK(other_xmm[i].u[j]==0x6C6C6C6Cu);
        CHECK(branch_test_byte==((expected_eax>>8)&0x44u));
        CHECK(branch_parity==((native_flags&4u)!=0));
        /* TEST clears CF/OF/SF; ZF corresponds to the actual tested byte. */
        CHECK((native_flags&0x881u)==0);
        CHECK(((native_flags&0x40u)!=0)==(branch_test_byte==0));
        double expected=branch_parity?(double)numerator/sqrt((double)denominator):1048576.0;
        double actual=g_fp_stack[g_fp_top];
        if(isnan(expected)) CHECK(isnan(actual));
        else if(isinf(expected)) CHECK(isinf(actual)&&signbit(actual)==signbit(expected));
        else CHECK(actual==expected);
        for(unsigned i=0;i<8;++i) if(i!=(unsigned)g_fp_top) CHECK(g_fp_stack[i]==old_stack[i]);
        ++cases;
    }
}
int main(void)
{
    DWORD old_protection;
    void *code=VirtualAlloc(NULL,sizeof(reference_code),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    CHECK(code);memcpy(code,reference_code,sizeof(reference_code));
    CHECK(VirtualProtect(code,sizeof(reference_code),PAGE_EXECUTE_READ,&old_protection));
    CHECK(FlushInstructionCache(GetCurrentProcess(),code,sizeof(reference_code)));
    reference=(FlagReference)code;
    check(1.0f,4.0f);check(-3.0f,9.0f);check(0.5f,4.0f);
    check(1.0f,0.0f);check(1.0f,-0.0f);check(1.0f,-4.0f);
    check(1.0f,INFINITY);check(1.0f,-INFINITY);
    check(1.0f,from_bits(0x7FC00001u));check(1.0f,from_bits(0x7F800001u));
    check(from_bits(0x7FC00001u),4.0f);
    /* Observed Natalia light delta before erroneous 2^20 scaling. */
    float x=5099944.0f/1048576.0f,y=6432200.0f/1048576.0f,z=-10050344.0f/1048576.0f;
    check(1.0f,x*x+y*y+z*z);
    CHECK(VirtualFree(code,0,MEM_RELEASE));
    printf("PASS: %u numeric/AH/x87-top cases match hardware UCOMISS/LAHF/TEST and retail ABI\n",cases);
    return 0;
}
'''

vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
with tempfile.TemporaryDirectory(prefix="dah2-light-normalization-") as temp:
    temp = Path(temp)
    for name, implementation in (("recovered", body), ("historical", re.sub(
            r"^    \{ float _sse_lahf_a = .*? /\* ucomiss; lahf \*/\r?\n", "", body, flags=re.M))):
        (temp / f"{name}.c").write_text(PREFIX + implementation + SUFFIX, encoding="utf-8")
        command = f'call "{vcvars}" >nul && cl /nologo /Od /W3 /TC {name}.c /Fe:{name}.exe'
        compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=temp,
                                  capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if compiled.returncode:
            print(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        result = subprocess.run([str(temp / f"{name}.exe")], cwd=temp,
                                capture_output=True, text=True, timeout=45,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if name == "recovered":
            if result.returncode:
                print(result.stdout + result.stderr)
            result.check_returncode()
            print(result.stdout, end="")
        else:
            assert result.returncode != 0, "historical no-op compare unexpectedly passed"
            print("PASS: historical no-op UCOMISS/LAHF mutant rejected")
print("PASS: verified retail 0x13C3C0..0x13C3E9, 41 bytes / 11 instructions")