"""Exercise recovered 36160 plus its three real math callees; no game/UI.

Checks the exact retail extent and native generated function bodies, including
all finite norm/epsilon paths, aliasing, full memory, registers and x87 depth.
The historical truncated function must reproduce the measured 16-byte leak.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image = (ROOT / "game_files/default.xbe").read_bytes()


def retail(va, size):
    section = next(s for s in config._SECTIONS if s.va <= va < s.va + s.raw_size)
    offset = section.raw_addr + va - section.va
    return image[offset:offset + size]


cs = Cs(CS_ARCH_X86, CS_MODE_32)
instructions = list(cs.disasm(retail(0x36160, 0x73), 0x36160))
assert len(instructions) == 39
assert instructions[-1].address + instructions[-1].size == 0x361D3
assert [(i.address, i.mnemonic, i.op_str) for i in instructions[-4:]] == [
    (0x361CF, "pop", "edi"), (0x361D0, "pop", "esi"),
    (0x361D1, "pop", "ecx"), (0x361D2, "ret", "")]
assert [(i.address, i.op_str) for i in instructions if i.mnemonic == "call"] == [
    (0x36170, "0x13a090"), (0x36188, "0x13c3f0"), (0x361C0, "0x139d10")]
for va, size, count, ending in [(0x13A090, 21, 9, ""), (0x13C3F0, 9, 3, "4"), (0x139D10, 49, 11, "4")]:
    insns = list(cs.disasm(retail(va, size), va))
    assert len(insns) == count and insns[-1].address + insns[-1].size == va + size
    assert (insns[-1].mnemonic, insns[-1].op_str) == ("ret", ending)


def function(source, address):
    match = re.search(rf"^void sub_{address:08X}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    assert match, hex(address)
    return match.group()


source = (ROOT / "src/recomp/gen/recomp_0001.c").read_text(encoding="utf-8")
helpers = (ROOT / "src/recomp/gen/recomp_0008.c").read_text(encoding="utf-8")
body = function(source, 0x36160)
dependencies = "\n".join(function(helpers, va) for va in (0x13A090, 0x13C3F0, 0x139D10))
old_body = "void sub_00036160(void)\n{\n" + body.split("loc_00036160: ;", 1)[1].split("loc_00036175:", 1)[0] + "\n}\n"
assert "sub_0013A090();" in old_body and "sub_0013C3F0();" not in old_body
threshold = int.from_bytes(retail(0x29BBD4, 4), "little")
one = int.from_bytes(retail(0x29B7A8, 4), "little")
assert threshold == 0x34000000 and one == 0x3F800000

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,ebp;
static unsigned char memory[0x10000],expected[0x10000];
static double g_fp_stack[8];
static unsigned g_fp_top;
static int g_fp_cmp;
typedef union { float f[4]; uint32_t u[4]; } Xmm;
static Xmm xmm0,xmm1;
static Xmm scalar(float f) { Xmm r={{f,0,0,0}}; return r; }
#define XMM_SCALAR(f) scalar(f)
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(3); } } while(0)
static uint32_t offset(uint32_t va) {
    if(va<0xF000) return va;
    if(va==0x29BBD4) return 0xF000;
    CHECK(va==0x29B7A8); return 0xF004;
}
#define MEM32(a) (*(uint32_t *)(memory+offset((uint32_t)(a))))
#define MEMF(a) (*(float *)(memory+offset((uint32_t)(a))))
#define E32(a) (*(uint32_t *)(expected+offset((uint32_t)(a))))
#define EF(a) (*(float *)(expected+offset((uint32_t)(a))))
#define HI8(v) ((uint8_t)((v)>>8))
#define RECOMP_FCMP(a,b) (((a)!=(a)||(b)!=(b)) ? 2 : (a)<(b) ? -1 : (a)>(b) ? 1 : 0)
static int parity(uint32_t value) { unsigned n=0; for(unsigned i=0;i<8;++i)n+=(value>>i)&1; return !(n&1); }
#define RECOMP_PARITY8(v) parity(v)
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
static uint32_t bits(float f) { uint32_t v; memcpy(&v,&f,4); return v; }
'''
suffix = r'''
int main(void) {
    const float special[][4]={
      {0,0,0,0}, {-0.0f,0,-0.0f,-0.0f}, {0,0,0,1}, {0,0,0,-1},
      {1,2,3,4}, {-1,2,-3,4}, {0.000244140625f,0,0,0},
      {0.000244140625f,0.000244140625f,0,0},
      {0.000244140625f,0.000244140625f,0.000244140625f,0},
      {0,0,0,0.000244140625f}, {1.0e-12f,-2.0e-12f,3.0e-12f,-4.0e-12f},
      {1.0e10f,-2.0e10f,3.0e10f,-4.0e10f}};
    unsigned cases=0,branches[3]={0};
    for(unsigned sample=0;sample<140;++sample)
    for(unsigned in_place=0;in_place<2;++in_place)
    for(unsigned top=0;top<8;++top) {
        const uint32_t src=0x2000,dst=in_place?src:0x3000,sp=0xD000;
        float q[4];
        for(unsigned c=0;c<4;++c) q[c]=sample<12 ? special[sample][c] : ((int)((sample*17+c*29)%127)-63)/8.0f;
        double norm64=((double)q[2]*q[2]+(double)q[1]*q[1])+(double)q[0]*q[0];
        norm64+=(double)q[3]*q[3];
        float norm=(float)norm64;
        int cmp=norm < 0x1p-23f ? -1 : norm > 0x1p-23f ? 1 : 0;
        float factor=cmp<0 ? 1.0f : (float)(1.0/(double)norm);
        ++branches[cmp+1];
        memset(memory,0xCD,sizeof(memory));
        eax=0xAABBCCDD;ecx=dst;edx=src;esp=sp;
        ebx=0x12345678;esi=0x23456789;edi=0x3456789A;ebp=0x456789AB;
        g_fp_top=top;g_fp_cmp=7;
        for(unsigned i=0;i<8;++i)g_fp_stack[i]=1000.0+i;
        MEM32(0x29BBD4)=0x34000000;MEM32(0x29B7A8)=0x3F800000;
        for(unsigned c=0;c<4;++c)MEMF(src+c*4)=q[c];
        MEM32(sp)=0x115560;
        memcpy(expected,memory,sizeof(memory));
        E32(sp-4)=bits(factor);E32(sp-8)=esi;E32(sp-12)=edi;
        E32(sp-16)=bits(-factor);E32(sp-20)=0x361C5;
        for(unsigned c=0;c<3;++c)EF(dst+c*4)=q[c]*-factor;
        EF(dst+12)=(float)((double)factor*q[3]);
        sub_00036160();
        if(esp!=sp+4)fprintf(stderr,"ABI shortfall=%u actual=%08X expected=%08X\n",sp+4-esp,esp,sp+4);
        CHECK(esp==sp+4);
        CHECK(ebx==0x12345678 && esi==0x23456789 && edi==0x3456789A && ebp==0x456789AB);
        CHECK(edx==src && ecx==bits(factor));
        CHECK(eax==((bits(q[3])&0xFFFF0000u)|(top<<11)|(cmp<0 ? 0x100 : cmp==0 ? 0x4000 : 0)));
        CHECK(g_fp_top==top && g_fp_cmp==cmp);
        for(unsigned i=0;i<8;++i) {
            double want=i==((top+7)&7) ? (double)factor*q[3] : i==((top+6)&7) ? (double)q[3]*q[3] : 1000.0+i;
            CHECK(g_fp_stack[i]==want);
        }
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        ++cases;
    }
    CHECK(branches[0] && branches[1] && branches[2]);
    printf("PASS: %u actual-body quaternion inverse cases, norm branches=%u/%u/%u, full ABI/memory/x87\n",cases,branches[0],branches[1],branches[2]);
    return 0;
}
'''

out_root = ROOT / "diagnostics/quaternion_inverse_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, implementation, leak in [("recovered", body, None), ("historical", old_body, 16)]:
    (out / f"{name}.c").write_text(prefix + dependencies + implementation + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /fp:strict /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if leak:
        assert result.returncode == 3 and f"ABI shortfall={leak} " in result.stderr, result
        print(f"PASS: historical truncation reproduces {leak}-byte leak: " + result.stderr.strip())
    else:
        if result.returncode: print(result.stderr)
        result.check_returncode()
        print(result.stdout, end="")
print(f"PASS: exact retail extent/callees verified; artifacts: {out}")
