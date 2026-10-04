"""Actual active-frame bodies: EBP ABI, saved slots and helper observations.

Tests all sixteen ESP alignments, both quaternion trace branches, camera and
identity branches, and the real nested inverse body. Matrix-building/camera
boundary doubles isolate the frame contract; this is not a math-parity test.
"""
import json
import re
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"xboxrecomp"))
from tools.recomp import config
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
config.configure_from_xbe(str(ROOT/"game_files/default.xbe"))
image=(ROOT/"game_files/default.xbe").read_bytes()
database={int(f["start"],16):f for f in json.loads((ROOT/"xboxrecomp/tools/disasm/output/functions.json").read_text(encoding="utf-8"))}
decoder=Cs(CS_ARCH_X86,CS_MODE_32)
for begin in (0x13AEB0,0x15CE90,0x13C1A0):
    end=int(database[begin]["end"],16)
    section=next(s for s in config._SECTIONS if s.va<=begin<s.va+s.raw_size)
    offset=section.raw_addr+begin-section.va
    ins=list(decoder.disasm(image[offset:offset+end-begin],begin))
    assert [(i.mnemonic,i.op_str) for i in ins[:2]]==[("push","ebp"),("mov","ebp, esp")]
    assert [(i.mnemonic,i.op_str) for i in ins[-3:]]==[("mov","esp, ebp"),("pop","ebp"),("ret","")]

def body(path,name):
    source=(ROOT/path).read_text(encoding="utf-8")
    return re.search(rf"^void {name}\(void\)\n\{{.*?^\}}",source,re.M|re.S).group()
chunk8="src/recomp/gen/recomp_0008.c"
functions="\n".join([
    body(chunk8,"sub_0013B890"),
    body("src/recomp_manual.c","sub_0013B8F0"),
    body(chunk8,"sub_0013A730").replace("void sub_0013A730", "void real_quaternion"),
    body(chunk8,"sub_0013C1A0").replace("void sub_0013C1A0", "void real_inverse"),
    body(chunk8,"sub_0013AEB0"),
    body("src/recomp/gen/recomp_0009.c","sub_0015CE90"),
])
prefix=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
typedef union RecompXmm { float f[4]; uint32_t u[4]; uint64_t q[2]; } RecompXmm;
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_ebp,g_seh_ebp;
static RecompXmm vectors[4];
static double g_fp_stack[8]; static int g_fp_top,g_fp_cmp;
static unsigned char memory[0x400000];
static uint32_t incoming,expected_frame;
static unsigned mode,negative,observations,cases;
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define xmm0 vectors[0]
#define xmm1 vectors[1]
#define xmm2 vectors[2]
#define xmm3 vectors[3]
#define MEM32(a) (*(uint32_t *)(memory+(uint32_t)(a)))
#define MEMF(a) (*(float *)(memory+(uint32_t)(a)))
#define XBOX_PTR(a) (memory+(uint32_t)(a))
static uint32_t *manual_mem32(uint32_t a) { return (uint32_t *)(memory+a); }
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
static RecompXmm scalar(float v) { RecompXmm r={{0}}; r.f[0]=v; return r; }
#define XMM_ZERO() scalar(0)
#define XMM_SCALAR(v) scalar(v)
#define HI8(v) (((v)>>8)&255u)
#define TEST_Z(a,b) (((a)&(b))==0)
#define RECOMP_FCMP(a,b) (((a)>(b))-((a)<(b)))
static int parity(uint32_t v) { v^=v>>4;v^=v>>2;v^=v>>1;return !(v&1); }
#define RECOMP_PARITY8(v) parity((v)&255u)
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"FAIL case%u mode%u negative%u line%d: %s\n",cases,mode,negative,__LINE__,#c); exit(3); } } while(0)
static void observe(void) {
    CHECK(g_ebp==expected_frame); CHECK(MEM32(g_ebp)==incoming);
    CHECK(g_seh_ebp==0xDA7ABA5E); observations++;
}
static void matrix(uint32_t destination) {
    memset(memory+destination,0,64);
    MEMF(destination)=negative ? -1.0f:1.0f;
    MEMF(destination+0x14)=negative ? -1.0f:1.0f;
    MEMF(destination+0x28)=MEMF(destination+0x3C)=1.0f;
}
void sub_0013BB60(void) { observe(); matrix(ecx); esp+=4; }
void sub_0013BC80(void) { observe(); esp+=4; }
void sub_0013A730(void);
void sub_0013C1A0(void);
static void camera(void) { observe(); eax=0x20000; esp+=4; }
#define RECOMP_ICALL_SAFE(target,saved) do { (void)(target); (void)(saved); camera(); } while(0)
'''
suffix=r'''
void sub_0013A730(void) {
    uint32_t entry=esp,current=g_ebp;
    if(mode==0) observe();
    real_quaternion();
    CHECK(esp==entry+4 && g_ebp==current);
    if(negative) CHECK(MEM32(entry-0x14-8)==current);
}
void sub_0013C1A0(void) {
    uint32_t current=g_ebp,entry=esp;
    observe(); real_inverse();
    CHECK(g_ebp==current && esp==entry+4);
    CHECK(MEM32(entry-4)==current);
}
int main(void) {
    for(unsigned alignment=0;alignment<16;alignment++)
    for(unsigned variant=0;variant<7;variant++) {
        uint32_t stack=0x3F0000-alignment;
        mode=variant<2 ? 0:(variant<4 ? 1:(variant==4 ? 2:3));
        negative=variant&1; observations=0;
        memset(memory,0xA6,sizeof(memory));
        memset(g_fp_stack,0,sizeof(g_fp_stack)); g_fp_top=0;
        MEMF(0x29B7A8)=1;MEMF(0x29B7B0)=0;MEMF(0x29B720)=0.5f;MEMF(0x29B7AC)=-1;
        MEM32(0x2C965C)=1;MEM32(0x2C9660)=2;MEM32(0x2C9664)=0;
        incoming=0xAABB1000+alignment+variant*32;g_ebp=incoming;g_seh_ebp=0xDA7ABA5E;
        eax=0x11111111;ebx=0x22222222;esi=0x33333333;edi=0x44444444;
        ecx=0x10000;edx=0x20000;matrix(edx);
        esp=stack;PUSH32(esp,0xFEEDFACE);expected_frame=esp-4;
        if(mode==0) sub_0013AEB0();
        else if(mode==1) {
            MEM32(ecx+0x90)=(variant&1) ? 0x30000:0;
            MEM32(0x30000)=0x31000;MEM32(0x31030)=0x12345678;
            sub_0015CE90();
        } else if(mode==2) real_inverse();
        else sub_0013A730();
        CHECK(esp==stack && g_ebp==incoming && g_seh_ebp==0xDA7ABA5E);
        CHECK(ebx==0x22222222 && esi==0x33333333 && edi==0x44444444);
        if(mode!=3) CHECK(MEM32(stack-8)==incoming);
        if(mode==0) CHECK(observations==2);
        if(mode==1) CHECK(observations==((variant&1) ? 3:2));
        cases++;
    }
    printf("PASS: %u actual-body active EBP cases across16stackalignments; savedslots/helpers/restore exact\n",cases);
    return 0;
}
'''
out=ROOT/"diagnostics/active_ebp_recovery_test"
out.mkdir(exist_ok=True)
vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
mutations={
    "fixed":functions,
    "missing_restore":functions.replace("g_ebp = ebp; /* retail POP EBP restores the caller's register */", "/* historical: local pop not published */"),
    "wrong_incoming":functions.replace("uint32_t ebp = g_ebp; /* retail PUSH EBP saves the incoming register */", "uint32_t ebp = 0xDEADABCD; /* deterministic poison for original uninitialized incoming local */"),
    "stale_seh":functions.replace("/* Complete ordinary callee: retain incoming g_ebp, not SEH transport. */", "ebp = g_seh_ebp; /* historical override */"),
}
for name,code in mutations.items():
    (out/f"{name}.c").write_text(prefix+code+suffix,encoding="utf-8")
    command=f'call "{vcvars}" >nul && cl /nologo /Od /fp:strict /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
    result=subprocess.run([str(out/f"{name}.exe")],capture_output=True,text=True,timeout=10)
    if name=="fixed":
        if result.returncode:print(result.stderr)
        result.check_returncode();print(result.stdout,end="")
    else:
        assert result.returncode==3,(name,result.returncode,result.stderr)
        print("PASS: rejected",name,"mutation:",result.stderr.strip())
