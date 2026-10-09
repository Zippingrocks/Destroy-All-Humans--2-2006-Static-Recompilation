"""Bounded 1AB6A0 recovery: actual pool scanner, modeled peripheral callbacks.

Tests RET4/nonvolatile ABI, ramp branching against host COMISS, all 256+16
array positions and actual 1AA8F0 activity marking below ranking capacities.
Does not claim full audio-device, ranking, eligibility or cleanup emulation.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.function_extents import apply_function_extents
from tools.recomp.translator import FunctionTranslator
image = (ROOT / "game_files/default.xbe").read_bytes()
assert hashlib.sha256(image).hexdigest() == "906871912263ae25de9f1c8e642ec0443b651b4beaf28b05057281ddc58baa1c"
config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
database = {}
for entry in json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text()):
    database[int(entry["start"], 16)] = dict(entry, end=int(entry["end"], 16))
apply_function_extents(image, database, ROOT / "seeds/verified_function_extents.json")
source = (ROOT / "src/recomp/gen/recomp_0011.c").read_text()
def body(address):
    return re.search(rf"^void sub_{address:08X}\(void\)\n\{{.*?^\}}", source, re.M | re.S).group()
actual, scanner = body(0x1AB6A0), body(0x1AA8F0)
regenerated = FunctionTranslator(image, database).translate_function(0x1AB6A0, database[0x1AB6A0])
assert actual == regenerated[regenerated.index("void sub_001AB6A0(void)"):].strip()
for address, end, count in ((0x1AB6A0, 0x1AB75A, 54), (0x1AA8F0, 0x1AAAE6, 141)):
    offset = config.va_to_file_offset(address)
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset+end-address], address))
    assert len(instructions) == count and sum(i.size for i in instructions) == end-address
    assert instructions[-1].mnemonic == "ret"
historical = actual[:actual.index("    ecx = 0x10;")] + "\n}\n"
ordered = actual.replace("((xmm2.f[0] <= xmm4.f[0]) || (isnan(xmm2.f[0]) || isnan(xmm4.f[0])))",
                         "(xmm2.f[0] <= xmm4.f[0])")
assert ordered != actual
native = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <xmmintrin.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,g_ebp,g_seh_ebp;
static double g_fp_stack[8];static uint32_t g_fp_top;
typedef union {float f[4];uint32_t u[4];uint64_t q[2];} Xmm;
static Xmm xmm0,xmm1,xmm2,xmm3,xmm4;
static Xmm XMM_SCALAR(float v){Xmm result;memset(&result,0,sizeof(result));result.f[0]=v;return result;}
static Xmm XMM_ZERO(void){return XMM_SCALAR(0);}
static unsigned char memory[0x300000],expected[0x300000];
static unsigned callback_calls[3],eligibility_calls;
#define g_esp esp
static void *at(unsigned char *ram,uint32_t a,unsigned size){CHECK(a<=sizeof(memory)-size);return ram+a;}
#define MEM8(a) (*(uint8_t *)at(memory,(uint32_t)(a),1))
#define MEM16(a) (*(uint16_t *)at(memory,(uint32_t)(a),2))
#define MEM32(a) (*(uint32_t *)at(memory,(uint32_t)(a),4))
#define MEMF(a) (*(float *)at(memory,(uint32_t)(a),4))
#define EM8(a) (*(uint8_t *)at(expected,(uint32_t)(a),1))
#define EM16(a) (*(uint16_t *)at(expected,(uint32_t)(a),2))
#define EM32(a) (*(uint32_t *)at(expected,(uint32_t)(a),4))
#define EMF(a) (*(float *)at(expected,(uint32_t)(a),4))
#define SMEM8(a) (*(int8_t *)at(memory,(uint32_t)(a),1))
#define LO8(v) ((uint8_t)(v))
#define LO16(v) ((uint16_t)(v))
#define HI8(v) ((uint8_t)((v)>>8))
#define ZX8(v) ((uint32_t)(uint8_t)(v))
#define ZX16(v) ((uint32_t)(uint16_t)(v))
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define CMP_L(a,b) ((int32_t)(a)<(int32_t)(b))
#define CMP_LE(a,b) ((int32_t)(a)<=(int32_t)(b))
#define CMP_G(a,b) ((int32_t)(a)>(int32_t)(b))
#define TEST_Z(a,b) (((a)&(b))==0)
#define TEST_NZ(a,b) (((a)&(b))!=0)
#define PUSH32(s,v) do {uint32_t value=(v);(s)-=4;MEM32(s)=value;}while(0)
#define POP32(s,v) do {(v)=MEM32(s);(s)+=4;}while(0)
static void unexpected(void){CHECK(0);}
#define RECOMP_ICALL_SAFE(t,s) unexpected()
/* Peripheral callback contracts only; no production behavior is replaced. */
static void sub_001AD670(void){CHECK(ecx==0x320CB4);callback_calls[0]++;eax=11;ecx=0xCC;edx=0xDD;esp+=4;}
static void sub_001AD2C0(void){CHECK(ecx==0x10000);callback_calls[1]++;eax=22;ecx=0xCC;edx=0xDD;esp+=8;}
static void sub_001AA430(void){CHECK(ecx==0x10000&&MEM32(esp+4)==1);callback_calls[2]++;eax=33;ecx=0xCC;edx=0xDD;esp+=8;}
static void sub_001ACAD0(void){eligibility_calls++;eax=!!MEM8(ecx+0x64);esp+=8;}
static void sub_001C55FC(void){CHECK(g_fp_stack[g_fp_top]==500.0);eax=500;g_fp_top=(g_fp_top+1)&7;esp+=4;}
static void sub_001A7540(void){unexpected();}
SCANNER
BODY
static const uint32_t values[]={0,0x80000000,0x3f000000,0x3f800000,0xbf800000,
    0x40000000,0x7f800000,0xff800000,0x7fc12345,0xffc12345,0x7f812345,1,0x80000001};
static void *oracle;
static unsigned compare_flags(float a,float b){return ((unsigned(*)(float,float))oracle)(a,b);}
static void setup(unsigned number) {
    memset(memory,0,sizeof(memory));memset(callback_calls,0,sizeof(callback_calls));eligibility_calls=0;
    for(unsigned i=0;i<272;i++){
        uint32_t object=0x20000+i*0x100,resource=0x50000+i*0x20;
        uint32_t array=i<256 ? 0x10454+i*4 : 0x10898+(i-256)*4;
        MEM32(array)=object;MEM32(object+0x5c)=resource;MEMF(object+0x54)=0.5f;
        MEM16(object+0x62)=7;MEM8(resource+10)=2;
    }
    unsigned index=number&255;
    MEM16(0x20000+index*0x100+0x60)=1;MEM8(0x20000+index*0x100+0x64)=1;
    MEM16(0x20000+((index+1)&255)*0x100+0x60)=1; /* active but not eligible */
    MEM8(0x20000+((index+2)&255)*0x100+0x64)=1; /* eligible but inactive */
    unsigned small_index=256+(number&15);
    MEM16(0x20000+small_index*0x100+0x60)=1;MEM8(0x20000+small_index*0x100+0x64)=1;
    MEM16(0x20000+(256+((number+1)&15))*0x100+0x60)=1;
    MEM8(0x20000+(256+((number+1)&15))*0x100+0x64)=1;
    MEM32(0x2B81A0)=0xFFC09E77;MEMF(0x29B7A8)=1.0f;MEMF(0x2B81C8)=1000.0f;
    unsigned size=sizeof(values)/sizeof(*values);
    for(unsigned i=0;i<16;i++){
        MEM32(0x108fc+i*4)=values[(number+i)%size];
        MEM32(0x1093c+i*4)=values[(number+i+3)%size];
        MEM32(0x1097c+i*4)=values[(number+i+6)%size];
        MEM32(0x109bc+i*4)=values[(number+i+9)%size];
    }
    MEM32(0x10af8)=0xffffffff;MEM32(0x10afc)=0xffffffff;
    esp=0x2ff000;MEM32(esp)=0x12345678;MEM32(esp+4)=values[number%size];
    eax=0x11;ecx=0x10000;edx=0x22;ebx=0x33445566;esi=0x778899aa;edi=0xbbccddee;
    g_ebp=0x123;g_seh_ebp=0x456;g_fp_top=number&7;
    memcpy(expected,memory,sizeof(memory));
}
static void reference(void) {
    float dt=EMF(esp+4);
    for(unsigned i=0;i<16;i++){
        uint32_t a=0x1093c+i*4;
        volatile float target=EMF(a+0x80)*EMF(a);
        volatile float step=dt*EMF(a+0x40);
        volatile float value=step+EMF(a-0x40);
        volatile float delta=target-value;
        volatile float direction=delta*EMF(a+0x40);
        unsigned flags=compare_flags(0.0f,direction);
        EMF(a-0x40)=value;
        if(!(flags&0x41)){EMF(a-0x40)=target;EMF(a+0x40)=0;}
    }
    for(unsigned i=0;i<272;i++){
        uint32_t obj=0x20000+i*0x100;
        if(EM16(obj+0x60)&&EM8(obj+0x64))EM8(obj+0x63)|=1;
    }
    EM32(0x10af8)=2;EM32(0x10afc)=2;
}
int main(void){
    unsigned csr=_mm_getcsr();_mm_setcsr(0x1f80);
    const unsigned char code[]={0x0f,0x2f,0xc1,0x9f,0x0f,0xb6,0xc4,0xc3};
    oracle=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);CHECK(oracle);
    memcpy(oracle,code,sizeof(code));DWORD old;CHECK(VirtualProtect(oracle,4096,PAGE_EXECUTE_READ,&old));
    FlushInstructionCache(GetCurrentProcess(),oracle,sizeof(code));
    for(unsigned n=0;n<320;n++){
        setup(n);reference();unsigned fp=g_fp_top;sub_001AB6A0();
        CHECK(esp==0x2ff008&&eax==33&&ebx==0x33445566&&esi==0x778899aa&&edi==0xbbccddee);
        CHECK(g_ebp==0x123&&g_seh_ebp==0x456&&g_fp_top==fp);
        CHECK(callback_calls[0]==1&&callback_calls[1]==1&&callback_calls[2]==1&&eligibility_calls==4);
        /* NaN classification and branch selection are checked, not NaN payload propagation. */
        for(unsigned i=0;i<16;i++)for(unsigned off=0x8fc;off<=0x97c;off+=0x80){
            uint32_t a=0x10000+off+i*4;
            if(isnan(MEMF(a))&&isnan(EMF(a)))EM32(a)=MEM32(a);
        }
        /* Only scratch stack bytes are excluded; caller return/argument and all non-stack RAM must match. */
        CHECK(!memcmp(memory,expected,0x2fc000));
        CHECK(!memcmp(memory+0x2ff000,expected+0x2ff000,sizeof(memory)-0x2ff000));
    }
    VirtualFree(oracle,0,MEM_RELEASE);_mm_setcsr(csr);
    printf("PASS: 320 actual audio-helper/scanner cases; all272 pool positions, RET4/nonvolatiles, nativeCOMISS ramps/NaN branches, activity bits and non-stackRAM\n");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="dah2-audio-pool-") as temporary:
    directory = Path(temporary)
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name, candidate in (("correct", actual), ("truncated", historical), ("ordered_nan", ordered)):
        (directory / f"{name}.c").write_text(native.replace("SCANNER", scanner).replace("BODY", candidate))
        command = f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 /fp:strict {name}.c /Fe:{name}.exe'
        result = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=directory, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, result.stdout + result.stderr
        result = subprocess.run([str(directory / f"{name}.exe")], capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        if name == "correct":
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout.strip())
        else:
            assert result.returncode == 3, result.stdout + result.stderr
            print(f"PASS: {name} historical mutant rejected")
print("PASS: exact XBE hashes/extents and fresh audio-helper regeneration")
