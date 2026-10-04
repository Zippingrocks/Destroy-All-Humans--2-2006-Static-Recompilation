"""Execute actual E5930 empty-list body plus exact recovered retail epilogue."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'xboxrecomp'))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
config.configure_from_xbe(str(ROOT / 'game_files/default.xbe'))
data = (ROOT / 'game_files/default.xbe').read_bytes()
section = next(s for s in config._SECTIONS if s.va <= 0xE5C3A < s.va + s.raw_size)
offset = section.raw_addr + 0xE5C3A - section.va
insns = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(data[offset:offset+10], 0xE5C3A))
assert [(i.mnemonic, i.op_str) for i in insns] == [
    ('pop','edi'), ('pop','esi'), ('pop','ebp'), ('pop','ebx'),
    ('add','esp, 0x28'), ('ret','4')]
source = (ROOT / 'src/recomp/gen/recomp_0005.c').read_text(encoding='utf-8')
def extract(name):
    return re.search(rf'^void {name}\(void\)\n\{{.*?^\}}', source, re.M|re.S).group()
caller, tail = extract('sub_000E5930'), extract('sub_000E5C3A')
prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_esp,g_ebp,g_seh_ebp;
static double g_fp_stack[8];
static unsigned g_fp_top;
static int g_fp_cmp;
static unsigned char memory[0x400000], before[0x400000];
static void *ptr(uint32_t a,unsigned n) { if(a>sizeof(memory)-n) exit(5); return memory+a; }
#define MEM32(a) (*(uint32_t *)ptr((uint32_t)(a),4))
#define MEM8(a) (*(uint8_t *)ptr((uint32_t)(a),1))
#define MEMF(a) (*(float *)ptr((uint32_t)(a),4))
#define eax g_eax
#define ebx g_ebx
#define ecx g_ecx
#define edx g_edx
#define esi g_esi
#define edi g_edi
#define esp g_esp
#define PUSH32(sp,v) do { uint32_t t=(v); (sp)-=4; MEM32(sp)=t; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
#define LO8(x) ((x)&255)
#define HI8(x) (((x)>>8)&255)
#define SET_LO8(x,v) ((x)=((x)&0xFFFFFF00u)|((v)&255u))
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define CMP_G(a,b) ((a)>(b))
#define CMP_LE(a,b) ((a)<=(b))
#define TEST_Z(a,b) (((a)&(b))==0)
#define TEST_NZ(a,b) (((a)&(b))!=0)
#define RECOMP_FCMP(a,b) ((a)!=(a)||(b)!=(b)?2:(a)<(b)?-1:(a)>(b)?1:0)
#define RECOMP_PARITY8(a) (0)
#define RECOMP_ICALL_SAFE(a,b) do { exit(6); } while(0)
#define UNREACHED(n) void n(void) { exit(7); }
UNREACHED(sub_0011A270)
UNREACHED(sub_000E5BE2)
UNREACHED(sub_000E4B70)
UNREACHED(sub_000E5AD7)
UNREACHED(sub_000E5AD2)
UNREACHED(sub_000E5A0D)
'''
suffix = r'''
int main(int argc,char **argv) {
    unsigned cases=0;
    (void)argv;
    for(unsigned align=0;align<4;align++)
    for(unsigned marker=1;marker<=16;marker++) {
        uint32_t object=0x1000+align, array=0x2000+align;
        memset(memory,0xA5,sizeof(memory));
        esp=0x3F0000; eax=0xAA; ecx=object; edx=0xDD;
        esi=0x11110000+marker; edi=0x22220000+marker;
        ebx=0x33330000+marker; g_ebp=g_seh_ebp=0x44440000+marker;
        MEM32(object+4)=0; MEM32(object+12)=array;
        memcpy(before,memory,sizeof(memory));
        PUSH32(esp,0x3C888889); PUSH32(esp,0x000F7D50);
        sub_000E5930();
        if(argc>1) {
            printf("HISTORICAL: stack leak=%X bytes\n",0x3F0000-esp);
            return esp==0x3F0000-0x3C ? 0 : 4;
        }
        if(esp!=0x3F0000 || esi!=0x11110000+marker || edi!=0x22220000+marker ||
           ebx!=0x33330000+marker || g_ebp!=0x44440000+marker || g_seh_ebp!=g_ebp) {
            fprintf(stderr,"FAIL: stack/register restoration esp=%X\n",esp); return 3;
        }
        if(eax!=array || ecx!=array || edx!=0xDD) return 4;
        if(memcmp(memory,before,0x3EFFC0)||memcmp(memory+0x3F0000,before+0x3F0000,0x10000)) return 8;
        cases++;
    }
    printf("PASS: %u actual E5930 empty-list paths preserve retail frame/registers and memory\n",cases);
    return 0;
}
'''
out = ROOT / 'diagnostics/event_empty_tail_test'
out.mkdir(exist_ok=True)
vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
for name, body in [('fixed',tail),('historical','void sub_000E5C3A(void) { g_esp+=4; }')]:
    (out/f'{name}.c').write_text(prefix+body+caller+suffix,encoding='utf-8')
    command=f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
    result=subprocess.run([str(out/f'{name}.exe')],capture_output=True,text=True,timeout=10)
    if name=='historical':
        assert result.returncode==3,result
        leak=subprocess.run([str(out/f'{name}.exe'),'leak'],capture_output=True,text=True,timeout=10)
        leak.check_returncode()
        print('PASS: historical tail rejected; '+leak.stdout.strip())
    else:
        if result.returncode: print(result.stderr)
        result.check_returncode()
        print(result.stdout,end='')
