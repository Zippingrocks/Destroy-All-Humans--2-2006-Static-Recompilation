"""Check actual recovered helper exits and menu API registration with call doubles."""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / 'diagnostics/menu_ctor_test'
out.mkdir(exist_ok=True)
bodies = []
for chunk, address in [('0001', '0003A0F0'), ('0001', '0003A1E0'), ('0003', '00091280'), ('0004', '000A9A80')]:
    source = (root / f'src/recomp/gen/recomp_{chunk}.c').read_text()
    bodies.append(re.search(rf'^void sub_{address}\(void\)\n\{{.*?^\}}', source, re.M | re.S).group())
prefix = r'''
#include <assert.h>
#include <stdio.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x400000];
static unsigned mode, functions, constants, close_calls;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_0008E430(void) { assert(ecx==0x100C); esp+=12; }
void sub_00090800(void) { assert(ecx==0x1000); eax=mode?0x3000:0; esp+=12; }
void sub_00093A80(void) { assert(0); }
void sub_00091080(void) { assert(0); }
void sub_001AEFE0(void) { assert(ecx==0x1000); esp+=4; }
void sub_001AFCE0(void) { assert(ecx==0x1000 && MEM32(esp+4)==0x2A8A08); esp+=8; }
void sub_001AF570(void) { assert(ecx==0x1000); functions++; esp+=12; }
void sub_001AF540(void) { assert(ecx==0x1000); constants++; esp+=12; }
void sub_001AF120(void) { assert(ecx==0x1000); close_calls++; esp+=4; }
'''
suffix = r'''
static void prepare(void) {
    memset(memory,0,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
    esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
    MEM32(esp+4)=7;
}
static void saved(void) { assert(esi==0xABC && edi==0xDEF && ebx==0x123); }
int main(void) {
    for(mode=0;mode<2;mode++) {
        prepare(); sub_00091280(); saved();
        assert(esp==0x20008 && MEM32(0x1020)==7);
    }
    prepare(); sub_000A9A80(); saved();
    assert(esp==0x20004 && functions==18 && constants==7 && close_calls==1);
    for(unsigned count=0;count<=3;count++) {
        prepare(); MEM32(0x2F1F80)=0x4000; MEM32(0x404C)=count;
        MEM32(0x4050)=0x5000; MEM32(0x4054)=0x5100; MEM32(0x4058)=0x5200;
        MEM32(0x5044)=0; MEM32(0x5144)=0x6000; MEM32(0x5244)=0x6100;
        MEM32(esp+4)=0; sub_0003A1E0(); saved();
        assert(esp==0x20008 && eax==0x1000);
        assert(MEM32(0x1000)==(count?0x4054:0x4050));
    }
    prepare(); MEM32(0x2F1F80)=0x4000; MEM32(0x404C)=3;
    MEM32(0x4050)=0x5000; MEM32(0x4054)=0x5100; MEM32(0x4058)=0x5200;
    MEM32(0x5144)=0x6000; MEM32(0x5244)=0x6100;
    MEM32(esp+4)=2; sub_0003A1E0(); saved();
    assert(esp==0x20008 && MEM32(0x1000)==0x4058);
    puts("PASS: actual iterator initialization, empty list, invalid-entry skip and indexed advance");
    puts("PASS: null/empty helper exits preserve ABI; all 18 functions and 7 constants register and close");
}
'''
(out / 'test.c').write_text(prefix + '\n'.join(bodies) + suffix)
vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
subprocess.run([str(out / 'test.exe')], cwd=out, check=True)
