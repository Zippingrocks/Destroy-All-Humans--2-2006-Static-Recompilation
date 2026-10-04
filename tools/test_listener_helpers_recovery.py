"""Exercise recovered listener append and component initialization bodies."""
import re
import subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
source = (root / 'src/recomp/gen/recomp_0001.c').read_text()
bodies = [re.search(rf'^void sub_{a}\(void\)\n\{{.*?^\}}', source, re.M | re.S).group()
          for a in ['0003AB60', '000424F0']]
out = root / 'diagnostics/listener_helpers_test'
out.mkdir(exist_ok=True)
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x300000];
static unsigned calls;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_0015E6E0(void) {
    assert(ecx==0x1080);
    assert(MEM32(esp+4)==0x1088+MEM32(0x1080)*4);
    assert(MEM32(esp+8)==0x1084+MEM32(0x1080)*4);
    MEM32(0x1080)++; esp+=12; calls++;
}
void sub_000BEEC0(void) {
    assert(ecx==0x1020 && MEM32(esp+4)==0x3F800000 && MEM32(esp+8)==1);
    assert(MEM32(ecx)==0x12345678 && MEM32(ecx+20)==0x3F800000);
    esp+=12; calls++;
}
'''
suffix = r'''
static void prepare(void) {
    memset(memory,0,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
    esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123; calls=0;
    MEM32(esp+4)=0x12345678;
}
static void saved(void) {
    assert(esi==0xABC && edi==0xDEF && ebx==0x123 && esp==0x20008 && calls==1);
}
int main(void) {
    for(unsigned n=0;n<3;n++) {
        prepare(); MEM32(0x1080)=n; sub_0003AB60(); saved();
        assert(MEM32(0x1080)==n+1 && MEM32(0x1084+n*4)==0x12345678);
    }
    prepare();
    for(unsigned n=0;n<4;n++) MEM32(0x2C9680+n*4)=n+11;
    sub_000424F0(); saved(); assert(eax==0x1000);
    for(unsigned n=0;n<8;n++) assert(MEM32(0x1000+n*4)==(n%4)+11);
    puts("PASS: listener append index/value and component defaults, call arguments and guest ABI");
}
'''
(out / 'test.c').write_text(prefix+'\n'.join(bodies)+suffix)
vcvars=Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
cmd=f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "'+cmd+'"',cwd=out,check=True)
subprocess.run([str(out/'test.exe')],cwd=out,check=True)
