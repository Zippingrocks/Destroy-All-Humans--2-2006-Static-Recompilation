"""Test original registration-loop count/arguments/ABI; Lua API helpers are doubles."""
import re
import subprocess
from pathlib import Path

root=Path(__file__).resolve().parents[1]
out=root/'diagnostics/registration_test'
out.mkdir(exist_ok=True)
source=(root/'src/recomp/gen/recomp_0011.c').read_text()
body=re.search(r'^void sub_001AF620\(void\)\n\{.*?^\}',source,re.M|re.S).group()
prefix=r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x30000];
static unsigned current,phase;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_00210EA0(void) { assert(phase==0 && ecx==0x1000 && edx==0x4000+current); phase=1; esp+=4; }
void sub_00210EF0(void) { assert(phase==1 && ecx==0x1000 && edx==0x5000+current && MEM32(esp+4)==0); phase=2; esp+=8; }
void sub_00211150(void) { assert(phase==2 && ecx==0x1000 && edx==0xFFFFFFFD); phase=0; ++current; esp+=4; }
'''
suffix=r'''
static void check(unsigned count) {
    memset(memory,0,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
    current=phase=0; esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
    MEM32(esp)=0x12345678; MEM32(esp+4)=0x2000; MEM32(esp+8)=count;
    for(unsigned i=0;i<count;i++) { MEM32(0x2000+i*8)=0x4000+i; MEM32(0x2004+i*8)=0x5000+i; }
    sub_001AF620();
    assert(current==count && !phase && esp==0x2000C && esi==0xABC && edi==0xDEF && ebx==0x123);
}
int main(void) { check(0); check(1); check(24); puts("PASS: 0, 1, and 24 registrations preserve ordering, arguments, stack, and saved registers"); }
'''
(out/'test.c').write_text(prefix+body+suffix)
vcvars=Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command=f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
subprocess.run([str(out/'test.exe')],cwd=out,check=True)
