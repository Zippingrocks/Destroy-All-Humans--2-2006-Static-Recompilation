"""Check recovered native script callback argument flow and ABI using doubles."""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / 'diagnostics/script_dispatch_test'
out.mkdir(exist_ok=True)
source = (root / 'src/recomp/gen/recomp_0009.c').read_text()
body = re.search(r'^void sub_00157460\(void\)\n\{.*?^\}', source, re.M | re.S).group()
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x30000];
static unsigned phase;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_001AF480(void) {
    assert(phase++==0 && ecx==0x1000 && MEM32(esp+4)==0xFFFFFFFFu);
    eax=0x4AD37271; esp+=8;
}
void sub_001AF130(void) {
    assert(phase++==1 && ecx==0x1000 && MEM32(esp+4)==1);
    eax=0xFFFF; esp+=8;
}
void sub_001552D0(void) { assert(phase++==2); eax=0x2000; esp+=4; }
static void virtual_call(uint32_t target) {
    assert(phase++==3 && target==0x159CC0 && ecx==0x2000);
    assert(MEM32(esp)==0x157484 && MEM32(esp+4)==0x4AD37271 && MEM32(esp+8)==0x1000);
    eax=7; esp+=12;
}
#undef RECOMP_ICALL_SAFE
#define RECOMP_ICALL_SAFE(target, saved_sp) virtual_call(target)
'''
suffix = r'''
int main(void) {
    g_xbox_mem_offset=(ptrdiff_t)memory; esp=0x20000; ecx=0x1000;
    esi=0xABC; edi=0xDEF; ebx=0x123;
    MEM32(0x2000)=0x3000; MEM32(0x3068)=0x159CC0;
    sub_00157460();
    assert(phase==4 && eax==7 && esp==0x20004 && esi==0xABC && edi==0xDEF && ebx==0x123);
    puts("PASS: script callback passes original ID/context and preserves guest ABI");
}
'''
(out / 'test.c').write_text(prefix + body + suffix)
vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
subprocess.run([str(out / 'test.exe')], cwd=out, check=True)
