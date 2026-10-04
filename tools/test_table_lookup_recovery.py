"""Exercise recovered table-lookup control flow and ABI with helper doubles."""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / 'diagnostics/table_lookup_test'
out.mkdir(exist_ok=True)
source = (root / 'src/recomp/gen/recomp_0013.c').read_text()
body = re.search(r'^void sub_002185E0\(void\)\n\{.*?^\}', source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_00217380\(void\)\n\{.*?^\}', source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_002181C0\(void\)\n\{.*?^\}', source, re.M | re.S).group()
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
RECOMP_TLS RecompXmm g_xmm0,g_xmm1;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x300000];
#undef RECOMP_ITAIL
#define RECOMP_ITAIL(target) assert(0)
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_002173F0(void) {
    assert(ecx==0x1000 && edx==0x3000 && MEM32(esp+4)==0x1FF8);
    eax=0x5000; esp+=8;
}
void sub_00212580(void) { assert(0); }
void sub_002115F0(void) { assert(0); }
void sub_00211810(void) { assert(0); }
void sub_00212D40(void) { assert(0); }
'''
suffix = r'''
static void check(unsigned subtype, unsigned result_type) {
    memset(memory,0,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
    esp=0x20000; ecx=0x1000; edx=0x1100;
    esi=0xABC; edi=0xDEF; ebx=0x123;
    MEM32(esp)=0x12345678; MEM32(0x1000)=0x2000; MEM32(0x1048)=0x4000;
    MEM32(0x1100)=4; MEM32(0x1104)=0x3000; MEM32(0x3004)=subtype;
    MEM32(0x5000)=result_type;
    sub_002185E0();
    assert(eax==0x5000 && esp==0x20004 && esi==0xABC && edi==0xDEF && ebx==0x123);
}
int main(void) {
    check(4,3); check(4,1); check(3,3); check(3,1);
    for (unsigned i=0;i<4;++i) {
        memset(memory,0,sizeof(memory));
        esp=0x20000; ecx=0x1000;
        MEM32(0x1000)=0x2000; MEM32(0x1008)=4;
        MEM32(0x2014)=2; MEMF(0x2018)=1.0f;
        MEMF(esp+4)=i==0?1.0f:(i==1?1.5f:5.0f);
        if (i==2) { MEM32(0x2024)=0x2100; MEM32(0x2100)=2; MEMF(0x2104)=5.0f; }
        if (i==3) MEM32(0x2018)=0x7FC00000; /* unordered candidate must not match */
        sub_00217380();
        assert(esp==0x20008 && eax==(i==0?0x201C:(i==2?0x2108:0x2C025C)));
    }
    puts("PASS: numeric lookup equality, inequality, collision chain, and unordered comparison");
    for (unsigned i=0;i<5;++i) {
        esp=0x20000; ecx=0x1000; edx=0x1100; esi=0xABC;
        MEM32(0x218204)=0x2181D7;
        MEM32(ecx)=MEM32(edx)=2;
        MEMF(ecx+4)=i==4?-0.0f:1.0f;
        MEMF(edx+4)=i==0?1.0f:(i==1?2.0f:0.0f);
        if (i==3) MEM32(edx+4)=0x7FC00000;
        sub_002181C0();
        assert(esp==0x20004 && esi==0xABC && eax==(i==0 || i==4));
    }
    puts("PASS: VM numeric equality, less/greater inequality, NaN, and signed zero");
    puts("PASS: plain table lookups, found and nil values, preserve stack and saved registers");
}
'''
(out / 'test.c').write_text(prefix + body + suffix)
vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
subprocess.run([str(out / 'test.exe')], cwd=out, check=True)
