"""Exercise recovered Lua jump-list append and its real instruction patcher."""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / 'diagnostics/jump_list_test'
out.mkdir(exist_ok=True)
source = (root / 'src/recomp/gen/recomp_0013.c').read_text()
bodies = '\n'.join(re.search(rf'^void sub_{addr}\(void\)\n\{{.*?^\}}', source, re.M | re.S).group()
                   for addr in ('0021CB10', '0021CEF0'))
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi;
RECOMP_TLS uint32_t g_ebp, g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x30000];
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_00215FD0(void) { assert(0); }
static uint32_t jump(unsigned pc, int target) {
    return (((target==-1 ? -1 : target-(int)pc-1)+0x1FFFFFFu)<<6)|0x16;
}
static void prepare(unsigned head, int target) {
    memset(memory,0,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
    esp=0x20000; ecx=0x1000; edx=0x1300;
    ebx=0xABCD1234; esi=0xABCD5678; edi=0xABCD9876;
    MEM32(esp)=0x12345678; MEM32(esp+4)=target;
    MEM32(0x1000)=0x1100; MEM32(0x1118)=0x1200; MEM32(0x1300)=head;
    MEM32(0x1200)=jump(0,-1); MEM32(0x1208)=jump(2,-1);
}
static void check(void) {
    assert(esp==0x20008 && ebx==0xABCD1234 && esi==0xABCD5678 && edi==0xABCD9876);
}
'''
suffix = r'''
int main(void) {
    prepare(0xFFFFFFFF,4); sub_0021CEF0(); check(); assert(MEM32(0x1300)==4);
    prepare(0,4); sub_0021CEF0(); check(); assert(MEM32(0x1200)==jump(0,4));
    prepare(0,5); MEM32(0x1200)=jump(0,2); sub_0021CEF0(); check();
    assert(MEM32(0x1200)==jump(0,2) && MEM32(0x1208)==jump(2,5));
    prepare(0,-1); sub_0021CEF0(); check(); assert(MEM32(0x1200)==jump(0,-1));
    puts("PASS: empty, single, chained, and sentinel jump lists preserve stack/registers and patch real bytecode");
    return 0;
}
'''
(out / 'test.c').write_text(prefix+bodies+suffix)
vcvars=Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command=f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
subprocess.run([str(out/'test.exe')],cwd=out,check=True)
