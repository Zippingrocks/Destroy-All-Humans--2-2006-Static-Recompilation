"""Test actual recovered tree insertion; allocator is a deterministic double."""
import re
import subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
out = root / 'diagnostics/tree_insert_test'
out.mkdir(exist_ok=True)
source = (root / 'src/recomp/gen/recomp_0001.c').read_text()
body = re.search(r'^void sub_0003A870\(void\)\n\{.*?^\}', source, re.M | re.S).group()
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x30000];
static unsigned allocations;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_000F96C0(void) { assert(MEM32(esp+4)==20); eax=0x4000+allocations++*32; esp+=4; }
'''
suffix = r'''
static void insert(unsigned key) {
    esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
    MEM32(esp+4)=0x2000; MEM32(esp+8)=0x3000; MEM32(esp+12)=0x5678; MEM32(0x3000)=key;
    sub_0003A870();
    assert(esp==0x20010 && esi==0xABC && edi==0xDEF && ebx==0x123);
}
int main(void) {
    g_xbox_mem_offset=(ptrdiff_t)memory;
    insert(10); assert(allocations==1 && MEM32(0x1000)==0x4000 && MEM32(0x2000)==0x4000);
    assert(MEM32(0x400C)==10 && MEM32(0x4010)==0x5678 && MEM32(0x102C)==1);
    insert(10); assert(allocations==1 && MEM32(0x2000)==0x1018 && MEM32(0x102C)==1);
    insert(5); assert(allocations==2 && MEM32(0x4000)==0x4020 && MEM32(0x402C)==5);
    insert(20); assert(allocations==3 && MEM32(0x4004)==0x4040 && MEM32(0x404C)==20);
    assert(MEM32(0x102C)==3);
    puts("PASS: empty, duplicate, left and right insertion preserve original node links, values and ABI");
}
'''
(out/'test.c').write_text(prefix+body+suffix)
vcvars=Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command=f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
subprocess.run([str(out/'test.exe')],cwd=out,check=True)
