"""Exercise the actual recovered heap-free body and runtime stack macros.

The coalescer and bin-index helper are test doubles; this validates argument
passing, all recovered return paths, bin insertion, and saved registers, not
the complete allocator or game. Generated test artifacts stay in diagnostics.
"""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / "diagnostics/heap_recovery_test"
out.mkdir(exist_ok=True)
source = (root / "src/recomp/gen/recomp_0008.c").read_text()
body = re.search(r"^void sub_0013FFC0\(void\)\n\{.*?^\}", source, re.M | re.S).group()
body += '\n' + re.search(r"^void sub_0013FD30\(void\)\n\{.*?^\}", source, re.M | re.S).group()
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi;
RECOMP_TLS uint32_t g_ebp, g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x30000];
static unsigned merges, merge_mode, bin_calls;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_0013FD6B(void) { assert(0); } /* nonempty allocation not exercised here */
void sub_0013FA20(void) { assert(eax == 0x40 || eax == 0x6C); eax=2; ++bin_calls; esp+=4; }
void sub_0013FAB0(void) {
    uint32_t left=MEM32(esp+4), right=MEM32(esp+8), mode=MEM32(esp+12);
    assert(ecx == 0x1000);
    if (mode == 0) { assert(left==0x2000 && right==0x204C); MEM32(left+4)=0x6D; }
    else { assert(mode==1 && left==0x1F00 && right==0x2000); }
    merge_mode=mode; ++merges; esp+=16;
}
static void prepare(void) {
    memset(memory,0,sizeof(memory));
    g_xbox_mem_offset=(ptrdiff_t)memory;
    g_esp=0x20000; g_esi=0xABCDEF01; g_edi=0xABCDE002; g_ebx=0xABCD0003;
    g_ebp=g_seh_ebp=0xAB000004;
    MEM32(0x20000)=0x12345678; MEM32(0x20004)=0x200C;
    MEM32(0x2004)=0x40; MEM32(0x2008)=0x1000;
    MEM32(0x1008)=0x2200;
    MEM32(0x1010)=7; MEM32(0x101C)=0x1200;
    MEM32(0x2050)=0x20;
    merges=bin_calls=0; merge_mode=99;
}
static void check_abi(void) {
    assert(g_esp==0x20008 && g_esi==0xABCDEF01 && g_edi==0xABCDE002 && g_ebx==0xABCD0003);
}
'''
suffix = r'''
int main(void) {
    prepare(); ecx=0x1000; MEM32(0x1004)=0;
    MEM32(0x20004)=193; MEM32(0x20008)=16; MEM32(0x2000C)=0;
    sub_0013FD30();
    assert(eax==0 && esp==0x20010 && esi==0xABCDEF01 && edi==0xABCDE002 && ebx==0xABCD0003);
    prepare(); MEM32(0x20004)=0; sub_0013FFC0(); check_abi(); assert(!merges && !bin_calls);
    prepare(); sub_0013FFC0(); check_abi();
    assert(!merges && bin_calls==1 && MEM32(0x101C)==0x2000 && MEM32(0x200C)==0x1200 && MEM32(0x1010)==0x47);
    prepare(); MEM32(0x2050)|=1; sub_0013FFC0(); check_abi();
    assert(merges==1 && merge_mode==0 && bin_calls==1 && MEM32(0x1010)==0x73);
    prepare(); MEM32(0x2000)=0x1F00; MEM32(0x1F04)=0x41;
    sub_0013FFC0(); check_abi(); assert(merges==1 && merge_mode==1 && !bin_calls);
    prepare(); MEM32(0x1008)=0x204C; sub_0013FFC0(); check_abi(); assert(!merges && bin_calls==1);
    puts("PASS: empty-heap allocation and five heap-free return paths preserve guest ESP and saved registers");
    return 0;
}
'''
(out / "test.c").write_text(prefix + body + suffix)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
subprocess.run([str(out / "test.exe")], cwd=out, check=True)
