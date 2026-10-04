"""Test the recovered delimiter-match body's two successful return paths.

Uses the real generated function and stack macros. Lexer and error helpers
are test doubles; this is not a complete parser or game stability test.
"""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / "diagnostics/parser_match_test"
out.mkdir(exist_ok=True)
source = (root / "src/recomp/gen/recomp_0013.c").read_text()
body = re.search(r"^void sub_00219810\(void\)\n\{.*?^\}", source, re.M | re.S).group()
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi;
RECOMP_TLS uint32_t g_ebp, g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x30000];
static unsigned lex_calls;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_00215E30(void) { assert(0); }
void sub_001C5DAD(void) { assert(0); }
void sub_0021CB00(void) { assert(0); }
void sub_00216A70(void) {
    assert(ecx==0x1000 && edx==0x1008);
    ++lex_calls; MEM32(edx)=0x1234; eax=0x107; esp+=4;
}
static void prepare(void) {
    memset(memory,0,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
    esp=0x20000; ecx=0x7D; esi=0x1000; edi=1; ebx=0x5555;
    MEM32(esp)=0x12345678; MEM32(esp+4)=0x7B;
    MEM32(esi+4)=0x7D; MEM32(esi+0x20)=1;
}
'''
suffix = r'''
int main(void) {
    prepare(); MEM32(0x100C)=0x107; MEM32(0x1010)=0x5678;
    sub_00219810();
    assert(esp==0x20008 && esi==0x1000 && edi==1 && ebx==0x5555);
    assert(MEM32(0x1004)==0x107 && MEM32(0x1008)==0x5678);
    assert(MEM32(0x100C)==0x11C && MEM32(0x1024)==1 && !lex_calls);
    prepare(); MEM32(0x100C)=0x11C; sub_00219810();
    assert(esp==0x20008 && esi==0x1000 && edi==1 && ebx==0x5555);
    assert(MEM32(0x1004)==0x107 && MEM32(0x1008)==0x1234 && lex_calls==1);
    puts("PASS: delimiter matching advances tokens and restores guest stack on both success paths");
    return 0;
}
'''
(out / "test.c").write_text(prefix + body + suffix)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
subprocess.run([str(out / "test.exe")], cwd=out, check=True)
