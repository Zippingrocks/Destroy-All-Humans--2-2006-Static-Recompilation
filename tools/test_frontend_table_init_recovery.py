"""Validate the tracked retail frontend vector-table initializer and ABI."""

import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / "diagnostics/frontend_table_init_test"
out.mkdir(exist_ok=True)

def generated_body(chunk: str, address: str) -> str:
    source = (root / f"src/recomp/gen/recomp_{chunk}.c").read_text(encoding="utf-8")
    match = re.search(rf"^void sub_{address}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    assert match, address
    return match.group()

manual_source = (root / "src/recomp_manual.c").read_text(encoding="utf-8")
manual_init = re.search(r"^void sub_00223180\(void\)\n\{.*?^\}", manual_source, re.M | re.S)
assert manual_init

source = r'''
#include <assert.h>
#include <stdio.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp,g_seh_head;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x400000];
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
static __forceinline uint32_t *manual_mem32(uint32_t va) { return (uint32_t *)((uintptr_t)g_xbox_mem_offset + va); }
''' + generated_body("0001", "000425A0") + "\n" + manual_init.group() + r'''
int main(void) {
    static const uint32_t expected[16] = {
        0x41000000, 0x40A00000, 0x40400000, 0x40000000,
        0x40400000, 0x40000000, 0x3FC00000, 0x40000000,
        0x3F800000, 0x3FC00000, 0x3F000000, 0x3F800000,
        0x41100000, 0x40A00000, 0x40C00000, 0x40800000,
    };
    memset(memory, 0, sizeof(memory));
    g_xbox_mem_offset = (ptrdiff_t)memory;
    esp = 0x3F0000;
    esi = 0xA1B2C3D4;
    sub_00223180();
    assert(esp == 0x3F0004);
    assert(esi == 0xA1B2C3D4);
    for (unsigned i = 0; i < 16; ++i) assert(MEM32(0x2F1F90 + i * 4) == expected[i]);
    puts("PASS: tracked retail frontend vector table and stack/register ABI recovered");
}
'''

(out / "test.c").write_text(source)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
command = (
    f'call "{vcvars}" >nul && cl /nologo /Od /TC '
    f'/I"{root / "src/recomp"}" /I"{root / "src"}" test.c /Fe:test.exe'
)
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
subprocess.run([str(out / "test.exe")], cwd=out, check=True)