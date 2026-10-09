"""Native ABI and semantic checks for the retail MSVC x87 _ftol2 override."""

import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANUAL = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")

def function(source, name):
    found = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    if not found:
        raise RuntimeError(f"Missing actual function {name}")
    return found.group()

body = function(MANUAL, "sub_001C55FC")
assert "converted = (int64_t)input;" in body
assert "g_fp_top = (g_fp_top + 1) & 7;" in body
assert "if (xbox_va == 0x001C55FC) return sub_001C55FC;" in MANUAL

prefix = r'''
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
static uint32_t g_esp, g_eax, g_edx;
static unsigned char memory[256];
static double g_fp_stack[8];
static int g_fp_top;
static volatile uint32_t g_dah2_grid_ftol_calls[4];
static volatile uint64_t g_dah2_grid_ftol_input_bits[4];
static volatile uint32_t g_dah2_grid_ftol_output_lo[4];
static volatile uint32_t g_dah2_grid_ftol_output_hi[4];
#define MEM32(a) (*(uint32_t *)(memory + (uint32_t)(a)))
'''

suffix = r'''
static void check(double input, int64_t expected)
{
    for (int top = 0; top < 8; ++top) {
        g_esp = 0x40; g_fp_top = top; g_fp_stack[top] = input;
        sub_001C55FC();
        assert(g_esp == 0x44);
        assert(g_fp_top == ((top + 1) & 7));
        assert(g_eax == (uint32_t)(uint64_t)expected);
        assert(g_edx == (uint32_t)((uint64_t)expected >> 32));
    }
}
int main(void)
{
    check(0.0, 0); check(3.0, 3); check(3.9, 3); check(-3.9, -3);
    check(2147483648.0, INT64_C(2147483648));
    check(-2147483649.0, INT64_C(-2147483649));
    check(-9223372036854775808.0, INT64_MIN);
    check(INFINITY, INT64_MIN); check(-INFINITY, INT64_MIN); check(NAN, INT64_MIN);
    puts("PASS: retail _ftol2 EDX:EAX and x87-pop/return contracts");
    return 0;
}
'''

vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
with tempfile.TemporaryDirectory(prefix="dah2-ftol-") as temp:
    temp = Path(temp)
    source = temp / "scene_ftol_recovery.c"
    source.write_text(prefix + body + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {source.name} /Fe:scene_ftol_recovery.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=temp, check=True)
    subprocess.run([str(temp / "scene_ftol_recovery.exe")], cwd=temp, check=True, timeout=20)