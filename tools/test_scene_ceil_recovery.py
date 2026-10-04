"""Native ABI and semantic checks for the retail x87 ceil override.

The test extracts the actual manual ``sub_001C6A27`` body, executes it with
the guest stack layout used by ``sub_0013C410``, and verifies the cdecl return
contract plus the shared eight-entry x87 stack model. No game, emulator,
window, or desktop is started.
"""

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

body = function(MANUAL, "sub_001C6A27")
assert "g_fp_stack[g_fp_top] = ceil(input);" in body
assert "g_esp += 4" in body
assert "if (xbox_va == 0x001C6A27) return sub_001C6A27;" in MANUAL

prefix = r'''
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static uint32_t g_esp;
static unsigned char memory[256];
static double g_fp_stack[8];
static int g_fp_top;
#define MEM32(a) (*(uint32_t *)(memory + (uint32_t)(a)))
'''

suffix = r'''
static void check(double input, double expected)
{
    uint64_t bits;
    int old_top;
    memset(memory, 0xCD, sizeof(memory));
    for (int i = 0; i < 8; ++i) g_fp_stack[i] = 1000.0 + i;
    for (int initial_top = 0; initial_top < 8; ++initial_top) {
        g_esp = 0x40;
        g_fp_top = initial_top;
        MEM32(g_esp) = 0x0013C46D;
        memcpy(&bits, &input, sizeof(bits));
        MEM32(g_esp + 4) = (uint32_t)bits;
        MEM32(g_esp + 8) = (uint32_t)(bits >> 32);
        old_top = g_fp_top;
        sub_001C6A27();
        assert(g_esp == 0x44);
        assert(g_fp_top == ((old_top + 7) & 7));
        if (isnan(expected)) assert(isnan(g_fp_stack[g_fp_top]));
        else {
            assert(g_fp_stack[g_fp_top] == expected);
            if (expected == 0.0) assert(signbit(g_fp_stack[g_fp_top]) == signbit(expected));
        }
    }
}
int main(void)
{
    check(0.11547005383792515, 1.0);
    check(0.0, 0.0); check(-0.0, -0.0); check(1.0, 1.0);
    check(1.0000000000000002, 2.0); check(-0.1, -0.0); check(-1.1, -1.0);
    check(4503599627370495.5, 4503599627370496.0);
    check(INFINITY, INFINITY); check(-INFINITY, -INFINITY); check(NAN, NAN);
    puts("PASS: retail ceil result and cdecl/x87 stack contracts");
    return 0;
}
'''

vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
with tempfile.TemporaryDirectory(prefix="dah2-ceil-") as temp:
    temp = Path(temp)
    source = temp / "scene_ceil_recovery.c"
    source.write_text(prefix + body + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {source.name} /Fe:scene_ceil_recovery.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=temp, check=True)
    subprocess.run([str(temp / "scene_ceil_recovery.exe")], cwd=temp, check=True, timeout=20)