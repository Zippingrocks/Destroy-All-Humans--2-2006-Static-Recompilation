"""Check the retail render-result tail and execute the actual recovered C body.

No emulator/game process is started. The native test checks all modified guest
registers, RET16 cleanup, aligned slot selection, and the complete memory delta.
The historical unresolved RET-only stub must fail the same test.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image = (ROOT / "game_files/default.xbe").read_bytes()
start, end = 0x1593F4, 0x159414
section = next(s for s in config._SECTIONS if s.va <= start < s.va + s.raw_size)
raw = section.raw_addr + start - section.va
instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[raw:raw + end - start], start))
expected = [
    (0x1593F4, "mov", "edx, dword ptr [ecx + 0x1680]"),
    (0x1593FA, "add", "ecx, 0x4c3"),
    (0x159400, "and", "ecx, 0xfffffffc"),
    (0x159403, "mov", "ecx, dword ptr [ecx + edx*4]"),
    (0x159406, "mov", "edx, dword ptr [esp + 8]"),
    (0x15940A, "mov", "dword ptr [ecx + eax*4 + 0x444], edx"),
    (0x159411, "ret", "0x10"),
]
assert [(i.address, i.mnemonic, i.op_str) for i in instructions] == expected
assert instructions[-1].address + instructions[-1].size == end

manual = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
match = re.search(r"^void sub_001593F4\(void\)\n\{.*?^\}", manual, re.M | re.S)
assert match, "Recovered tail missing from manual override"
dispatcher = (ROOT / "src/recomp/gen/recomp_0009.c").read_text(encoding="utf-8")
assert "if (TEST_Z(_fa, _fb)) { g_seh_ebp = ebp; sub_001593F4(); return; }" in dispatcher

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static uint32_t g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
static unsigned char memory[0x20000], expected_memory[0x20000];
static uint32_t *manual_mem32(uint32_t va) { return (uint32_t *)(memory + va); }
'''
suffix = r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 3; } } while(0)
int main(void) {
    unsigned cases = 0;
    for (uint32_t alignment = 0; alignment < 4; ++alignment)
    for (uint32_t slot = 0; slot < 4; ++slot)
    for (uint32_t index = 0; index < 64; index += 7) {
        uint32_t object = 0x1000 + alignment;
        uint32_t table = (object + 0x4C3) & 0xFFFFFFFCu;
        uint32_t result = 0x8000 + slot * 0x800;
        uint32_t destination = result + index * 4 + 0x444;
        uint32_t payload = 0xABCD0000u + cases;
        memset(memory, 0xCD, sizeof(memory));
        g_eax = index; g_ecx = object; g_edx = 0xDEADBEEF; g_esp = 0x1F000;
        g_ebx = 0x11223344; g_esi = 0x55667788; g_edi = 0x99AABBCC; g_ebp = 0x12345678;
        *manual_mem32(object + 0x1680) = slot;
        for (uint32_t entry = 0; entry < 4; ++entry)
            *manual_mem32(table + entry * 4) = 0x8000 + entry * 0x800;
        *manual_mem32(g_esp) = 0x155555;
        *manual_mem32(g_esp + 8) = payload;
        memcpy(expected_memory, memory, sizeof(memory));
        memcpy(expected_memory + destination, &payload, sizeof(payload));
        sub_001593F4();
        CHECK(g_esp == 0x1F014);
        CHECK(g_eax == index && g_ecx == result && g_edx == payload);
        CHECK(g_ebx == 0x11223344 && g_esi == 0x55667788 && g_edi == 0x99AABBCC && g_ebp == 0x12345678);
        CHECK(memcmp(memory, expected_memory, sizeof(memory)) == 0);
        ++cases;
    }
    printf("PASS: %u result-tail cases, retail registers/store/RET16 preserved\n", cases);
    return 0;
}
'''

out = ROOT / "diagnostics/render_result_tail_test"
out.mkdir(exist_ok=True)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, body, failure in [
    ("recovered", match.group(), False),
    ("historical_stub", "void sub_001593F4(void) { g_esp += 4; }", True),
]:
    (out / f"{name}.c").write_text(prefix + body + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=10)
    if failure:
        assert result.returncode == 3, f"Historical stub unexpectedly passed: {result}"
        print("PASS: historical unresolved stub rejected: " + result.stderr.strip())
    else:
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr)
        result.check_returncode()
print("PASS: exact retail tail extent and dispatcher branch verified")
