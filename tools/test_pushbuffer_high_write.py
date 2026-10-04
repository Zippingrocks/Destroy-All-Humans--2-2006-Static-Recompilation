"""Audit retail 24F200 and execute its translated function on high guest memory.

Uses a checked sparse guest-memory test double, not a real emulator or UI.
Only the focused C harness is compiled; this does not rebuild the project.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.recomp import config


def main():
    xbe_path = ROOT / "game_files/default.xbe"
    config.configure_from_xbe(str(xbe_path))
    data = xbe_path.read_bytes()
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)

    def disassemble(start, end):
        section = next(s for s in config._SECTIONS if s.va <= start < s.va + s.raw_size)
        offset = section.raw_addr + start - section.va
        return [(i.mnemonic, i.op_str) for i in decoder.disasm(data[offset:offset + end - start], start)]

    assert disassemble(0x24F200, 0x24F212) == [
        ("mov", "dword ptr [eax], 0x41d84"),
        ("mov", "dword ptr [eax + 4], ecx"),
        ("add", "eax, 8"), ("mov", "dword ptr [esi], eax"),
        ("pop", "esi"), ("ret", "4"),
    ]
    assert disassemble(0x24DE0D, 0x24DE1D) == [
        ("mov", "edx, dword ptr [esp + 0xc]"), ("push", "edx"),
        ("call", "dword ptr [esi*4 + 0x25bf30]"),
        ("pop", "esi"), ("ret", "8"),
    ]
    source = (ROOT / "src/recomp/gen/recomp_0014.c").read_text(encoding="utf-8")
    function = re.search(r"^void sub_0024F1B0\(void\)\n\{.*?^\}", source, re.M | re.S).group()
    caller = (ROOT / "src/recomp/gen/recomp_missing_complete.c").read_text(encoding="utf-8")
    caller = caller[caller.index("loc_0024DE0D: ;"):caller.index("loc_0024DE19: ;")]
    assert "PUSH32(esp, edx);" in caller and "PUSH32(esp, 0x0024DE19u);" in caller

    prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DEVICE 0x86100000u
#define RING 0x86E01000u
#define STACK 0x007FF000u
static uint32_t globals[64], device[64], ring[2048], stack[1024];
static uint32_t eax, ecx, edx, esi, esp;
static unsigned int refill_count;
static uint32_t *word(uint32_t address) {
    if (address & 3u) abort();
    if (address >= 0x25E500u && address < 0x25E600u) return globals + (address - 0x25E500u) / 4;
    if (address >= DEVICE && address < DEVICE + sizeof(device)) return device + (address - DEVICE) / 4;
    if (address >= RING && address < RING + sizeof(ring)) return ring + (address - RING) / 4;
    if (address >= STACK && address < STACK + sizeof(stack)) return stack + (address - STACK) / 4;
    fprintf(stderr, "Unexpected guest address %08X\n", address);
    abort();
}
#define MEM32(a) (*word((uint32_t)(a)))
#define PUSH32(sp,v) do { uint32_t tmp = (v); (sp) -= 4; MEM32(sp) = tmp; } while (0)
#define POP32(sp,v) do { (v) = MEM32(sp); (sp) += 4; } while (0)
#define CMP_B(a,b) ((uint32_t)(a) < (uint32_t)(b))
#define CMP_NE(a,b) ((uint32_t)(a) != (uint32_t)(b))
#define TEST_Z(a,b) (((uint32_t)(a) & (uint32_t)(b)) == 0)
static void sub_00255450(void) {
    if (MEM32(esp) != 0x0024F1CCu) abort();
    ++refill_count;
    MEM32(DEVICE + 4) = RING + 0x1FFCu;
    esp += 4;
}
'''
    suffix = r'''
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)
int main(void) {
    unsigned int value, other, test_enabled, keep_enabled, refill;
    for (value = 0; value != 2; ++value)
    for (other = 0; other != 2; ++other)
    for (test_enabled = 0; test_enabled != 2; ++test_enabled)
    for (keep_enabled = 0; keep_enabled != 2; ++keep_enabled)
    for (refill = 0; refill != 2; ++refill) {
        const uint32_t before_sp = STACK + 0xB00u;
        const uint32_t before_put = RING + 0x814u;
        uint32_t expected = (other ? 2u : 0u) | ((value && (!test_enabled || keep_enabled)) ? 1u : 0u);
        memset(globals, 0, sizeof(globals)); memset(device, 0, sizeof(device));
        memset(ring, 0xA5, sizeof(ring)); memset(stack, 0, sizeof(stack));
        MEM32(0x25E5A8) = DEVICE; MEM32(DEVICE) = before_put;
        MEM32(DEVICE + 4) = refill ? before_put : RING + 0x1FFCu;
        MEM32(0x25E598) = other; MEM32(0x25E550) = test_enabled;
        MEM32(0x25E554) = keep_enabled ? 0x1E00u : 0x1E01u;
        eax = ecx = edx = 0; esi = 0x12345678u; esp = before_sp; refill_count = 0;
        /* Exact 24DE11 argument push and 24DE12 CALL return address. */
        PUSH32(esp, value); PUSH32(esp, 0x0024DE19u);
        sub_0024F1B0();
        CHECK(esp == before_sp && esi == 0x12345678u);
        CHECK(MEM32(0x25E594) == value && refill_count == refill);
        CHECK(MEM32(before_put) == 0x00041D84u && MEM32(before_put + 4) == expected);
        CHECK(MEM32(DEVICE) == before_put + 8 && eax == before_put + 8);
        CHECK(MEM32(before_put - 4) == 0xA5A5A5A5u && MEM32(before_put + 8) == 0xA5A5A5A5u);
    }
    puts("PASS: retail tail/caller audited; high-ring packet, flags, refill path, ESI and RET4 tested across 32 cases");
    return 0;
}
'''
    out = ROOT / "diagnostics/pushbuffer_high_write_test"
    out.mkdir(exist_ok=True)
    (out / "test.c").write_text(prefix + function + suffix, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /W4 /wd4101 /wd4102 /TC test.c /Fe:test.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
    subprocess.run([str(out / "test.exe")], cwd=out, check=True)


if __name__ == "__main__":
    main()
