"""Regression for DAH2's factory EEPROM AV-region query.

Compiles the actual kernel query function against the actual kernel header.
Tests include the historical missing-case mutant, guarded buffers, metadata,
short lengths, optional outputs, null values, and unchanged existing settings.
Also checks the retail XBE instructions that turn the region byte into video
mode initialization. No emulator/game process is started.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.recomp import config

XBE = ROOT / "game_files/default.xbe"
config.configure_from_xbe(str(XBE))
image = XBE.read_bytes()
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
retail_contract = {
    0x1CE518: ("push", "0x103"),
    0x1CE51D: ("call", "0xff514"),
    0x1CE526: ("movzx", "eax, byte ptr [ebp - 3]"),
    0x15B65A: ("call", "0x1ce507"),
    0x15B666: ("je", "0x15b6bd"),
    0x15B66B: ("je", "0x15b6bd"),
    0x15B6C5: ("mov", "dword ptr [esi + 0x238], 2"),
    0x15B6CF: ("mov", "dword ptr [esi + 0x228], 0x280"),
    0x15B6D9: ("mov", "dword ptr [esi + 0x230], eax"),
    0x15B6DF: ("mov", "dword ptr [esi + 0x22c], eax"),
    0x15B715: ("neg", "eax"),
    0x15B717: ("sbb", "eax, eax"),
    0x15B719: ("and", "eax, 0xa"),
    0x15B71C: ("add", "eax, 0x32"),
}
for address, expected in retail_contract.items():
    section = next(s for s in config._SECTIONS if s.va <= address < s.va + s.raw_size)
    offset = section.raw_addr + address - section.va
    instruction = next(decoder.disasm(image[offset:offset + 16], address))
    assert (instruction.mnemonic, instruction.op_str) == expected, hex(address)
print("PASS: retail region query, NTSC 640x480 branch, and 50/60 Hz selection instructions")

reference = ROOT / "diagnostics/codex_parity_20260925/xemu/eeprom.bin"
if reference.exists():
    with reference.open("rb") as stream:
        stream.seek(0x58)
        region = int.from_bytes(stream.read(4), "little")
    assert region == 0x00400100, f"Reference EEPROM profile changed: 0x{region:08X}"
    print("PASS: factory AV-region default matches private xemu EEPROM DWORD 0x58")

source = (ROOT / "xboxrecomp/src/kernel/kernel_xbox.c").read_text(encoding="utf-8")
match = re.search(
    r"^NTSTATUS __stdcall xbox_ExQueryNonVolatileSetting\(.*?^\}",
    source, re.M | re.S,
)
assert match, "Actual kernel query function not found"
actual = match.group()
historical, removed = re.subn(
    r"    case XC_FACTORY_AV_REGION:\n.*?        break;\n\n", "", actual,
    count=1, flags=re.S,
)
assert removed == 1, "Factory AV-region implementation missing"
historical = historical.replace(
    "xbox_ExQueryNonVolatileSetting(", "historical_ExQueryNonVolatileSetting(", 1
)

prefix = r'''
#include "kernel/kernel.h"
#include <stdio.h>
#include <string.h>
void xbox_log(int level, const char *subsystem, const char *format, ...) {
    (void)level; (void)subsystem; (void)format;
}
'''
harness = r'''
#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 3; \
} } while (0)

typedef NTSTATUS (__stdcall *QUERY)(ULONG, PULONG, PVOID, ULONG, PULONG);
typedef union { ULONG alignment; unsigned char bytes[40]; } GUARDED;

int main(int argc, char **argv) {
    QUERY query = argc > 1 && strcmp(argv[1], "historical") == 0
        ? historical_ExQueryNonVolatileSetting : xbox_ExQueryNonVolatileSetting;
    ULONG value = 0xCDCDCDCD, type = 0xDEADBEEF, length = 0xCAFEAABB;
    unsigned tests = 0;
    CHECK(sizeof(ULONG) == 4 && XC_FACTORY_AV_REGION == 0x103);
    CHECK(query(XC_FACTORY_AV_REGION, &type, &value, 4, &length) == STATUS_SUCCESS);
    CHECK(value == 0x00400100 && type == 4 && length == 4);
    CHECK(((unsigned char *)&value)[1] == 1); /* Retail XGetVideoStandard. */

    for (ULONG bytes = 0; bytes <= 12; ++bytes) {
        for (unsigned outputs = 0; outputs < 4; ++outputs) {
            GUARDED buffer, expected;
            NTSTATUS status;
            memset(buffer.bytes, 0xCD, sizeof(buffer.bytes));
            memset(expected.bytes, 0xCD, sizeof(expected.bytes));
            type = 0xDEADBEEF; length = 0xCAFEAABB;
            status = query(XC_FACTORY_AV_REGION,
                           (outputs & 1) ? &type : NULL,
                           buffer.bytes + 8, bytes,
                           (outputs & 2) ? &length : NULL);
            CHECK(length == ((outputs & 2) ? 4u : 0xCAFEAABBu));
            if (bytes < 4) {
                CHECK(status == STATUS_BUFFER_TOO_SMALL);
                CHECK(type == 0xDEADBEEF);
            } else {
                ULONG expected_region = 0x00400100;
                CHECK(status == STATUS_SUCCESS);
                CHECK(type == ((outputs & 1) ? 4u : 0xDEADBEEFu));
                memcpy(expected.bytes + 8, &expected_region, sizeof(expected_region));
            }
            CHECK(memcmp(buffer.bytes, expected.bytes, sizeof(buffer.bytes)) == 0);
            ++tests;
        }
    }
    for (ULONG bytes = 0; bytes <= 8; ++bytes) {
        type = 0xDEADBEEF; length = 0xCAFEAABB;
        CHECK(query(XC_FACTORY_AV_REGION, &type, NULL, bytes, &length)
              == STATUS_INVALID_PARAMETER);
        CHECK(type == 0xDEADBEEF && length == 0xCAFEAABB);
        ++tests;
    }

    /* The only behavioral change is the newly supported factory index. */
    {
        const ULONG indices[] = {
            XC_LANGUAGE, XC_VIDEO, XC_AUDIO, XC_P_CONTROL_GAMES,
            XC_P_CONTROL_MOVIES, XC_DVD_REGION, XC_MISC, XC_TIMEZONE_BIAS, 0xDEAD
        };
        for (unsigned index = 0; index < sizeof(indices) / sizeof(indices[0]); ++index) {
            for (ULONG bytes = 0; bytes <= 12; ++bytes) {
                GUARDED fixed, old;
                ULONG fixed_type = 0xDEADBEEF, old_type = 0xDEADBEEF;
                ULONG fixed_length = 0xCAFEAABB, old_length = 0xCAFEAABB;
                NTSTATUS fixed_status, old_status;
                memset(fixed.bytes, 0xCD, sizeof(fixed.bytes));
                memset(old.bytes, 0xCD, sizeof(old.bytes));
                fixed_status = xbox_ExQueryNonVolatileSetting(
                    indices[index], &fixed_type, fixed.bytes + 8, bytes, &fixed_length);
                old_status = historical_ExQueryNonVolatileSetting(
                    indices[index], &old_type, old.bytes + 8, bytes, &old_length);
                CHECK(fixed_status == old_status);
                CHECK(fixed_type == old_type && fixed_length == old_length);
                CHECK(memcmp(fixed.bytes, old.bytes, sizeof(fixed.bytes)) == 0);
                ++tests;
            }
        }
    }
    printf("PASS: %u native EEPROM cases; metadata, lengths 0..12, guards, optional outputs, null Value, and old settings\n", tests);
    return 0;
}
'''
out = ROOT / "diagnostics/eeprom_av_region_test"
out.mkdir(exist_ok=True)
(out / "native_query.c").write_text(
    prefix + actual + "\n" + historical + "\n" + harness, encoding="utf-8"
)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
include = ROOT / "xboxrecomp/src"
command = (
    f'call "{vcvars}" >nul && cl /nologo /Od /TC '
    f'/I"{include}" native_query.c /Fe:native_query.exe'
)
subprocess.run(
    'cmd.exe /d /s /c "' + command + '"', cwd=out, check=True,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
for mode, expected_code in [([], 0), (["historical"], 3)]:
    result = subprocess.run(
        [str(out / "native_query.exe"), *mode], capture_output=True, text=True,
        timeout=10, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == expected_code, (mode, result.returncode, result.stdout, result.stderr)
    if mode:
        assert "value == 0x00400100" in result.stderr
        print("PASS: historical missing-case implementation rejected: " + result.stderr.strip())
    else:
        print(result.stdout, end="")
