"""Exercise actual allocator/probe bodies against an explicit kernel test double.

The double checks the retail MmAllocateContiguousMemoryEx arguments and guest
return address, consumes the real stdcall stack layout, and enforces a finite
capacity. No game process, emulator, or desktop window is started.
--prove-regression also verifies that each historical omitted-push defect fails.
"""
import argparse
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--prove-regression", action="store_true")
args = parser.parse_args()
out = root / "diagnostics" / "allocator_abi_test"
out.mkdir(exist_ok=True)
manual = (root / "src/recomp_manual.c").read_text(encoding="utf-8")
generated = (root / "src/recomp/gen/recomp_0006.c").read_text(encoding="utf-8")


def function(source, name):
    match = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    if not match:
        raise RuntimeError(f"Missing actual function {name}")
    return match.group()


wrapper = function(manual, "sub_000FCB03")
probe = function(manual, "sub_001397F0")
physical_alloc = function(generated, "sub_000FB0A1")
macros = manual[manual.index("#define eax g_eax"):manual.index("void sub_0015E740(void)")]

prefix = r'''
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <crtdbg.h>
typedef void (*recomp_func_t)(void);
__declspec(thread) uint32_t g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
static unsigned char memory[0x400000];
static __forceinline uint32_t *manual_mem32(uint32_t va) {
    assert(va <= sizeof(memory) - 4); return (uint32_t *)(memory + va);
}
static volatile long g_call_count_FCB03;
int g_manual_transplant_icall_trace;
recomp_func_t recomp_lookup_manual(uint32_t);
recomp_func_t recomp_lookup(uint32_t);
recomp_func_t recomp_lookup_kernel(uint32_t);
void recomp_icall_fail_log(uint32_t);
void sub_000FAFD5(void);
void sub_000FCB73(void);
void sub_000FCB46(void);
void sub_000FCAC8(void);
#define XBOX_PTR(va) ((uintptr_t)memory + (uint32_t)(va))
'''

suffix = r'''
static uint32_t capacity, expected_size, expected_low, expected_high, expected_align, expected_prot;
static unsigned calls, allocations, frees, errors;
static int probe_mode;
static void allocator_kernel_double(void) {
    /* Match kernel_thunk_dispatch: pop return address, read args, ret 20. */
    assert(MEM32(esp) == 0x000FCB32u);
    esp += 4;
    uint32_t size = MEM32(esp), low = MEM32(esp + 4), high = MEM32(esp + 8);
    uint32_t align = MEM32(esp + 12), prot = MEM32(esp + 16);
    assert(++calls < 2000);
    if (probe_mode) {
        assert(size >= 2 && low == 0 && high == 0xFFFFFFFFu && align == 0x1000 && prot == 4);
        if (calls <= 2 && capacity >= 4) assert(size == (calls == 1 ? 2u : 4u));
    } else {
        assert(size == expected_size && low == expected_low && high == expected_high);
        assert(align == expected_align && prot == expected_prot);
    }
    eax = size <= capacity ? 0x00380000u : 0;
    if (eax) ++allocations;
    esp += 20;
}
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_kernel(uint32_t va) {
    assert(va == 0xFE000000u); return allocator_kernel_double;
}
void recomp_icall_fail_log(uint32_t va) { (void)va; assert(0); }
void sub_000FAFD5(void) {
    assert(MEM32(esp) == 0x000FCB3Fu && MEM32(esp + 4) == 8);
    ++errors; esp += 8;
}
void sub_000FCB73(void) {
    assert(MEM32(esp) == 0x00139829u && MEM32(esp + 4) == 0x00380000u);
    ++frees; esp += 8;
}
void sub_000FCB46(void) { assert(0); }
void sub_000FCAC8(void) { assert(0); }
static void setup(void) {
    memset(memory, 0, sizeof(memory));
    esp = 0x00200000; ebx = 0x11112222; esi = 0x33334444; edi = 0x55556666; g_ebp = 0x00210000;
    MEM32(0x29B5E0) = 0xFE000000u;
    /* The descriptor's protection-table lookup is part of the real body. */
    MEM32(0x2C84E4 + 2 * 4) = 4;
    MEM32(0x2C84E4 + 3 * 4) = 0x404;
    calls = allocations = frees = errors = 0; probe_mode = 0;
}
static void preserved(void) {
    assert(esp == 0x00200000 && ebx == 0x11112222 && esi == 0x33334444 && edi == 0x55556666);
}
static void check_wrapper(uint32_t size, uint32_t address, uint32_t limit) {
    setup(); capacity = limit;
    expected_size = size; expected_low = address == 0xFFFFFFFFu ? 0 : address;
    expected_high = address == 0xFFFFFFFFu ? 0xFFFFFFFFu : address + size - 1;
    expected_align = address == 0xFFFFFFFFu ? 0x1000 : 0; expected_prot = 4;
    PUSH32(esp, 4); PUSH32(esp, 0x1000); PUSH32(esp, address); PUSH32(esp, size);
    PUSH32(esp, 0x00139814u); sub_000FCB03();
    preserved(); assert(g_ebp == 0x00210000 && calls == 1);
    assert(eax == (size <= limit ? 0x00380000u : 0));
    assert(errors == (size > limit ? 1u : 0u));
}
static void check_descriptor(uint32_t size, uint32_t descriptor, uint32_t protection) {
    setup(); capacity = 0x04000000;
    expected_size = size; expected_low = 0; expected_high = 0xFFFFFFFFu;
    expected_align = 0x1000; expected_prot = protection;
    /* This is the real device-init caller's exact allocation convention. */
    PUSH32(esp, descriptor); PUSH32(esp, size); PUSH32(esp, 0x00254595u);
    sub_000FB0A1(); preserved(); assert(calls == 1 && errors == 0 && eax == 0x00380000u);
}
static void check_probe(uint32_t limit, int must_exceed_old_cap) {
    setup(); capacity = limit; probe_mode = 1;
    PUSH32(esp, 0x12345678u); sub_001397F0(); preserved();
    /* Retail searches in two-byte steps and returns the final odd boundary. */
    assert(eax == (limit | 1u));
    assert(allocations == frees && errors > 0);
    if (must_exceed_old_cap) assert(calls > 64);
    printf("PASS: capacity %u, %u probes, guest stack and saved registers preserved\n", limit, calls);
}
int main(int argc, char **argv) {
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc > 1 && strcmp(argv[1], "probe") == 0) { check_probe(0x7FFDu, 1); return 0; }
    check_wrapper(0x800, 0xFFFFFFFFu, 0x4000000);
    if (argc > 1) return 0;
    check_wrapper(0x800, 0x100000, 0x4000000);
    check_wrapper(0x800, 0xFFFFFFFFu, 0);
    check_descriptor(0x60, 0xAC800000u, 4);
    check_descriptor(0x200000, 0xBC800000u, 0x404);
    check_probe(0, 0); check_probe(1, 0); check_probe(2, 0); check_probe(3, 0);
    check_probe(0x1000, 0); check_probe(0x7FFDu, 1); check_probe(0x03FFFFFDu, 1);
    puts("PASS: 3 allocator contracts, 2 device descriptor paths, 7 finite capacity probes");
    return 0;
}
'''

vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")


def compile_and_run(name, wrapper_body, probe_body, mode=None, expected_failure=False):
    source = out / f"{name}.c"
    source.write_text(prefix + macros + wrapper_body + "\n" + probe_body + "\n" + physical_alloc + suffix,
                      encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
    result = subprocess.run([str(out / f"{name}.exe")] + ([mode] if mode else []),
                            cwd=out, capture_output=True, text=True, timeout=20)
    if expected_failure:
        if result.returncode == 0:
            raise AssertionError(f"Historical defect unexpectedly passed: {name}")
        print(f"PASS: regression detector rejected {name} (exit {result.returncode})")
        print(result.stderr[-600:].strip())
    else:
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr)
        result.check_returncode()


compile_and_run("allocator_abi", wrapper, probe)
if args.prove_regression:
    broken_wrapper = wrapper.replace("        PUSH32(esp, 0x000FCB32u);\n", "")
    broken_wrapper = broken_wrapper.replace("        PUSH32(esp, 0x000FCB3Fu);\n", "")
    compile_and_run("missing_kernel_return", broken_wrapper, probe, "wrapper", True)
    broken_probe = probe
    for omitted in ["4", "0x1000", "0xFFFFFFFFu", "eax", "0x00139814u", "0x00139829u"]:
        # Omit only the first eax push (allocation arg); free still pushes eax.
        broken_probe = broken_probe.replace(f"    PUSH32(esp, {omitted});\n", "", 1)
    compile_and_run("missing_probe_arguments", wrapper, broken_probe, "probe", True)
