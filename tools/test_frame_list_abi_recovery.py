"""Execute the actual manual frame-list walk against its retail CALL/RET ABI.

Includes empty, retained, removed, null-object and mixed lists. Historical
missing return-address / RET-4 cleanup mutations must fail this harness.
Only small console test programs run; no game or emulator is launched.
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
section = next(s for s in config._SECTIONS if s.va <= 0x12C9A0 < s.va + s.raw_size)
offset = section.raw_addr + 0x12C9A0 - section.va
retail = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + 0x58], 0x12C9A0))
assert [(i.address, i.mnemonic, i.op_str) for i in retail if i.mnemonic in ("call", "ret")] == [
    (0x12C9B8, "call", "0x12b870"), (0x12C9E9, "call", "dword ptr [edx]"),
    (0x12C9F5, "ret", "4"),
]
source = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_0012C9A0\(void\)\n\{.*?^\}", source, re.M | re.S).group()

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_seh_ebp;
static unsigned char memory[0x10000];
static volatile long g_call_count_C9A0;
static unsigned updates, destroys;
typedef void (*recomp_func_t)(void);
static uint32_t *manual_mem32(uint32_t a) {
    if(a>sizeof(memory)-4) exit(5);
    return (uint32_t *)(memory+a);
}
#define M(a) (*manual_mem32(a))
#define PUSH(v) do { uint32_t pushed=(v); g_esp-=4; M(g_esp)=pushed; } while(0)
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(3); } } while(0)
static long InterlockedIncrement(volatile long *n) { return ++*n; }
static void sub_0012B870(void) {
    CHECK(M(g_esp)==0x12C9BD && M(g_esp+4)==0x3C888889);
    CHECK(g_ecx==0 || (g_ecx>=0x2000 && g_ecx<0x2100));
    ++updates;
    g_eax=g_ecx ? M(g_ecx+4) : 0;
    g_esp+=8;
}
static void destroy(void) {
    CHECK(M(g_esp)==0x12C9EB && M(g_esp+4)==1);
    CHECK(g_ecx>=0x2000 && g_ecx<0x2100);
    CHECK(M(0x1018)==M(0x101C)-destroys-1);
    M(g_ecx+8)=1; ++destroys; g_esp+=8;
}
static recomp_func_t recomp_lookup_manual(uint32_t va) { CHECK(va==0x3210); return destroy; }
static recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
static recomp_func_t recomp_lookup_kernel(uint32_t va) { (void)va; return NULL; }
static void recomp_icall_fail_log(uint32_t va) { (void)va; exit(6); }
'''
suffix = r'''
int main(void) {
    unsigned cases=0;
    for(unsigned count=0;count<=4;++count)
    for(unsigned keep=0;keep<(1u<<count);++keep)
    for(unsigned null_last=0;null_last<2;++null_last) {
        uint32_t sentinel=0x1008, previous=sentinel;
        unsigned retained=0, expected_destroy=0;
        memset(memory,0,sizeof(memory)); updates=destroys=0;
        M(0x4000)=0x3210;
        for(unsigned i=0;i<count;++i) {
            uint32_t node=0x3000+i*16, object=0x2000+i*16;
            M(previous)=node; M(node+4)=previous;
            M(node+8)=(null_last && i==count-1) ? 0 : object;
            M(object)=0x4000; M(object+4)=(keep>>i)&1;
            if(M(node+8) && M(object+4)) ++retained;
            else if(M(node+8)) ++expected_destroy;
            previous=node;
        }
        M(previous)=sentinel; M(sentinel+4)=previous;
        M(0x1018)=count; M(0x101C)=count;
        /* The destructor count assertion includes null removals by deriving
         * its expected count from already-unlinked nodes below instead. */
        g_ecx=0x1000; g_esp=0xF000; g_esi=0x11111111;
        g_edi=0x22222222; g_ebx=0x33333333; g_seh_ebp=0x44444444;
        PUSH(0x3C888889); PUSH(0xF7D65);
        sub_0012C9A0();
        CHECK(g_esp==0xF000);
        CHECK(g_esi==0x11111111 && g_edi==0x22222222 && g_ebx==0x33333333);
        CHECK(updates==count && destroys==expected_destroy && M(0x1018)==retained);
        previous=sentinel;
        for(unsigned i=0;i<count;++i) {
            uint32_t node=0x3000+i*16, object=0x2000+i*16;
            if(((keep>>i)&1) && !(null_last && i==count-1)) {
                CHECK(M(previous)==node && M(node+4)==previous && M(node+8)==object);
                previous=node;
            } else {
                CHECK(M(node)==0 && M(node+4)==0 && M(node+8)==0);
            }
        }
        CHECK(M(previous)==sentinel && M(sentinel+4)==previous);
        ++cases;
    }
    printf("PASS: %u actual C9A0 list paths preserve stack, registers and list links\n",cases);
    return 0;
}
'''
out = ROOT / "diagnostics/frame_list_abi_test"
out.mkdir(exist_ok=True)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
mutants = [
    ("fixed", body, False),
    ("old_ret_cleanup", body.replace("g_esp += 8; return;", "g_esp += 4; return;"), True),
    ("missing_call_ret", body.replace("g_esp -= 4; *manual_mem32(g_esp) = 0x0012C9BDu;", ""), True),
]
for name, implementation, should_fail in mutants:
    (out / f"{name}.c").write_text(prefix + implementation + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=10)
    if should_fail:
        assert result.returncode == 3, result
        print(f"PASS: {name} rejected: " + result.stderr.splitlines()[-1])
    else:
        if result.returncode: print(result.stderr)
        result.check_returncode()
        print(result.stdout, end="")
