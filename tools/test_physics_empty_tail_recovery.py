"""Verify retail F360B epilogue with the actual generated F3470 caller.

The historical unresolved tail must reproduce the observed 0x198-byte leak.
Only a small console harness is compiled and executed.
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
section = next(s for s in config._SECTIONS if s.va <= 0xF360B < s.va + s.raw_size)
offset = section.raw_addr + 0xF360B - section.va
instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + 11], 0xF360B))
assert [(i.mnemonic, i.op_str) for i in instructions] == [
    ("pop", "edi"), ("pop", "esi"), ("pop", "ebp"), ("pop", "ebx"),
    ("add", "esp, 0x188"), ("ret", ""),
]

def extract(path, name):
    text = (ROOT / path).read_text(encoding="utf-8")
    return re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", text, re.M | re.S).group()

fixed = extract("src/recomp_manual.c", "sub_000F360B")
caller = extract("src/recomp/gen/recomp_0006.c", "sub_000F3470")
assert "sub_000F360B(); return;" in caller
prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_ebp,g_seh_ebp;
static unsigned char memory[0x10000];
static uint32_t *manual_mem32(uint32_t a) {
    if(a>sizeof(memory)-4) exit(5);
    return (uint32_t *)(memory+a);
}
#define MEM32(a) (*manual_mem32((uint32_t)(a)))
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define esi g_esi
#define edi g_edi
#define ebx g_ebx
#define PUSH32(sp,v) do { uint32_t pushed=(v); (sp)-=4; MEM32(sp)=pushed; } while(0)
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define TEST_Z(a,b) (((a)&(b))==0)
#define LO8(v) ((v)&255)
#define RECOMP_ICALL_SAFE(a,b) do { exit(6); } while(0)
#define UNREACHED(name) void name(void) { exit(7); }
UNREACHED(sub_0019E6E0)
UNREACHED(sub_000F35CE)
UNREACHED(sub_000F35B4)
UNREACHED(sub_0002FC50)
UNREACHED(sub_00042290)
'''
suffix = r'''
int main(int argc,char **argv) {
    unsigned cases=0;
    (void)argv;
    for(unsigned alignment=0;alignment<4;++alignment)
    for(unsigned marker=1;marker<=16;++marker) {
        uint32_t object=0x1000+alignment;
        memset(memory,0,sizeof(memory));
        esp=0xF000; eax=0xAA; ecx=object; edx=0xDD;
        esi=0x11110000+marker; edi=0x22220000+marker;
        ebx=0x33330000+marker; g_ebp=g_seh_ebp=0x44440000+marker;
        PUSH32(esp,0x18C44C);
        sub_000F3470();
        if(argc>1) {
            printf("HISTORICAL: stack leak=%X bytes\n",0xF000-esp);
            return esp==0xF000-0x198 ? 0 : 4;
        }
        if(esp!=0xF000 || esi!=0x11110000+marker || edi!=0x22220000+marker ||
           ebx!=0x33330000+marker || g_ebp!=0x44440000+marker || g_seh_ebp!=g_ebp) {
            fprintf(stderr,"FAIL: stack/register restoration, esp=%X\n",esp); return 3;
        }
        if(eax!=((object+0x44FF)&~3u) || ecx!=0 || edx!=0xDD) return 4;
        ++cases;
    }
    printf("PASS: %u actual F3470 empty-array paths preserve retail frame/registers\n",cases);
    return 0;
}
'''
out = ROOT / "diagnostics/physics_empty_tail_test"
out.mkdir(exist_ok=True)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, tail in [("fixed", fixed), ("historical", "void sub_000F360B(void) { g_esp+=4; }")]:
    (out / f"{name}.c").write_text(prefix + tail + caller + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=10)
    if name == "historical":
        assert result.returncode == 3, result
        leak = subprocess.run([str(out / f"{name}.exe"), "leak"], capture_output=True, text=True, timeout=10)
        leak.check_returncode()
        print("PASS: historical tail rejected; " + leak.stdout.strip())
    else:
        if result.returncode: print(result.stderr)
        result.check_returncode()
        print(result.stdout, end="")
