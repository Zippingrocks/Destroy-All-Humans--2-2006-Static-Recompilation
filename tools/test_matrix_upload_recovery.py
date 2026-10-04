"""Execute the actual recovered 24FB10 matrix pushbuffer upload body."""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image = (ROOT / "game_files/default.xbe").read_bytes()
section = next(s for s in config._SECTIONS if s.va <= 0x24FB10 < s.va + s.raw_size)
offset = section.raw_addr + 0x24FB10 - section.va
insns = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + 0xA2], 0x24FB10))
movq = [(i.address, i.op_str) for i in insns if i.mnemonic == "movq"]
assert len(insns) == 42 and len(movq) == 24
assert [text for _, text in movq[:8]] == [
    "mm0, qword ptr [edx]", "mm1, qword ptr [edx + 8]",
    "mm2, qword ptr [edx + 0x10]", "mm3, qword ptr [edx + 0x18]",
    "mm4, qword ptr [edx + 0x20]", "mm5, qword ptr [edx + 0x28]",
    "mm6, qword ptr [edx + 0x30]", "mm7, qword ptr [edx + 0x38]",
]

source = (ROOT / "src/recomp/gen/recomp_0014.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_0024FB10\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert body.count("memcpy(&mm") == 8 and body.count("memcpy((void *)XBOX_PTR(") == 16

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi;
static unsigned char memory[0x300000], expected[0x300000];
static unsigned helper_calls;
static uint32_t helper_put,helper_limit;
static void *ptr(uint32_t a,unsigned n) {
    if(a > sizeof(memory)-n) { fprintf(stderr,"bad address %08X\n",a); exit(5); }
    return memory+a;
}
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define MEM32(a) (*(uint32_t *)ptr((uint32_t)(a),4))
#define XBOX_PTR(a) ptr((uint32_t)(a),1)
#define PUSH32(sp,v) do { uint32_t t=(v); (sp)-=4; MEM32(sp)=t; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
#define CMP_AE(a,b) ((uint32_t)(a)>=(uint32_t)(b))
static void sub_00255450(void) {
    ++helper_calls;
    eax=0xA1A2A3A4; ecx=0xC1C2C3C4; edx=0xD1D2D3D4;
    MEM32(0x25E5B0)=helper_put; MEM32(0x25E5B4)=helper_limit;
    esp += 4;
}
#define CHECK(v) do { if(!(v)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v); return 3; } } while(0)
'''

suffix = r'''
static void store32(unsigned char *p,uint32_t a,uint32_t v) { memcpy(p+a,&v,4); }
int main(void) {
    static const uint32_t source_mode[] = {0x001001,0x26000C,0x25D510,0x180003};
    unsigned cases=0;
    for(unsigned retry=0;retry<2;++retry)
    for(unsigned mode=0;mode<4;++mode) {
        for(unsigned i=0;i<sizeof(memory);++i) memory[i]=(unsigned char)((i*37u+i/17u+11u)%251u);
        uint32_t initial_put=0x260000, index=2, cache=0x25D4F0+index*16;
        uint32_t final_put=retry?0x270000:initial_put;
        uint32_t source=source_mode[mode];
        if(mode==1) source=final_put+12;
        if(mode==2) source=cache;
        uint32_t final_eax=final_put+0x4C, pb=final_eax-0x40;
        uint8_t snapshot[64]; memcpy(snapshot,memory+source,64);
        memcpy(expected,memory,sizeof(memory));
        store32(expected,0x25E5B0,final_eax);
        store32(expected,final_eax-0x4C,0x41EA4);
        store32(expected,final_eax-0x48,index);
        store32(expected,final_eax-0x44,0x400B80);
        memcpy(expected+pb,snapshot,64); memcpy(expected+cache,snapshot,64);
        eax=0x11111111; ecx=index; edx=source; ebx=0x44444444;
        esi=0x55555555; edi=0x66666666; esp=0x2FF000;
        MEM32(esp)=0xCAFEBABE; memcpy(expected+esp,memory+esp,4);
        MEM32(0x25E5B0)=initial_put;
        MEM32(0x25E5B4)=retry?initial_put+0x4C:initial_put+0x1000;
        memcpy(expected+0x25E5B4,memory+0x25E5B4,4);
        helper_calls=0; helper_put=final_put; helper_limit=final_put+0x1000;
        if(retry) {
            store32(expected,0x25E5B4,helper_limit);
            store32(expected,esp-4,source); store32(expected,esp-8,index);
            store32(expected,esp-12,0x0024FBAB);
        }
        sub_0024FB10();
        CHECK(helper_calls==retry);
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        CHECK(ecx==cache && edx==source && esp==0x2FF004);
        CHECK(ebx==0x44444444 && esi==0x55555555 && edi==0x66666666);
        ++cases;
    }
    printf("PASS: %u direct/retry unaligned and overlapping matrix uploads match retail memory/ABI\n",cases);
    return 0;
}
'''

mutant = re.sub(r"^    memcpy\((?:&mm|\(void \*\)XBOX_PTR\().*?;$", "    /* historical untranslated movq */", body, flags=re.M)
assert mutant.count("historical untranslated movq") == 24
out_root = ROOT / "diagnostics/matrix_upload_recovery_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, implementation in (("recovered", body), ("historical", mutant)):
    (out / f"{name}.c").write_text(prefix + implementation + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /W3 /TC {name}.c /Fe:{name}.exe'
    compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out,
                              capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if compiled.returncode: print(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True,
                            timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    if name == "recovered":
        if result.returncode: print(result.stderr)
        result.check_returncode(); print(result.stdout, end="")
    else:
        assert result.returncode == 3, result
        print("PASS: historical no-op MOVQ mutant rejected")
print(f"PASS: verified 42 retail instructions / 24 MOVQs; artifacts: {out}")
