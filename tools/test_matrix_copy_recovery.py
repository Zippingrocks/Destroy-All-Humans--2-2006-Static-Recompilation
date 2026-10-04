"""Native test of the actual retail matrix-copy recovery, including high VA.

Uses a small address-mapped memory double, not a game launch or a multi-GB
allocation. The previous guard must reproduce zeroing a valid high-VA matrix.
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
s = next(s for s in config._SECTIONS if s.va <= 0x13B8F0 < s.va+s.raw_size)
o = s.raw_addr+0x13B8F0-s.va
retail = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[o:o+16], 0x13B8F0))
assert [(i.mnemonic, i.op_str) for i in retail] == [
    ("push", "esi"), ("push", "edi"), ("mov", "edi, ecx"), ("mov", "ecx, 0x10"),
    ("mov", "esi, edx"), ("rep movsd", "dword ptr es:[edi], dword ptr [esi]"),
    ("pop", "edi"), ("pop", "esi"), ("ret", ""),
]
def body(path):
    source = (ROOT/path).read_text(encoding="utf-8")
    return re.search(r"^void sub_0013B8F0\(void\)\n\{.*?^\}", source, re.M|re.S).group()
prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi;
static unsigned char memory[0x30000], expected[0x30000];
static unsigned offset(uint32_t a) {
    if(a>=0x00310000 && a<=0x0031FFFC) return a-0x00310000;
    if(a>=0x81250000 && a<=0x8125FFFC) return a-0x81250000+0x10000;
    if(a>=0x007F0000 && a<=0x007FFFFC) return a-0x007F0000+0x20000;
    fprintf(stderr,"bad test address %08X\n",a); exit(5);
}
static uint32_t *manual_mem32(uint32_t a) { return (uint32_t *)(memory+offset(a)); }
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define MEM32(a) (*manual_mem32(a))
#define XBOX_PTR(a) (memory+offset(a))
#define PUSH32(sp,v) do { uint32_t pushed=(v); (sp)-=4; MEM32(sp)=pushed; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
#define CHECK(v) do { if(!(v)) { fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v); return 3; } } while(0)
'''
suffix = r'''
int main(int argc,char **argv) {
    static const uint32_t sources[]={0x81255440,0x00315330,0x81255440,0x00315330,0x00315334,0x81255444,0x81255430};
    static const uint32_t destinations[]={0x00315330,0x81255440,0x81255440,0x00315334,0x00315330,0x81255430,0x81255444};
    unsigned cases=0;
    (void)argv;
    for(unsigned alignment=0;alignment<4;++alignment)
    for(unsigned test=0;test<sizeof(sources)/sizeof(sources[0]);++test) {
        uint32_t source=sources[test]+alignment,destination=destinations[test]+alignment;
        for(unsigned i=0;i<sizeof(memory);++i) memory[i]=(unsigned char)((i*41+i/13+1)%251);
        eax=0x1111; ebx=0x2222; esi=0x3333; edi=0x4444; esp=0x007FF000;
        ecx=destination; edx=source; PUSH32(esp,0x15CEB4);
        memcpy(expected,memory,sizeof(memory));
        /* Retail stack writes and forward REP copy are part of memory effects. */
        *(uint32_t *)(expected+offset(esp-4))=esi;
        *(uint32_t *)(expected+offset(esp-8))=edi;
        for(unsigned i=0;i<16;++i) {
            uint32_t word; memcpy(&word,expected+offset(source+4*i),4);
            memcpy(expected+offset(destination+4*i),&word,4);
        }
        sub_0013B8F0();
        if(argc>1) {
            unsigned nonzero=0; for(unsigned i=0;i<64;++i) nonzero+=memory[offset(destination)+i]!=0;
            printf("HISTORICAL: mapped source=%08X destination=%08X nonzero=%u\n",source,destination,nonzero);
            return nonzero==0 ? 0 : 4;
        }
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        CHECK(eax==0x1111 && ebx==0x2222 && esi==0x3333 && edi==0x4444);
        CHECK(ecx==0 && edx==source && esp==0x007FF000);
        ++cases;
    }
    printf("PASS: %u high/low/overlapping/unaligned matrix copies match retail memory and ABI\n",cases);
    return 0;
}
'''
out = ROOT/"diagnostics/matrix_copy_recovery_test"
out.mkdir(exist_ok=True)
vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, source in [("fixed",body("src/recomp_manual.c")),("historical",body("src/recomp/gen/recomp_0008.c"))]:
    (out/f"{name}.c").write_text(prefix+source+suffix,encoding="utf-8")
    command=f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
    result=subprocess.run([str(out/f"{name}.exe")],capture_output=True,text=True,timeout=10)
    if name=="fixed":
        if result.returncode: print(result.stderr)
        result.check_returncode(); print(result.stdout,end="")
    else:
        assert result.returncode==3,result
        zeroed=subprocess.run([str(out/f"{name}.exe"),"zeroing"],capture_output=True,text=True,timeout=10)
        zeroed.check_returncode(); print("PASS: old guard rejected; "+zeroed.stdout.strip())
