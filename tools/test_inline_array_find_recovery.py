"""Retail inline-array find regression and real state-19 erase integration.

Compiles the actual manual finder, actual generated erase, and actual state-19
cleanup callsite. The historical truncated finder must reproduce corruption.
Only a console test is executed; no game or emulator is launched.
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
section = next(s for s in config._SECTIONS if s.va <= 0xF4A60 < s.va + s.raw_size)
offset = section.raw_addr + 0xF4A60 - section.va
instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + 0x32], 0xF4A60))
assert [(i.mnemonic, i.op_str) for i in instructions] == [
    ("lea", "eax, [ecx + 7]"), ("mov", "ecx, dword ptr [ecx]"),
    ("and", "eax, 0xfffffffc"), ("lea", "edx, [eax + ecx*4]"),
    ("mov", "ecx, eax"), ("cmp", "ecx, edx"), ("je", "0xf4a80"),
    ("mov", "eax, dword ptr [esp + 8]"), ("cmp", "dword ptr [ecx], eax"),
    ("je", "0xf4a89"), ("add", "ecx, 4"), ("cmp", "ecx, edx"),
    ("jne", "0xf4a75"), ("mov", "eax, dword ptr [esp + 4]"),
    ("mov", "dword ptr [eax], edx"), ("ret", "8"),
    ("mov", "eax, dword ptr [esp + 4]"), ("mov", "dword ptr [eax], ecx"), ("ret", "8"),
]
assert instructions[-1].address + instructions[-1].size == 0xF4A92

def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")

def function(source, name):
    match = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    assert match, name
    return match.group()

fixed = function(read("src/recomp_manual.c"), "sub_000F4A60")
old = function(read("src/recomp/gen/recomp_0006.c"), "sub_000F4A60")
erase = function(read("src/recomp/gen/recomp_0002.c"), "sub_00070F70")
dispatcher = function(read("src/recomp/gen/recomp_0009.c"), "sub_00159900")
cleanup = dispatcher[dispatcher.index("loc_00159A51: ;"):dispatcher.rindex("}")]

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static uint32_t g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp, g_seh_ebp;
static unsigned char memory[0x400000];
static uint32_t *manual_mem32(uint32_t va) {
    if (va > sizeof(memory)-4) { fprintf(stderr,"out of range: %08X\n",va); exit(4); }
    return (uint32_t *)(memory + va);
}
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define MEM32(a) (*manual_mem32((uint32_t)(a)))
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
#define CMP_EQ(a,b) ((a)==(b))
#define TEST_Z(a,b) (((a)&(b))==0)
static unsigned moves;
void sub_001C5270(void) {
    uint32_t destination=MEM32(esp+4), source=MEM32(esp+8), bytes=MEM32(esp+12);
    if (destination+bytes > sizeof(memory) || source+bytes > sizeof(memory)) exit(5);
    memmove(memory+destination,memory+source,bytes); ++moves;
    eax=destination; esp+=4;
}
void sub_000F4A80(void) { esp+=4; }
void sub_000F4A89(void) { esp+=4; }
'''
cleanup_prefix = r'''
static void cleanup_case(void) {
    uint32_t ebp = 0x810, _fa=0, _fb=0; int32_t _fas=0, _fbs=0;
    PUSH32(esp,ecx); PUSH32(esp,ebx); PUSH32(esp,ebp); PUSH32(esp,esi); PUSH32(esp,edi);
    esi=0x308D30; ebx=0x320000;
'''
suffix = r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 3; } } while(0)
int main(int argc, char **argv) {
    unsigned cases=0;
    (void)argv;
    if (argc>1) goto erase_only;
    for (uint32_t alignment=0;alignment<4;++alignment)
    for (uint32_t count=0;count<=4;++count)
    for (uint32_t query=0;query<=5;++query) {
        uint32_t object=0x1000+alignment, base=(object+7)&~3u;
        memset(memory,0xCD,sizeof(memory));
        MEM32(object)=count;
        for(uint32_t i=0;i<count;++i) MEM32(base+i*4)=100+i;
        eax=0x11; ecx=object; edx=0x22; esp=0x3F0000;
        ebx=0x33; esi=0x44; edi=0x55; g_ebp=0x66;
        PUSH32(esp,100+query); PUSH32(esp,0x2000); PUSH32(esp,0x159A64);
        sub_000F4A60();
        CHECK(esp==0x3F0000 && MEM32(0x2000)==base+(query<count?query:count)*4);
        CHECK(eax==0x2000 && ecx==MEM32(0x2000) && edx==base+count*4);
        CHECK(ebx==0x33 && esi==0x44 && edi==0x55 && g_ebp==0x66);
        ++cases;
    }
erase_only:
    memset(memory,0,sizeof(memory)); moves=0;
    MEM32(0x308D30+0x4C0)=1; MEM32(0x308D30+0x4C4)=0x320000;
    MEM32(0x308D30+0x1664)=1;
    MEM32(0x2C8BA4)=0x30F2E0; MEM32(0x2CA6A0)=0x314C40;
    ecx=0x308D30; ebx=0x307318; esi=0x307318; edi=0x33333333;
    esp=0x3F0000; PUSH32(esp,0x15658B); cleanup_case();
    printf("ERASE: moves=%u input=%08X renderer=%08X esp=%08X\n",moves,MEM32(0x2C8BA4),MEM32(0x2CA6A0),esp);
    CHECK(esp==0x3F0000);
    CHECK(MEM32(0x308D30+0x4C0)==0 && MEM32(0x308D30+0x10)==24);
    CHECK(MEM32(0x2C8BA4)==0x30F2E0 && MEM32(0x2CA6A0)==0x314C40 && moves==0);
    printf("PASS: %u finder cases and actual state-19 erase preserve immutable globals\n",cases);
    return 0;
}
'''
out=ROOT/"diagnostics/inline_array_find_test"
out.mkdir(exist_ok=True)
vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name,body,failure in [("recovered",fixed,False),("historical_truncated",old,True)]:
    (out/f"{name}.c").write_text(prefix+body+"\n"+erase+cleanup_prefix+cleanup+"}\n"+suffix,encoding="utf-8")
    command=f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
    result=subprocess.run([str(out/f"{name}.exe")],capture_output=True,text=True,timeout=10)
    if failure:
        assert result.returncode==3, result
        print("PASS: historical finder rejected: "+result.stderr.strip())
        integration=subprocess.run([str(out/f"{name}.exe"),"erase"],capture_output=True,text=True,timeout=10)
        assert integration.returncode==3, integration
        assert "moves=1 input=00000000 renderer=00000000" in integration.stdout, integration
        print("PASS: historical finder reproduces .data corruption: "+integration.stdout.strip())
    else:
        print(result.stdout,end="")
        if result.returncode: print(result.stderr)
        result.check_returncode()
print("PASS: complete 0x000F4A60..0x000F4A92 retail finder verified")
