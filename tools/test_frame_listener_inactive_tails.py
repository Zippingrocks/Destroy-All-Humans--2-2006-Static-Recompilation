"""Execute BF790 and its actual inactive BFB50/BFFF0 callees.

The historical paired missing epilogues must reproduce the run6 0xA0 stack
shortfall. Active effects remain outside this test and fail if accidentally
entered. No game/emulator process or UI operation is performed.
"""
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


def retail(va, size):
    s = next(s for s in config._SECTIONS if s.va <= va < s.va + s.raw_size)
    offset = s.raw_addr + va - s.va
    return image[offset:offset + size]


disasm = Cs(CS_ARCH_X86, CS_MODE_32)
assert [(i.address, i.mnemonic, i.op_str) for i in disasm.disasm(retail(0xBFDC1, 5), 0xBFDC1)] == [
    (0xBFDC1, "pop", "edi"), (0xBFDC2, "add", "esp, 0x5c"), (0xBFDC5, "ret", "")]
assert [(i.address, i.mnemonic, i.op_str) for i in disasm.disasm(retail(0xC0116, 5), 0xC0116)] == [
    (0xC0116, "pop", "esi"), (0xC0117, "add", "esp, 0x3c"), (0xC011A, "ret", "")]
assert [(i.address, i.op_str) for i in disasm.disasm(retail(0xBF790, 211), 0xBF790) if i.mnemonic == "call"] == [
    (0xBF7E6, "0xbf9f0"), (0xBF7F7, "0xbfa70"), (0xBF802, "0xbfb50"),
    (0xBF831, "0xbfdd0"), (0xBF83C, "0xbfff0"), (0xBF84F, "0xbfe30"), (0xBF85A, "0xbfff0")]
for start, length, address, target in [(0xBFB50, 20, 0xBFB5E, "0xbfdc1"), (0xBFFF0, 20, 0xBFFFE, "0xc0116")]:
    assert any(i.address == address and i.mnemonic == "je" and i.op_str == target
               for i in disasm.disasm(retail(start, length), start))

source = (ROOT / "src/recomp/gen/recomp_0004.c").read_text(encoding="utf-8")


def function(name):
    found = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    assert found, name
    return found.group()


effect_a = function("sub_000BFB50")
effect_b = function("sub_000BFFF0")
listener = function("sub_000BF790")
tail_a = re.search(r"    if \(TEST_Z\(_fa, _fb\)\) \{\n        /\* Retail inactive branch.*?^    \}", effect_a, re.M | re.S).group()
tail_b = re.search(r"    if \(TEST_Z\(_fa, _fb\)\) \{\n        /\* Retail inactive branch.*?^    \}", effect_b, re.M | re.S).group()
old_a = effect_a.replace(tail_a, "    if (TEST_Z(_fa, _fb)) { g_seh_ebp = ebp; sub_000BFDC1(); return; }")
old_b = effect_b.replace(tail_b, "    if (TEST_Z(_fa, _fb)) { g_seh_ebp = ebp; sub_000C0116(); return; }")
constant = int.from_bytes(retail(0x29BBD4, 4), "little")

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,g_ebp,g_seh_ebp;
static unsigned char memory[0x10000],expected[0x10000];
static double g_fp_stack[8];
static unsigned g_fp_top;
static int g_fp_cmp;
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(3); } } while(0)
static uint32_t offset(uint32_t va) { if(va<0xF000) return va; CHECK(va==0x29BBD4); return 0xF000; }
#define MEM8(a) (*(uint8_t *)(memory+offset((uint32_t)(a))))
#define MEM32(a) (*(uint32_t *)(memory+offset((uint32_t)(a))))
#define MEMF(a) (*(float *)(memory+offset((uint32_t)(a))))
#define E32(a) (*(uint32_t *)(expected+offset((uint32_t)(a))))
#define LO8(v) ((uint8_t)(v))
#define HI8(v) ((uint8_t)((v)>>8))
#define SET_LO8(r,v) ((r)=((r)&0xFFFFFF00u)|(uint8_t)(v))
#define CMP_L(a,b) ((int32_t)(a)<(int32_t)(b))
#define CMP_NE(a,b) ((a)!=(b))
#define TEST_Z(a,b) (((a)&(b))==0)
#define TEST_NZ(a,b) (((a)&(b))!=0)
#define RECOMP_FCMP(a,b) (((a)!=(a)||(b)!=(b)) ? 2 : (a)<(b) ? -1 : (a)>(b) ? 1 : 0)
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
static void sub_000BFDC1(void) { esp+=4; }
static void sub_000C0116(void) { esp+=4; }
'''
dependencies = sorted(set(re.findall(r"\b(sub_[0-9A-F]{8})\(\)", effect_a + effect_b + listener)) - {
    "sub_000BFB50", "sub_000BFFF0", "sub_000BFDC1", "sub_000C0116"})
prefix += "\n".join(f'static void {name}(void) {{ CHECK(0 && "active dependency {name}"); }}' for name in dependencies) + "\n"
suffix = r'''
int main(void) {
    unsigned cases=0;
    const uint32_t counts[]={0,1,2,3,4,31,0xFFFFFFFFu,0x7FFFFFFFu};
    const uint32_t events[]={0,0xFAA22138u,0xD2EB1B81u};
    for(unsigned path=0;path<3;++path)
    for(unsigned c=0;c<sizeof(counts)/sizeof(counts[0]);++c)
    for(unsigned e=0;e<3;++e)
    for(unsigned index=0;index<4;++index)
    for(unsigned sample=0;sample<3;++sample)
    for(unsigned top=0;top<8;top+=3) {
        const uint32_t object=0x2000, event=0x3000, initial_sp=0xE000;
        uint32_t updated=counts[c]+1;
        unsigned active=events[e]==0xD2EB1B81u && (int32_t)updated>=4;
        float value;
        memset(memory,0xCD,sizeof(memory));
        eax=0xAABBCCDD; ecx=object; edx=0x44332211; esp=initial_sp;
        ebx=0x12345678; esi=0x23456789; edi=0x3456789A;
        g_ebp=g_seh_ebp=0x456789AB; g_fp_top=top; g_fp_cmp=7;
        for(unsigned i=0;i<8;++i) g_fp_stack[i]=1000.0+i;
        MEM32(0x29BBD4)=CONSTANT;
        value=sample==0 ? MEMF(0x29BBD4)-1.0f : sample==1 ? MEMF(0x29BBD4) : NAN;
        MEM32(object+0x4DC)=counts[c]; MEM32(object+0x4D8)=index;
        MEM8(object+0x1A8)=0; MEM8(object+0x4D4)=0;
        MEMF(object+index*24+0x14)=value; MEMF(object+index*24+0x1C)=value;
        MEM32(event+4)=events[e]; MEM32(event+8)=0x3C888889;
        MEM32(initial_sp)=0x155508; MEM32(initial_sp+4)=event;
        memcpy(expected,memory,sizeof(memory));
        if(path==0) {
            E32(initial_sp-4)=esi;
            if(events[e]==0xD2EB1B81u) E32(object+0x4DC)=updated;
            if(active) {
                E32(initial_sp-8)=0xBF85F;
                E32(initial_sp-0x68)=edi;
                E32(initial_sp-0x48)=object;
            }
            sub_000BF790();
            if(esp!=initial_sp+8) fprintf(stderr,"ABI shortfall=%X actual=%08X expected=%08X\n",initial_sp+8-esp,esp,initial_sp+8);
            CHECK(esp==initial_sp+8);
        } else if(path==1) {
            ecx=object+0x100;
            E32(initial_sp-0x60)=edi;
            sub_000BFB50();
            CHECK(esp==initial_sp+4);
        } else {
            ecx=object+0x1AC;
            E32(initial_sp-0x40)=esi;
            sub_000BFFF0();
            CHECK(esp==initial_sp+4);
        }
        CHECK(ebx==0x12345678 && esi==0x23456789 && edi==0x3456789A);
        CHECK(g_ebp==0x456789AB && g_seh_ebp==0x456789AB && g_fp_top==top);
        for(unsigned i=0;i<8;++i) {
            double expected_fp=(path==0 && active && i==((top+7)&7)) ? value : 1000.0+i;
            CHECK((isnan(expected_fp) && isnan(g_fp_stack[i])) || g_fp_stack[i]==expected_fp);
        }
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        ++cases;
    }
    printf("PASS: %u actual listener/inactive-effect paths, exact stack/store/register/FP effects\n",cases);
    return 0;
}
'''.replace("CONSTANT", f"0x{constant:08X}u")

out_root = ROOT / "diagnostics/frame_listener_inactive_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, a, b, shortfall in [
    ("recovered", effect_a, effect_b, None),
    ("historical_both", old_a, old_b, "A0"),
    ("historical_BFB50", old_a, effect_b, "60"),
    ("historical_BFFF0", effect_a, old_b, "40"),
]:
    (out / f"{name}.c").write_text(prefix + a + b + listener + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if shortfall:
        assert result.returncode == 3 and f"ABI shortfall={shortfall} " in result.stderr, result
        print(f"PASS: {name} reproduces 0x{shortfall} leak: " + result.stderr.strip())
    else:
        if result.returncode: print(result.stderr)
        result.check_returncode()
        print(result.stdout, end="")
print(f"PASS: exact retail inactive branches/shared epilogues verified; artifacts: {out}")
