"""Execute the actual 00115200 body and reject its historical truncated tail.

Checks retail disassembly, FP branches, guest stack/store/register effects, and
the indirect-call argument/return slot. Tiny hidden native tests only; no game.
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


def retail_bytes(va, size):
    section = next(s for s in config._SECTIONS if s.va <= va < s.va + s.raw_size)
    offset = section.raw_addr + va - section.va
    return image[offset:offset + size]


instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(retail_bytes(0x115200, 0xB0), 0x115200))
assert len(instructions) == 46
assert [(i.address, i.mnemonic, i.op_str) for i in instructions[-6:]] == [
    (0x115290, "fstp", "dword ptr [esi + 0x10]"),
    (0x115293, "mov", "eax, dword ptr [0x323ae4]"),
    (0x115298, "mov", "dword ptr [eax + 0x2c40], 0"),
    (0x1152A2, "mov", "dword ptr [0x30fdf4], 0"),
    (0x1152AC, "pop", "esi"),
    (0x1152AD, "ret", "4"),
]
assert instructions[-1].address + instructions[-1].size == 0x1152B0
source = (ROOT / "src/recomp/gen/recomp_0007.c").read_text(encoding="utf-8")
match = re.search(r"^void sub_00115200\(void\)\n\{.*?^\}", source, re.M | re.S)
assert match, "Actual generated function missing"
body = match.group()
timing_hook = '    dah2_parity_timing("simulation_delta", 0x001152ADu, g_ebp);\n'
assert body.count(timing_hook) == 1
assert ('    POP32(esp, esi); /* retail 0x001152AC */\n' + timing_hook +
        '    esp += 8; return; /* retail 0x001152AD: ret 4 */') in body
# The observer is tested independently. Keep this ABI fixture's original
# behavioral oracle and negative mutants unchanged after verifying placement.
body = body.replace(timing_hook, '')
tail = """    MEM32(0x30FDF4) = 0; /* retail 0x001152A2 */
    POP32(esp, esi); /* retail 0x001152AC */
    esp += 8; return; /* retail 0x001152AD: ret 4 */"""
assert body.count(tail) == 1
constant_a = int.from_bytes(retail_bytes(0x29BBD0, 4), "little")
constant_b = int.from_bytes(retail_bytes(0x29B7A8, 4), "little")

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,ebp;
static unsigned char memory[0x10000], expected[0x10000];
static double g_fp_stack[8];
static unsigned g_fp_top;
static int g_fp_cmp;
static unsigned calls, wanted_mode;
static uint32_t post_mode;
#define g_esp esp
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(3); } } while(0)
static uint32_t offset(uint32_t va) {
    if(va < 0xF000) return va;
    switch(va) {
    case 0x2CA6A0: return 0xF000;
    case 0x29BBD0: return 0xF004;
    case 0x29B7A8: return 0xF008;
    case 0x323AE4: return 0xF00C;
    case 0x30FDF4: return 0xF010;
    default: fprintf(stderr,"Unexpected guest VA %08X\n",va); exit(5);
    }
}
#define MEM8(a) (*(uint8_t *)(memory+offset((uint32_t)(a))))
#define MEM32(a) (*(uint32_t *)(memory+offset((uint32_t)(a))))
#define SMEM32(a) (*(int32_t *)(memory+offset((uint32_t)(a))))
#define MEMF(a) (*(float *)(memory+offset((uint32_t)(a))))
#define E32(a) (*(uint32_t *)(expected+offset((uint32_t)(a))))
#define EF(a) (*(float *)(expected+offset((uint32_t)(a))))
#define LO8(v) ((uint8_t)(v))
#define HI8(v) ((uint8_t)((v)>>8))
#define SET_LO8(r,v) ((r)=((r)&0xFFFFFF00u)|(uint8_t)(v))
#define TEST_Z(a,b) (((a)&(b))==0)
#define TEST_NZ(a,b) (((a)&(b))!=0)
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_LE(a,b) ((int32_t)(a)<=(int32_t)(b))
#define RECOMP_FCMP(a,b) (((a)!=(a)||(b)!=(b)) ? 2 : (a)<(b) ? -1 : (a)>(b) ? 1 : 0)
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
static void indirect(uint32_t target, uint32_t saved_esp) {
    CHECK(target==0x123456 && ecx==0x6000 && saved_esp==0xDFFC);
    CHECK(esp==0xDFF4 && MEM32(esp)==0x115245 && MEM32(esp+4)==wanted_mode);
    CHECK(MEM32(esp+8)==0x76543210);
    ++calls;
    MEM32(0x627C)=post_mode;
    esp+=8;
}
#define RECOMP_ICALL_SAFE(t,s) indirect((t),(s))
'''
suffix = r'''
int main(void) {
    unsigned cases=0;
    uint32_t modes[]={0,1,2,3,0xFFFFFFFFu};
    for(unsigned rate=0;rate<2;++rate)
    for(unsigned flag=0;flag<2;++flag)
    for(unsigned call=0;call<2;++call)
    for(unsigned clamp=0;clamp<2;++clamp)
    for(unsigned sample=0;sample<5;++sample)
    for(unsigned mode=0;mode<5;++mode)
    for(unsigned top=0;top<8;top+=3) {
        const uint32_t object=0x1000, manager=0x6000, target=0x8000, initial_sp=0xE000;
        float argument, limit;
        uint32_t active_mode;
        double result;
        memset(memory,0xCD,sizeof(memory));
        eax=0xAABBCCDD; ecx=object; edx=0xBAD0BAD0; esp=initial_sp;
        ebx=0x11223344; esi=0x76543210; edi=0x55667788; ebp=0x99AABBCC;
        calls=0; wanted_mode=flag ? 1 : 2; post_mode=modes[mode];
        g_fp_top=top; g_fp_cmp=7;
        for(unsigned i=0;i<8;++i) g_fp_stack[i]=1000.0+i;
        MEM32(0x2CA6A0)=manager; MEM32(0x323AE4)=target;
        MEM32(0x29BBD0)=CONSTANT_A; MEM32(0x29B7A8)=CONSTANT_B;
        MEM32(manager)=0x7000; MEM32(0x7020)=0x123456;
        MEM32(manager+0x238)=rate;
        MEM32(manager+0x27C)=call ? wanted_mode+10 : wanted_mode;
        MEM8(object+0x3059)=(uint8_t)flag; MEM8(object+0x303D)=(uint8_t)clamp;
        limit=MEMF(0x29BBD0);
        switch(sample) {
        case 0: argument=limit*0.5f; break;
        case 1: argument=limit; break;
        case 2: argument=limit*2.0f; break;
        case 3: argument=-1.0f; break;
        default: argument=NAN; break;
        }
        MEM32(initial_sp)=0xF7C99; MEMF(initial_sp+4)=argument;
        memcpy(expected,memory,sizeof(memory));
        E32(initial_sp-4)=esi;
        EF(object+4)=rate ? 60.0f : 50.0f;
        if(call) {
            E32(initial_sp-8)=wanted_mode;
            E32(initial_sp-12)=0x115245;
            E32(manager+0x27C)=post_mode;
        }
        active_mode=call ? post_mode : wanted_mode;
        if(clamp) result=(!isnan(argument) && limit>argument) ? argument : limit;
        else {
            result=(double)MEMF(0x29B7A8)/(rate ? 60.0 : 50.0);
            E32(initial_sp+4)=active_mode;
            if((int32_t)active_mode>1) result*=(int32_t)active_mode;
        }
        EF(object+0x10)=(float)result;
        E32(target+0x2C40)=0; E32(0x30FDF4)=0;
        sub_00115200();
        CHECK(esp==initial_sp+8 && esi==0x76543210);
        CHECK(ebx==0x11223344 && edi==0x55667788 && ebp==0x99AABBCC);
        CHECK(eax==target && ecx==(clamp ? manager : active_mode));
        CHECK(edx==(call ? 0x7000 : rate));
        CHECK(calls==call && g_fp_top==top);
        for(unsigned i=0;i<8;++i)
            CHECK(g_fp_stack[i]==(i==((top+7)&7) ? result : 1000.0+i));
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        ++cases;
    }
    printf("PASS: %u actual 00115200 cases preserve FP paths, stores and POP/RET4 ABI\n",cases);
    return 0;
}
'''.replace("CONSTANT_A", f"0x{constant_a:08X}u").replace("CONSTANT_B", f"0x{constant_b:08X}u")

out_root = ROOT / "diagnostics/frame_timing_tail_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
mutants = [
    ("recovered", body, False),
    ("historical_truncation", body.replace(tail, ""), True),
    ("missing_global_store", body.replace("MEM32(0x30FDF4) = 0;", ""), True),
    ("missing_pop", body.replace("POP32(esp, esi); /* retail 0x001152AC */", ""), True),
    ("wrong_ret_cleanup", body.replace("esp += 8; return; /* retail 0x001152AD", "esp += 4; return; /* retail 0x001152AD"), True),
]
for name, implementation, should_fail in mutants:
    (out / f"{name}.c").write_text(prefix + implementation + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if should_fail:
        assert result.returncode == 3, result
        print(f"PASS: {name} rejected: " + result.stderr.strip())
    else:
        if result.returncode: print(result.stderr)
        result.check_returncode()
        print(result.stdout, end="")
print(f"PASS: exact retail extent/tail verified; artifacts: {out}")
