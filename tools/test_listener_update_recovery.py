"""Native ABI/semantic checks for recovered retail listener update 0002B350.

Runs actual generated 2B350 directly and through actual 2B0C0 -> 115F60.
Timer/removal callees are bounded stand-ins checking their exact CALL frames.
No game, emulator, visible window, or desktop operation is performed.
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
    section = next(s for s in config._SECTIONS if s.va <= va < s.va + s.raw_size)
    offset = section.raw_addr + va - section.va
    return image[offset:offset + size]


instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(retail(0x2B350, 94), 0x2B350))
expected_assembly = """push ebx
push esi
mov esi, ecx
mov eax, dword ptr [esi + 0x10]
xor ebx, ebx
cmp eax, 2
jne 0x2b37e
mov eax, dword ptr [0x30fde4]
fld dword ptr [eax + 0xc]
fcomp dword ptr [esi + 0x14]
fnstsw ax
test ah, 1
jne 0x2b37e
mov dword ptr [esi + 0x10], ebx
mov ecx, dword ptr [0x30fdf8]
call 0x121a90
cmp dword ptr [esi + 0x18], ebx
jle 0x2b3a9
push edi
mov ecx, dword ptr [esi + 0x20]
mov edi, dword ptr [ecx + ebx*4]
mov edx, dword ptr [esi]
push 1
push edi
mov ecx, esi
call dword ptr [edx + 0x40]
test al, al
jne 0x2b3a2
push edi
mov ecx, esi
call 0x2b280
jmp 0x2b3a3
inc ebx
cmp ebx, dword ptr [esi + 0x18]
jl 0x2b384
pop edi
pop esi
pop ebx
ret 4"""
assert [f"{i.mnemonic} {i.op_str}" for i in instructions] == expected_assembly.splitlines()
assert instructions[-1].address + instructions[-1].size == 0x2B3AE
assert int.from_bytes(retail(0x29DD18 + 8, 4), "little") == 0x2B0C0
assert int.from_bytes(retail(0x29DD18 + 0x50, 4), "little") == 0x2B350
listener_instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(retail(0x2B0C0, 41), 0x2B0C0))
assert [(i.address, i.op_str) for i in listener_instructions if i.mnemonic == "call"] == [
    (0x2B0D9, "dword ptr [eax + 0x50]"), (0x2B0DF, "0x115f60")]


def function(chunk, name):
    source = (ROOT / f"src/recomp/gen/recomp_{chunk}.c").read_text(encoding="utf-8")
    found = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    assert found, name
    return found.group()


body = function("0000", "sub_0002B350")
listener = function("0000", "sub_0002B0C0")
base_listener = function("0007", "sub_00115F60")
assert "sub_0002B37E();" not in body

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,g_ebp,g_seh_ebp;
static unsigned char memory[0x10000], expected[0x10000];
static double g_fp_stack[8];
static unsigned g_fp_top;
static int g_fp_cmp;
static unsigned keep_mask, checked, removed, timer_calls;
static uint32_t callee_sp;
#define g_esp esp
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(3); } } while(0)
static uint32_t offset(uint32_t va) {
    if(va<0xF000) return va;
    if(va==0x30FDE4) return 0xF000;
    if(va==0x30FDF8) return 0xF004;
    fprintf(stderr,"Unexpected VA %08X\n",va); exit(5);
}
#define MEM32(a) (*(uint32_t *)(memory+offset((uint32_t)(a))))
#define MEMF(a) (*(float *)(memory+offset((uint32_t)(a))))
#define E32(a) (*(uint32_t *)(expected+offset((uint32_t)(a))))
#define LO8(r) ((uint8_t)(r))
#define HI8(r) ((uint8_t)((r)>>8))
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define RECOMP_FCMP(a,b) (((a)!=(a)||(b)!=(b)) ? 2 : (a)<(b) ? -1 : (a)>(b) ? 1 : 0)
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
static void sub_0002B350(void);
static void sub_00115F60(void);
static void sub_0002B000(void) { CHECK(0 && "unexpected removal-registration event"); }
static void sub_0003D200(void) { CHECK(0 && "unexpected add-registration event"); }
static void sub_0002B37E(void) { esp+=4; } /* Historical unresolved stub. */
static void sub_00121A90(void) {
    CHECK(ecx==0x6000 && esp==callee_sp-12 && MEM32(esp)==0x2B37E);
    CHECK(MEM32(0x1010)==0 && ebx==0 && esi==0x1000);
    ++timer_calls; eax=0xAABBCCDD; esp+=4;
}
static void sub_0002B280(void) {
    uint32_t child=MEM32(esp+4), count=MEM32(0x1018), index=0;
    CHECK(ecx==0x1000 && esp==callee_sp-20 && MEM32(esp)==0x2B3A0);
    CHECK(child==edi && count<=4);
    while(index<count && MEM32(0x4000+index*4)!=child) ++index;
    CHECK(index<count && index==ebx);
    for(uint32_t i=index;i+1<count;++i) MEM32(0x4000+i*4)=MEM32(0x4004+i*4);
    MEM32(0x1018)=count-1;
    ++removed; esp+=8;
}
static void indirect(uint32_t target, uint32_t saved_esp) {
    uint32_t save_bx=ebx,save_si=esi,save_di=edi;
    CHECK(ecx==0x1000);
    if(target==0x2B350) {
        CHECK(esp==callee_sp && saved_esp==callee_sp+8);
        CHECK(MEM32(esp)==0x2B0DC && MEM32(esp+4)==0x3C888889);
        sub_0002B350();
    } else {
        uint32_t child=MEM32(esp+4);
        CHECK(target==0x2B220 && esp==callee_sp-24 && saved_esp==callee_sp-12);
        CHECK(MEM32(esp)==0x2B394 && MEM32(esp+8)==1);
        CHECK(child>=0xA0 && child<0xA4 && child==edi);
        CHECK(child==MEM32(0x4000+ebx*4));
        ++checked; eax=0xDEAD0000u|((keep_mask>>(child-0xA0))&1); esp+=12;
    }
    /* Match the production ICALL macro's register preservation. Direct entry
       is also tested, so this wrapper cannot conceal a broken callee epilogue. */
    ebx=save_bx; esi=save_si; edi=save_di;
}
#define RECOMP_ICALL_SAFE(t,s) indirect((t),(s))
'''
suffix = r'''
int main(void) {
    unsigned cases=0;
    for(unsigned nested=0;nested<2;++nested)
    for(unsigned state=0;state<4;++state)
    for(unsigned clock=0;clock<5;++clock)
    for(unsigned top=0;top<8;top+=3)
    for(unsigned list=0;list<6;++list)
    for(unsigned mask=0;mask<(1u<<(list<5 ? list : 0));++mask) {
        uint32_t count=list<5 ? list : 0xFFFFFFFFu;
        uint32_t initial_sp=0xE000, index=0, oracle_count=count;
        unsigned expected_removed=0, expected_timer;
        float now=clock==0 ? 4.0f : clock==1 ? 5.0f : clock==2 ? 6.0f : clock==3 ? NAN : 5.0f;
        float deadline=clock==4 ? NAN : 5.0f;
        memset(memory,0xCD,sizeof(memory));
        eax=0x10101010; ecx=0x1000; edx=0x20202020; esp=initial_sp;
        ebx=0x11223344; esi=0x55667788; edi=0x99AABBCC;
        g_ebp=g_seh_ebp=0x77777777;
        keep_mask=mask; checked=removed=timer_calls=0;
        g_fp_top=top; g_fp_cmp=7;
        for(unsigned i=0;i<8;++i) g_fp_stack[i]=1000.0+i;
        MEM32(0x1000)=0x2000; MEM32(0x2050)=0x2B350; MEM32(0x2040)=0x2B220;
        MEM32(0x1010)=state; MEMF(0x1014)=deadline; MEM32(0x1018)=count; MEM32(0x1020)=0x4000;
        MEM32(0x30FDE4)=0x5000; MEMF(0x500C)=now; MEM32(0x30FDF8)=0x6000;
        MEM32(0x3004)=0xFAEBB4DCu; MEM32(0x3008)=0x3C888889;
        for(unsigned i=0;i<4;++i) MEM32(0x4000+i*4)=0xA0+i;
        MEM32(initial_sp)=0x115072;
        MEM32(initial_sp+4)=nested ? 0x3000 : 0x3C888889;
        memcpy(expected,memory,sizeof(memory));
        callee_sp=nested ? initial_sp-16 : initial_sp;
        if(nested) {
            E32(initial_sp-4)=esi; E32(initial_sp-8)=edi;
            E32(initial_sp-12)=0x3C888889; E32(initial_sp-16)=0x2B0DC;
        }
        E32(callee_sp-4)=ebx;
        E32(callee_sp-8)=nested ? 0x1000 : esi;
        expected_timer=state==2 && !isnan(now) && !isnan(deadline) && now>=deadline;
        if(expected_timer) { E32(0x1010)=0; E32(callee_sp-12)=0x2B37E; }
        if((int32_t)count>0) E32(callee_sp-12)=nested ? 0x3000 : edi;
        while((int32_t)index<(int32_t)oracle_count) {
            uint32_t child=E32(0x4000+index*4);
            E32(callee_sp-16)=1; E32(callee_sp-20)=child; E32(callee_sp-24)=0x2B394;
            if((mask>>(child-0xA0))&1) ++index;
            else {
                E32(callee_sp-16)=child; E32(callee_sp-20)=0x2B3A0;
                for(uint32_t i=index;i+1<oracle_count;++i) E32(0x4000+i*4)=E32(0x4004+i*4);
                --oracle_count; ++expected_removed; E32(0x1018)=oracle_count;
            }
        }
        if(nested) {
            E32(initial_sp-12)=0x3000; E32(initial_sp-16)=0x2B0E4;
            sub_0002B0C0();
        } else sub_0002B350();
        if(esp!=initial_sp+8) fprintf(stderr,"ABI shortfall=%d actual=%08X expected=%08X\n",(int)(initial_sp+8-esp),esp,initial_sp+8);
        CHECK(esp==initial_sp+8);
        CHECK(ebx==0x11223344 && esi==0x55667788 && edi==0x99AABBCC);
        CHECK(g_ebp==0x77777777 && g_seh_ebp==0x77777777);
        CHECK(checked==(list<5 ? list : 0) && removed==expected_removed && timer_calls==expected_timer);
        CHECK(g_fp_top==top);
        for(unsigned i=0;i<8;++i) {
            double value=(state==2 && i==((top+7)&7)) ? now : 1000.0+i;
            CHECK((isnan(value) && isnan(g_fp_stack[i])) || g_fp_stack[i]==value);
        }
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        ++cases;
    }
    printf("PASS: %u direct/nested listener cases, FP timer branches, list updates, exact stack/memory ABI\n",cases);
    return 0;
}
'''

old_prefix = body[:body.index("    g_fp_cmp = RECOMP_FCMP")]
old_prefix = old_prefix.replace("goto loc_0002B37E; /* retail in-function branch */",
                              "{ g_seh_ebp = ebp; sub_0002B37E(); return; }")
old_body = old_prefix + body[body.index("    #undef fp_push"):]
out_root = ROOT / "diagnostics/listener_update_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
mutants = [
    ("recovered", body, False),
    ("historical_truncation", old_body, True),
    ("wrong_ret_cleanup", body.replace("esp += 8; return;", "esp += 4; return;"), True),
    ("missing_timer_ret", body.replace("PUSH32(esp, 0x0002B37Eu);", ""), True),
    ("missing_icall_ret", body.replace("PUSH32(esp, 0x0002B394u);", ""), True),
]
for name, implementation, should_fail in mutants:
    (out / f"{name}.c").write_text(prefix + implementation + base_listener + listener + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if should_fail:
        assert result.returncode == 3, result
        if name == "historical_truncation": assert "ABI shortfall=12" in result.stderr
        print(f"PASS: {name} rejected: " + result.stderr.strip())
    else:
        if result.returncode: print(result.stderr)
        result.check_returncode()
        print(result.stdout, end="")
print(f"PASS: exact retail 39-instruction update and vtable route verified; artifacts: {out}")
