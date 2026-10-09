"""Native test for the opt-in, observational timing-list lvalue watch."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
from read_title_probe_rings import RINGS, decode
assert RINGS["timing_link_access"] == ("g_dah2_timing_link_access_sequence", "g_dah2_timing_link_access_ring", 64, 16)
sample = decode("timing_link_access", (0, 0x30FE98, 0x314BBC, 0x8698A138, 0x123450, 42,
                                       0x567890, 99, 1, 2, 3, 4, 5, 6, 100, 1))
assert sample["oldValue"] == "00314BBC" and sample["newValue"] == "8698A138"
assert sample["previousAccessFunction"] == "00123450" and sample["previousAccessLine"] == 42
assert sample["previousRegisters"] == dict(zip(("eax", "ecx", "edx", "esi", "edi", "esp"),
                                               [f"{value:08X}" for value in range(1, 7)]))
assert sample["threadId"] == 100 and sample["publishedSequence"] == 1
manual = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
header = (ROOT / "src/recomp/recomp_types.h").read_text(encoding="utf-8")


def function(source, name):
    return re.search(r"^(?:static )?(?:inline )?(?:volatile uint32_t \*|uint32_t |void )"
                     + name + r"\([^\n]*\)\n\{.*?^\}", source, re.M | re.S).group()


prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static unsigned char memory[0x400000], original[0x400000];
static __declspec(thread) uint32_t g_eax,g_ecx,g_edx,g_esi,g_edi,g_esp,g_seh_head;
volatile uint32_t g_dah2_timing_link_access_sequence;
volatile uint32_t g_dah2_timing_link_access_ring[64][16];
static uint32_t *manual_mem32(uint32_t va) {return (uint32_t *)(memory+va);}
#define XBOX_PTR(a) ((uintptr_t)(memory+(uint32_t)(a)))
static unsigned natalia_calls;
static void dah2_watch_natalia_x_access(uint32_t a,const char *f,int l) {(void)a;(void)f;(void)l;++natalia_calls;}
'''
suffix = r'''
int main(int argc,char **argv) {
    int enabled=argc>1 && atoi(argv[1]);
    uint32_t *word=manual_mem32(0x30FE98),regs[6];
    *word=0x314BBC;
    g_eax=1;g_ecx=2;g_edx=3;g_esi=4;g_edi=5;g_esp=6;
    regs[0]=g_eax;regs[1]=g_ecx;regs[2]=g_edx;regs[3]=g_esi;regs[4]=g_edi;regs[5]=g_esp;
    memcpy(original,memory,sizeof(memory));
    CHECK(recomp_mem32_ptr(0x30FE98,"sub_00123450",17)==word);
    CHECK(!memcmp(original,memory,sizeof(memory)));
    *recomp_mem32_ptr(0x30FE98,"sub_00123450",42)=0x8698A138;
    memcpy(original,memory,sizeof(memory));
    CHECK(recomp_mem32_ptr(0x30FE98,"sub_00567890",99)==word);
    CHECK(!memcmp(original,memory,sizeof(memory)));
    CHECK(g_dah2_timing_link_access_sequence==(enabled?1u:0u));
    if(enabled) {
        CHECK(g_dah2_timing_link_access_ring[0][1]==0x30FE98);
        CHECK(g_dah2_timing_link_access_ring[0][2]==0x314BBC);
        CHECK(g_dah2_timing_link_access_ring[0][3]==0x8698A138);
        CHECK(g_dah2_timing_link_access_ring[0][4]==0x123450);
        CHECK(g_dah2_timing_link_access_ring[0][5]==42);
        CHECK(g_dah2_timing_link_access_ring[0][6]==0x567890);
        CHECK(g_dah2_timing_link_access_ring[0][7]==99);
        for(unsigned i=0;i<6;++i) CHECK(g_dah2_timing_link_access_ring[0][8+i]==regs[i]);
    }
    for(unsigned i=0;i<130;++i) {
        *recomp_mem32_ptr(0x30FE98,"sub_00123450",43)=i;
        memcpy(original,memory,sizeof(memory));
        recomp_mem32_ptr(0x30FE98,"sub_00567890",100);
        CHECK(!memcmp(original,memory,sizeof(memory)));
    }
    CHECK(g_dah2_timing_link_access_sequence==(enabled?131u:0u));
    if(enabled) {
        CHECK(g_dah2_timing_link_access_ring[130&63][0]==130);
        CHECK(g_dah2_timing_link_access_ring[130&63][2]==128);
        CHECK(g_dah2_timing_link_access_ring[130&63][3]==129);
    }
    CHECK(g_eax==1 && g_ecx==2 && g_edx==3 && g_esi==4 && g_edi==5 && g_esp==6);
    recomp_mem32_ptr(0x858E96F0,"sub_00123450",101);
    CHECK(natalia_calls==1);
    CHECK(recomp_mem32_ptr(0,"sub_00123450",102)==&g_seh_head);
    return 0;
}
'''
watch = function(manual, "dah2_watch_timing_link_access")
assert "DAH2_TIMING_LINK_WATCH" in watch and "DAH2_TEST_WINDOW_HIDDEN" in watch
assert "dah2_watch_timing_link_access(addr, function, line);" in header
native = prefix + function(manual, "dah2_function_va") + watch + function(header, "recomp_mem32_ptr") + suffix
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
with tempfile.TemporaryDirectory(prefix="dah2-timing-watch-") as directory:
    out = Path(directory)
    (out / "watch.c").write_text(native, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC watch.c /Fe:watch.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
    for hidden, requested in (("0", "0"), ("0", "1"), ("1", "0"), ("1", "1")):
        enabled = hidden == requested == "1"
        environment = dict(os.environ, DAH2_TEST_WINDOW_HIDDEN=hidden, DAH2_TIMING_LINK_WATCH=requested)
        result = subprocess.run([str(out / "watch.exe"), str(int(enabled))], env=environment,
                                capture_output=True, text=True, timeout=10, check=True)
        lines = result.stdout.splitlines()
        assert len(lines) == (64 if enabled else 0), len(lines)
        assert not result.stderr, result.stderr
        if enabled:
            assert "old=00314BBC new=8698A138" in lines[0]
            assert "previous=00123450:42 observed=00567890:99" in lines[0]
print("PASS: native timing watch preserves guest RAM/GPRs; hidden+opt-in gating, prior source location,64-line bound,ring wrapping,Natalia/SEH behavior")
