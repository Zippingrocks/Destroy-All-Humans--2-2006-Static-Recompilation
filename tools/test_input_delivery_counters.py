"""Native test of actual scripted XInput output plus observational counters."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
input_source = (ROOT / "xboxrecomp/src/input/xinput_device.c").read_text(encoding="utf-8")
assert "XBOX_BUTTON_BLACK] =\n        (xi_state.Gamepad.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER)" in input_source
assert "XBOX_BUTTON_WHITE] =\n        (xi_state.Gamepad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER)" in input_source
event = re.search(r"typedef struct Dah2InputEvent \{.*?\} Dah2InputEvent;", source, re.S).group()
body = re.search(r"static void dah2_scripted_xinput_get_state\(void\)\n\{.*?^\}", source, re.M | re.S).group()
counter_lines = [
    "    g_dah2_input_polls = poll + 1u;\n",
    "    g_dah2_input_latest_packet = packet;\n",
    "    g_dah2_input_latest_buttons = (uint32_t)(state[4] | ((unsigned)state[5] << 8));\n",
    "    g_dah2_input_latest_delta_bits = caller_delta_bits;\n",
    "    memcpy((void *)g_dah2_input_latest_sticks, state + 14,\n",
    "           sizeof(g_dah2_input_latest_sticks));\n",
]
for line in counter_lines:
    assert body.count(line) == 1
assert body.index(counter_lines[0]) > body.index("memcpy(manual_mem8(output), state, sizeof(state))")
assert body.index(counter_lines[0]) < body.index("    ++poll;")
prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static unsigned char memory[0x40000],expected[0x40000];
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,ebp;
volatile uint32_t g_dah2_input_polls,g_dah2_input_latest_packet,g_dah2_input_latest_buttons;
volatile uint32_t g_dah2_input_latest_delta_bits;
volatile int16_t g_dah2_input_latest_sticks[4];
#define DAH2_INPUT_HANDLE_BASE 0xDA220000u
#define MEM32(a) (*(uint32_t *)(memory+(uint32_t)(a)))
static unsigned char *manual_mem8(uint32_t a) {CHECK(a<sizeof(memory));return memory+a;}
static int dah2_hidden_input_enabled(void) {return 1;}
static void dah2_live_input_fill(unsigned char *state, unsigned port) {(void)state;(void)port;}
'''
suffix = r'''
int main(void) {
    unsigned packets[]={1,1,2,3,4,5,5,5};
    for(unsigned poll=0;poll<8;++poll) {
        unsigned char wanted[22]={0};
        uint32_t packet=packets[poll];
        uint16_t buttons=poll==2 ? 0x10 : 0;
        const uint32_t initial=0x10000,output=poll==7?0x88000000:0x20000;
        memset(memory,0xCD,sizeof(memory));
        eax=0xAABBCCDD;ecx=1;edx=2;esp=initial;ebx=3;esi=4;edi=5;ebp=6;
        MEM32(esp)=0x10295D;MEM32(esp+4)=0xDA220000;MEM32(esp+8)=output;
        MEM32(esp+0x38)=0x3D072B02;
        memcpy(expected,memory,sizeof(memory));
        memcpy(wanted,&packet,4);memcpy(wanted+4,&buttons,2);
        if(poll==4) {
            unsigned char analog[]={12,34,56,78,90,123,200,255};
            int16_t sticks[]={-32768,32767,-1,1};
            memcpy(wanted+6,analog,sizeof(analog));memcpy(wanted+14,sticks,sizeof(sticks));
        }
        if(poll<7) memcpy(expected+output,wanted,sizeof(wanted));
        dah2_scripted_xinput_get_state();
        CHECK(eax==0 && esp==initial+12);
        CHECK(ecx==1 && edx==2 && ebx==3 && esi==4 && edi==5 && ebp==6);
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        CHECK(g_dah2_input_polls==poll+1);
        CHECK(g_dah2_input_latest_packet==packet);
        CHECK(g_dah2_input_latest_buttons==buttons);
        CHECK(g_dah2_input_latest_delta_bits==0x3D072B02);
        CHECK(memcmp((const void *)g_dah2_input_latest_sticks,wanted+14,8)==0);
    }
    {
        const uint32_t initial=0x10000,output=0x20000;
        memset(memory,0xCD,sizeof(memory));
        eax=0xAABBCCDD;esp=initial;MEM32(esp)=0x10295D;MEM32(esp+4)=0xBAD00000;MEM32(esp+8)=output;
        memcpy(expected,memory,sizeof(memory));
        dah2_scripted_xinput_get_state();
        CHECK(eax==0x48F && esp==initial+12);
        CHECK(memcmp(memory,expected,sizeof(memory))==0);
        CHECK(g_dah2_input_polls==8 && g_dah2_input_latest_packet==5);
    }
    puts("PASS: eight exact Xbox polls plus invalid-handle rejection; timing/buttons/axes, port ABI, RET8, RAM/GPRs");
    return 0;
}
'''
vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
with tempfile.TemporaryDirectory(prefix="dah2-input-counter-") as directory:
    out=Path(directory)
    schedule=out/"schedule.txt"
    schedule.write_text("2 1 0010 0 0 0 0 0 0\n4 1 0000 12 34 -32768 32767 -1 1 56 78 90 123 200 255\n",encoding="utf-8")
    (out/"counter.c").write_text(prefix+event+"\n"+body+suffix,encoding="utf-8")
    build_cmd=out/"build.cmd"
    build_cmd.write_text(f'@call "{vcvars}" >nul\n@cl /nologo /Od /TC counter.c /Fe:counter.exe\n',encoding="utf-8")
    compiled=subprocess.run(["cmd.exe", "/d", "/c", "build.cmd"],cwd=out,
                            capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if compiled.returncode:
        print(compiled.stdout+compiled.stderr)
    compiled.check_returncode()
    result=subprocess.run([str(out/"counter.exe")],env=dict(os.environ,DAH2_INPUT_SCRIPT=str(schedule)),
                          capture_output=True,text=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        print(result.stdout+result.stderr)
    result.check_returncode()
    print(result.stdout,end="")
