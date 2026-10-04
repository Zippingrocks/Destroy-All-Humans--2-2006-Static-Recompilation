"""Execute active complete Bink-success tails that previously leaked 0x2c/0x0c."""
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
md = Cs(CS_ARCH_X86, CS_MODE_32)
def retail(start, end):
    sec = next(s for s in config._SECTIONS if s.va <= start < s.va+s.raw_size)
    off = sec.raw_addr + start-sec.va
    insns = list(md.disasm(image[off:off+end-start], start))
    assert insns and insns[-1].address + insns[-1].size <= end
    return insns
assert len(retail(0x282940,0x282F37)) > 300
assert len(retail(0x282F40,0x2830E3)) > 100

source = (ROOT/"src/recomp/gen/recomp_0014.c").read_text(encoding="utf-8")
def extract(address):
    name=f"sub_{address:08X}"
    return re.search(rf"^void {name}\(void\)\n\{{.*?^\}}",source,re.M|re.S).group()
first,second=extract(0x282940),extract(0x282F40)
assert "goto loc_00282968" in first and "loc_00282EEB:" in first
assert "goto loc_0028307B" in second and "loc_002830DD:" in second
assert not re.search(r"sub_00282(?:968|F37)\(\); return",first)
assert not re.search(r"sub_002830(?:20|47|7A|7B|DD)\(\); return",second)

prefix=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_ebp,g_seh_ebp;
static unsigned char memory[0x400000];
static void *ptr(uint32_t a,unsigned n){if(a>sizeof(memory)-n){fprintf(stderr,"bad %08X\n",a);exit(5);}return memory+a;}
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define MEM32(a) (*(uint32_t*)ptr((uint32_t)(a),4))
#define XBOX_PTR(a) ptr((uint32_t)(a),1)
#define PUSH32(s,v) do{uint32_t t=(v);(s)-=4;MEM32(s)=t;}while(0)
#define POP32(s,v) do{(v)=MEM32(s);(s)+=4;}while(0)
#define CMP_EQ(a,b) ((uint32_t)(a)==(uint32_t)(b))
#define CMP_NE(a,b) ((uint32_t)(a)!=(uint32_t)(b))
#define CMP_L(a,b) ((int32_t)(a)<(int32_t)(b))
#define CMP_LE(a,b) ((int32_t)(a)<=(int32_t)(b))
#define CMP_G(a,b) ((int32_t)(a)>(int32_t)(b))
#define CMP_GE(a,b) ((int32_t)(a)>=(int32_t)(b))
#define CMP_B(a,b) ((uint32_t)(a)<(uint32_t)(b))
#define CMP_BE(a,b) ((uint32_t)(a)<=(uint32_t)(b))
#define CMP_AE(a,b) ((uint32_t)(a)>=(uint32_t)(b))
#define TEST_Z(a,b) (((uint32_t)(a)&(uint32_t)(b))==0)
#define TEST_NZ(a,b) (((uint32_t)(a)&(uint32_t)(b))!=0)
#define RECOMP_ICALL_SAFE(t,s) do{(void)(t);(void)(s);eax=0;esp+=8;}while(0)
static unsigned lock_calls;
static void sub_002827B0(void){esp+=12;}
static void sub_002846D0(void){lock_calls++;eax=0x11223344;esp+=4;}
static void sub_00280650(void){esp+=4;}
static void sub_00284320(void){esp+=12;}
static void sub_002851A0(void){esp+=24;}
static void sub_002843B0(void){esp+=12;}
static void sub_00284350(void){esp+=20;}
static void sub_00280940(void){esp+=4;}
static void sub_002842F0(void){esp+=4;}
static void sub_00284470(void){esp+=4;}
static void sub_00288B20(void){esp+=4;}
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v);return 3;}}while(0)
'''

suffix=r'''
static void set32(uint32_t a,uint32_t v){MEM32(a)=v;}
int main(void){
    const uint32_t object=0x100000,stack=0x3FF000;
    memset(memory,0,sizeof(memory));
    /* 282940: force its former split at 282968, then take a short valid success exit. */
    set32(object+0xC,2);set32(object+0x2EC,1);set32(object+0x2F4,1);
    set32(object+0x2A0,0);set32(object+0x2C8,1);set32(object+0x274,1);
    set32(object+0x300,0);set32(object+0x12C,0);set32(object+0x1C,1);
    for(unsigned i=0;i<7;i++)set32(object+0x2CC+i*4,0x180000+i*0x100);
    set32(object+0x104,0x190000);
    eax=0xAAAA;ecx=0xCCCC;edx=0xDDDD;ebx=0xB0B0B0B0;esi=0x51515151;edi=0xD1D1D1D1;
    g_ebp=0xEBEBEBEB;g_seh_ebp=0xABABABAB;esp=stack-8;set32(esp,0x12345678);set32(esp+4,object);lock_calls=0;
    sub_00282940();
    CHECK(esp==stack && eax==1 && ebx==0xB0B0B0B0 && esi==0x51515151 && edi==0xD1D1D1D1);
    CHECK(lock_calls==1 && MEM32(object+0x2EC)==1);
    /* 282F40: zero streams take former split 28307B and must restore all three pushes. */
    ebx=0xB0B0B0B0;esi=0x51515151;edi=0xD1D1D1D1;g_ebp=0xEBEBEBEB;g_seh_ebp=0xABABABAB;
    esp=stack-8;set32(esp,0x87654321);set32(esp+4,object);set32(object+0x300,0);
    sub_00282F40();
    CHECK(esp==stack && ebx==0xB0B0B0B0 && esi==0x51515151 && edi==0xD1D1D1D1);
    puts("PASS: active Bink success tails restore exact RET4 stack and callee-saved registers");
    return 0;
}
'''

old_first=first.replace("if (CMP_NE(_fa, _fb)) goto loc_00282968;", "if (CMP_NE(_fa, _fb)) { esp += 4; return; }")
old_second=second.replace("if (CMP_BE(_fa, _fb)) goto loc_0028307B;", "if (CMP_BE(_fa, _fb)) { esp += 4; return; }")
assert old_first!=first and old_second!=second
out_root=ROOT/"diagnostics/bink_success_tail_test";out_root.mkdir(exist_ok=True)
out=Path(tempfile.mkdtemp(prefix="run_",dir=out_root))
vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name,a,b in (("recovered",first,second),("historical",old_first,old_second)):
    (out/f"{name}.c").write_text(prefix+a+"\n"+b+suffix,encoding="utf-8")
    command=f'call "{vcvars}" >nul && cl /nologo /Od /W3 /TC {name}.c /Fe:{name}.exe'
    compiled=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if compiled.returncode:print(compiled.stdout+compiled.stderr)
    compiled.check_returncode()
    result=subprocess.run([str(out/f"{name}.exe")],capture_output=True,text=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    if name=="recovered":
        if result.returncode:print(result.stderr)
        result.check_returncode();print(result.stdout,end="")
    else:
        assert result.returncode==3,result
        print("PASS: historical split-tail stack leak rejected")
print(f"PASS: retail extents 282940..282F37 and 282F40..2830E3; artifacts: {out}")
