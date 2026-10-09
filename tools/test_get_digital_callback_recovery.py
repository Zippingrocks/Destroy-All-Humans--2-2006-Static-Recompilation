"""Verify restored retail Input.GetDigital bytes, reproducibility and native ABI.

Executes the actual callback, digital-state lookup and boolean-result bridge.
Only Lua integer argument access and TValue push primitives are test models.
No game process or GUI is started.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'xboxrecomp'))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator
from tools.disasm.loader import load_image
from tools.disasm.engine import DisasmEngine
from tools.disasm.functions import FunctionDetector
START,END=0x1145C0,0x114614
xbe=ROOT/'game_files/default.xbe'
image=xbe.read_bytes()
assert hashlib.sha256(image).hexdigest()=='906871912263ae25de9f1c8e642ec0443b651b4beaf28b05057281ddc58baa1c'
config.configure_from_xbe(str(xbe))
def raw(va,n):
    section=next(s for s in config._SECTIONS if s.va<=va<s.va+s.raw_size)
    offset=section.raw_addr+va-section.va
    return image[offset:offset+n]
retail=list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(raw(START,END-START),START))
assert len(retail)==30 and sum(i.size for i in retail)==84
assert retail[-1].address==END-1 and retail[-1].mnemonic=='ret' and not retail[-1].op_str
assert raw(END,12)==b'\xCC'*12
# The real detector finds the verified end after receiving the new start seed;
# this function needs no special extent override after normal discovery.
normal_image=load_image(str(xbe),str(ROOT/'game_files/analysis.json'))
engine=DisasmEngine(normal_image)
engine.decode_at(START, max_insns=30)
detector=FunctionDetector(engine,normal_image,None,None)
assert detector._find_function_end(START,0x114620,0x225CA0)==END
assert raw(0x114A11,5)==b'\x68\xC0\x45\x11\x00'
assert raw(0x2AF6E8,11)==b'GetDigital\0'
assert next(i for i in retail if i.address==0x1145D8).op_str=='0x1145fd'
assert [(i.mnemonic,i.op_str) for i in retail[-5:]]==[
    ('pop','edi'),('mov','eax, 1'),('pop','esi'),('add','esp, 8'),('ret','')]
entries=json.loads((ROOT/'xboxrecomp/tools/disasm/output/functions.json').read_text())
database={}
for entry in entries:
    address=int(entry['start'],16)
    entry=dict(entry,end=int(entry['end'],16));database[address]=entry
info=dict(database.get(START,{}),end=END,size=END-START)
database[START]=info
code=FunctionTranslator(image,database).translate_function(START,info)
fresh=code[code.index('void sub_001145C0(void)'):].strip()
def function(path,name):
    text=path.read_text(encoding='utf-8')
    found=re.search(r'^void '+name+r'\(void\)\n\{.*?^\}',text,re.M|re.S)
    assert found,name
    return found.group()
body=function(ROOT/'src/recomp/gen/recomp_0007.c','sub_001145C0')
assert body==fresh,'Callback differs from fresh verified retail translation'
assert (ROOT/'src/recomp/gen/recomp_funcs.h').read_text().count('void sub_001145C0(void);')==1
assert (ROOT/'src/recomp/gen/recomp_dispatch.c').read_text().count('{ 0x001145C0u, (recomp_func_t)sub_001145C0 },')==1
seeds=json.loads((ROOT/'seeds/manual_functions.json').read_text())
assert sum(int(e['start'],16)==START for e in seeds)==1
prefix=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static unsigned char memory[0x400000],before[0x400000];
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,g_ebp,g_seh_ebp;
#define MEM32(a) (*(uint32_t *)(memory+(uint32_t)(a)))
#define MEM8(a) (*(uint8_t *)(memory+(uint32_t)(a)))
#define PUSH32(s,v) do {(s)-=4;MEM32(s)=(uint32_t)(v);}while(0)
#define POP32(s,r) do {(r)=MEM32(s);(s)+=4;}while(0)
#define LO8(v) ((v)&255u)
#define SET_LO8(v,b) ((v)=((v)&0xFFFFFF00u)|((uint32_t)(b)&255u))
#define ZX8(v) ((uint32_t)(uint8_t)(v))
#define CMP_AE(a,b) ((uint32_t)(a)>=(uint32_t)(b))
#define TEST_Z(a,b) (((a)&(b))==0)
static uint32_t lua_port,lua_button;
static unsigned argcalls,argindices[2],pushes;
static const uint32_t lua=0x1000,luaout=0x1100,inputbase=0x2000;
void sub_001027B0(void),sub_00102460(void),sub_001026A0(void),sub_001AEEA0(void);
static void sub_001AF3D0(void) {
    CHECK(ecx==lua && argcalls<2);
    uint32_t index=MEM32(esp+4);argindices[argcalls++]=index;
    CHECK(MEM32(esp)==(index==2?0x1145D3:0x1145E3));
    CHECK(index==1 || index==2);eax=index==1?lua_port:lua_button;edx=index;esp+=8;
}
static void sub_00210DF0(void) {
    CHECK(ecx==lua && MEM32(esp)==0x1AEEBA && MEM32(lua)==luaout);
    MEM32(luaout)=1;MEM32(lua)=luaout+8;++pushes;esp+=4;
}
static void sub_00210E20(void) {
    CHECK(ecx==lua && MEM32(esp)==0x114609 && MEM32(esp+4)==0x3F800000 && MEM32(lua)==luaout);
    MEM32(luaout)=2;MEM32(luaout+4)=0x3F800000;MEM32(lua)=luaout+8;++pushes;esp+=8;
}
'''
dependencies='\n'.join([
    function(ROOT/'src/recomp/gen/recomp_0006.c','sub_001027B0'),
    function(ROOT/'src/recomp/gen/recomp_0006.c','sub_00102460'),
    function(ROOT/'src/recomp/gen/recomp_0006.c','sub_001026A0'),
    function(ROOT/'src/recomp/gen/recomp_0011.c','sub_001AEEA0')])
suffix=r'''
static unsigned cases;
static void one(uint32_t port,uint32_t button,unsigned value,unsigned disabled,unsigned poison) {
    const uint32_t sp=0x380000;
    memset(memory,poison,sizeof(memory));
    MEM32(lua)=luaout;MEM32(lua+8)=luaout+128;MEM32(0x2C8BA4)=inputbase;
    for(unsigned p=0;p<4;++p) {
        uint32_t device=inputbase+p*0x24C;MEM32(device)=p;
        for(unsigned b=0;b<16;++b){MEM8(device+0xC+b*20)=0;MEM8(device+0x1C+b*20)=0;}
    }
    int valid=button<16;
    if(valid){uint32_t device=inputbase+(port-1)*0x24C;MEM8(device+0xC+button*20)=value;MEM8(device+0x1C+button*20)=disabled;}
    lua_port=port;lua_button=button;argcalls=pushes=0;argindices[0]=argindices[1]=0;
    eax=0xA1;ecx=lua;edx=0xA2;ebx=0xA3;esi=0x11223344;edi=0x55667788;
    g_ebp=0x11111111;g_seh_ebp=0x22222222;esp=sp;MEM32(sp)=0x2117FD;
    memcpy(before,memory,sizeof(memory));
    sub_001145C0();
    CHECK(eax==1 && esp==sp+4 && esi==0x11223344 && edi==0x55667788 && ebx==0xA3);
    CHECK(g_ebp==0x11111111 && g_seh_ebp==0x22222222);
    CHECK(argcalls==(valid?2:1) && argindices[0]==2 && (!valid || argindices[1]==1));
    CHECK(pushes==1 && MEM32(lua)==luaout+8);
    int truth=valid && value && !disabled;
    CHECK(MEM32(luaout)==(truth?2:1));
    if(truth)CHECK(MEM32(luaout+4)==0x3F800000);
    else CHECK(MEM32(luaout+4)==(poison*0x01010101u));
    /* Only callee stack scratch/return slots and one Lua TValue may change. */
    memcpy(before+sp-64,memory+sp-64,64);memcpy(before+lua,memory+lua,4);memcpy(before+luaout,memory+luaout,8);
    CHECK(!memcmp(before,memory,sizeof(memory)));
    ++cases;
}
int main(void) {
    unsigned values[]={0,1,255},poisons[]={0xCD,0xA5};
    for(unsigned p=1;p<=4;++p)for(unsigned b=0;b<16;++b)for(unsigned v=0;v<3;++v)
    for(unsigned d=0;d<2;++d)for(unsigned z=0;z<2;++z)one(p,b,values[v],d,poisons[z]);
    for(unsigned z=0;z<2;++z){one(99,16,1,0,poisons[z]);one(0,0xFFFFFFFF,1,0,poisons[z]);}
    printf("PASS: %u native GetDigital cases; 4 ports/16 buttons, enabled/disabled, invalid unsigned branches, Lua args 2 then1, number1/nil result, RET0/callee-save and bounded RAM ABI\n",cases);
    return 0;
}
'''
mutants=[('constant_false',body.replace('    MEM8(esp + 8) = LO8(eax);','    MEM8(esp + 8) = 0;')),
         ('missing_esi_restore',body.replace('    POP32(esp, esi);','    esp += 4;'))]
vcvars=Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
with tempfile.TemporaryDirectory(prefix='dah2-get-digital-') as directory:
    out=Path(directory)
    for name,implementation,fail in [('recovered',body,False)]+[(n,c,True) for n,c in mutants]:
        (out/f'{name}.c').write_text(prefix+dependencies+implementation+suffix,encoding='utf-8')
        command=f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
        subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
        result=subprocess.run([str(out/f'{name}.exe')],capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        if fail:
            assert result.returncode==3,(name,result.returncode,result.stdout,result.stderr)
            print('PASS: '+name+' mutant rejected')
        else:
            if result.returncode:print(result.stdout+result.stderr)
            result.check_returncode();print(result.stdout,end='')
print('PASS: exact retail XBE hash, 84-byte/30-instruction registered callback, dispatch/prototype/start seed and regeneration equality')
