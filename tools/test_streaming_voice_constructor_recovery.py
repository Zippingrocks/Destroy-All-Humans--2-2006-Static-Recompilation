"""Actual byte-verified streaming constructor; modeled external resource/SDK ABI.

Covers RET8, nonvolatile preservation, complete object contents, resource failure,
non-PCM rejection, PCM capability branches, rounded packet/allocation sizing and
all eight exercised resource indices. Does not claim actual stream playback.
"""
from pathlib import Path
import hashlib, json, re, subprocess, sys, tempfile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.function_extents import apply_function_extents
from tools.recomp.translator import FunctionTranslator
image = (ROOT / "game_files/default.xbe").read_bytes()
assert hashlib.sha256(image).hexdigest() == "906871912263ae25de9f1c8e642ec0443b651b4beaf28b05057281ddc58baa1c"
config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
database = {int(x["start"], 16): dict(x, end=int(x["end"], 16))
            for x in json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())}
apply_function_extents(image, database, ROOT / "seeds/verified_function_extents.json")
actual = re.search(r"^void sub_001AE2F0\(void\)\n\{.*?^\}", (ROOT / "src/recomp/gen/recomp_0011.c").read_text(), re.M | re.S).group()
fresh = FunctionTranslator(image, database).translate_function(0x1AE2F0, database[0x1AE2F0])
assert actual == fresh[fresh.index("void sub_001AE2F0(void)"):].strip()
offset = config.va_to_file_offset(0x1AE2F0)
blob = image[offset:offset+414]
assert hashlib.sha256(blob).hexdigest() == "d0ee7305d3df3c113e8ba11f52c661aa3673e5f803da062e2cf93d980e8c6099"
ins = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(blob, 0x1AE2F0))
assert len(ins) == 131 and ins[-1].address == 0x1AE48B and ins[-1].op_str == "8"
historical = actual[:actual.index("    MEM32(esi + 8) = 0x2B8AB8;")] + "\n}\n"
native = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t eax,ebx,ecx,edx,esi,edi,esp,g_ebp,g_seh_ebp;
static unsigned char memory[0x300000],expected[0x300000];
static unsigned mode,index_arg,cap,alloc_size,calls[5];
#define OBJ 0x40000u
#define VOICE 0x60000u
#define RES 0x80000u
#define FMT 0xA0000u
static void *at(unsigned char *ram,uint32_t a,unsigned n){CHECK(a<=sizeof(memory)-n);return ram+a;}
#define MEM8(a) (*(uint8_t *)at(memory,(uint32_t)(a),1))
#define MEM16(a) (*(uint16_t *)at(memory,(uint32_t)(a),2))
#define MEM32(a) (*(uint32_t *)at(memory,(uint32_t)(a),4))
#define SMEM32(a) (*(int32_t *)at(memory,(uint32_t)(a),4))
#define EM8(a) (*(uint8_t *)at(expected,(uint32_t)(a),1))
#define EM32(a) (*(uint32_t *)at(expected,(uint32_t)(a),4))
#define LO8(v) ((uint8_t)(v))
#define LO16(v) ((uint16_t)(v))
#define ZX16(v) ((uint32_t)(uint16_t)(v))
#define SET_LO8(v,x) ((v)=((v)&0xFFFFFF00u)|(uint8_t)(x))
#define TEST_Z(a,b) (((a)&(b))==0)
#define CMP_NE(a,b) ((a)!=(b))
#define CMP_GE(a,b) ((int32_t)(a)>=(int32_t)(b))
#define g_esp esp
#define PUSH32(s,v) do {uint32_t value=(v);(s)-=4;MEM32(s)=value;}while(0)
#define POP32(s,v) do {(v)=MEM32(s);(s)+=4;}while(0)
static uint32_t sample_start,sample_length;
static void sub_001552D0(void){calls[0]++;eax=0x10000;esp+=4;}
static void resource_call(uint32_t target,uint32_t pre_sp){
    CHECK(target==0x30000 && ecx==0x10000 && esp==pre_sp-16);
    CHECK(MEM32(esp+4)==0x270248B1);
    CHECK(MEM32(esp+8)==MEM32(RES+index_arg*24+0x20));
    CHECK(MEM32(esp+12)==OBJ+0x4C);
    calls[1]++;
    if(mode!=0){MEM32(OBJ+0x4C)=0xFACE;MEM32(OBJ+0x50)=sample_start;MEM32(OBJ+0x54)=sample_length;}
    eax=mode!=0;esp+=16;
}
#define RECOMP_ICALL_SAFE(t,s) resource_call((t),(s))
static void sub_001CE579(void){CHECK(mode==2||mode==3);calls[2]++;eax=cap;esp+=4;}
static void sub_002654F0(void){
    uint32_t desc=MEM32(esp+4),out=MEM32(esp+8);
    unsigned pcm=mode>=2;
    CHECK(MEM32(desc)==(0x40000u|(pcm?0x10u:0)));
    CHECK(MEM32(desc+4)==3 && MEM32(desc+8)==FMT);
    CHECK(MEM32(desc+12)==0 && MEM32(desc+16)==0);
    CHECK(MEM32(desc+20)==(pcm?(cap?0x2EC36C:0x2EC364):(RES+index_arg*24+0x14)));
    CHECK(out==OBJ+0xC);
    calls[3]++;MEM32(out)=0x120000;eax=0;esp+=12;
}
static void sub_00263974(void){CHECK(MEM32(esp+4)==0x120000&&MEM32(esp+8)==0);calls[4]++;eax=0;esp+=12;}
static void sub_000F96C0(void){alloc_size=MEM32(esp+4);eax=0xD0000;esp+=4;}
BODY
int main(void){
 for(unsigned n=0;n<256;n++){
    mode=n%5;index_arg=(n/5)%8;cap=(n&1)?0x10000:0;
    unsigned channels=1+(n%4),align=1+(n%23),pcm=mode>=2;
    sample_start=n*19;sample_length=(n&2)?19:1000000;
    memset(memory,0xA5,sizeof(memory));memset(calls,0,sizeof(calls));alloc_size=0;
    MEM32(0x10000)=0x20000;MEM32(0x20000+0x30)=0x30000;
    MEM32(VOICE+0x5C)=RES;MEM16(VOICE+0x60)=pcm?3:1;
    MEM8(RES+0xA)=n&1;
    for(unsigned i=0;i<8;i++){MEM32(RES+i*24+0x1C)=FMT;MEM32(RES+i*24+0x20)=0xABC000+i;}
    MEM16(FMT+2)=mode==4?2:1;MEM16(FMT+0xC)=align;
    if(!pcm)MEM16(FMT+2)=channels;
    MEM32(0x2FF000)=0x11223344;MEM32(0x2FF004)=VOICE;MEM32(0x2FF008)=index_arg;
    memcpy(expected,memory,sizeof(memory));
    EM32(OBJ)=0x2B8ABC;EM32(OBJ+4)=0;EM32(OBJ+8)=0x2B8AB8;
    EM32(OBJ+0xC)=0;EM32(OBJ+0x10)=0;EM32(OBJ+0x14)=0;
    EM32(OBJ+0x30)=0;EM32(OBJ+0x44)=0;EM8(OBJ+0x48)=0;
    unsigned success=(mode!=0&&mode!=4),packet=0;
    if(mode!=0){EM32(OBJ+0x4C)=0xFACE;EM32(OBJ+0x50)=sample_start;EM32(OBJ+0x54)=sample_length;}
    if(success){
        unsigned actual_channels=MEM16(FMT+2);
        unsigned base=actual_channels*32768;
        packet=((base+align-1)/align)*align;
        EM32(OBJ+0xC)=0x120000;
        for(unsigned off=0x18;off<=0x2C;off+=4)EM32(OBJ+off)=0;
        EM32(OBJ+0x30)=sample_start;EM32(OBJ+0x34)=sample_length;
        EM32(OBJ+0x3C)=packet;EM32(OBJ+0x38)=sample_length<packet?sample_length:packet;
        EM32(OBJ+0x40)=(packet+15)&~15u;EM32(OBJ+0x44)=0xD0000;
        EM8(OBJ+0x48)=n&1;
    }
    esp=0x2FF000;ecx=OBJ;ebx=0x12345678;esi=0x87654321;edi=0x99AA55CC;
    g_ebp=g_seh_ebp=0xDEADBEEF;
    sub_001AE2F0();
    CHECK(esp==0x2FF00C&&eax==OBJ&&ebx==0x12345678&&esi==0x87654321&&edi==0x99AA55CC);
    CHECK(g_ebp==0xDEADBEEF&&g_seh_ebp==0xDEADBEEF);
    CHECK(calls[0]==1&&calls[1]==1&&calls[2]==((mode==2||mode==3)?1:0));
    CHECK(calls[3]==success&&calls[4]==success);
    CHECK(alloc_size==(success?3*((packet+15)&~15u):0));
    CHECK(!memcmp(memory,expected,0x2FC000));
    CHECK(!memcmp(memory+0x2FF000,expected+0x2FF000,sizeof(memory)-0x2FF000));
 }
 puts("PASS: 256 actual streaming-constructor cases; RET8/nonvolatiles, both failure paths, PCM capability, packet rounding, eight resource indices and complete non-stack RAM");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="dah2-stream-ctor-") as temporary:
    directory=Path(temporary)
    vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name,body in (("correct",actual),("historical",historical)):
        (directory/f"{name}.c").write_text(native.replace("BODY",body))
        command=f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 {name}.c /Fe:{name}.exe'
        result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=directory,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stdout+result.stderr
        result=subprocess.run([str(directory/f"{name}.exe")],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==(0 if name=="correct" else 3),result.stdout+result.stderr
        print(result.stdout.strip() if name=="correct" else "PASS: historical 56-byte stack-leak mutant rejected")
print("PASS: exact retail XBE/range hashes, 131 instructions and fresh regeneration")
