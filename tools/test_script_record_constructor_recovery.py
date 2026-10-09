"""Retail script-record constructor; modeled reader/vector/hash/allocator ABI.
Exercises empty/skipped/populated script paths, nested numeric/string records,
RET8/nonvolatiles and exact object/vector RAM. Not actual Lua or menu playback.
"""
from pathlib import Path
import hashlib,json,re,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator
from tools.recomp.function_extents import apply_function_extents
image=(ROOT/"game_files/default.xbe").read_bytes()
config.configure_from_xbe(str(ROOT/"game_files/default.xbe"))
database={int(x["start"],16):dict(x,end=int(x["end"],16)) for x in json.loads((ROOT/"xboxrecomp/tools/disasm/output/functions.json").read_text())}
apply_function_extents(image,database,ROOT/"seeds/verified_function_extents.json")
offset=config.va_to_file_offset(0x110790);blob=image[offset:offset+357]
assert hashlib.sha256(blob).hexdigest()=="19ee085f82bbb17472697b3c504369203818b3c8485516b00619294ac99abcbd"
ins=list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(blob,0x110790))
assert len(ins)==117 and ins[-1].address==0x1108F2 and ins[-1].op_str=="8"
actual=re.search(r"^void sub_00110790\(void\)\n\{.*?^\}",(ROOT/"src/recomp/gen/recomp_0007.c").read_text(),re.M|re.S).group()
fresh=FunctionTranslator(image,database).translate_function(0x110790,database[0x110790])
assert actual==fresh[fresh.index("void sub_00110790(void)"):].strip()
historical=actual.replace("goto loc_001108E9;","{ esp += 4; return; }",1)
assert historical!=actual
native=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t eax,ebx,ecx,edx,esp,esi,edi,g_ebp,g_seh_ebp;
static uint8_t memory[0x20000],expected[0x20000];
typedef union {float f[4];uint32_t u[4];} Xmm;
static Xmm xmm0;
static double g_fp_stack[8];static unsigned g_fp_top;
static unsigned mode,outer,inner,alloc_calls,append_calls,number_calls,hash_calls;
#define OBJ 0x1000u
#define READER 0x2000u
#define ARRAY 0x3000u
#define TYPE_NUM 0x6000u
#define TYPE_STR 0x6100u
#define VALUE_STR 0x6200u
static void *at(uint32_t a,unsigned n){CHECK(a<=sizeof(memory)-n);return memory+a;}
#define XBOX_PTR(a) ((uintptr_t)at((uint32_t)(a),1))
#define MEM32(a) (*(uint32_t*)at((uint32_t)(a),4))
#define MEM8(a) (*(uint8_t*)at((uint32_t)(a),1))
#define MEMF(a) (*(float*)at((uint32_t)(a),4))
#define PUSH32(s,v) do{uint32_t value=(v);(s)-=4;MEM32(s)=value;}while(0)
#define POP32(s,v) do{(v)=MEM32(s);(s)+=4;}while(0)
#define LO8(v) ((uint8_t)(v))
#define TEST_Z(a,b) (((a)&(b))==0)
#define TEST_NZ(a,b) (((a)&(b))!=0)
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
static Xmm scalar(float value){Xmm x={{value,0,0,0}};return x;}
#define XMM_SCALAR(v) scalar(v)
#define XMM_ZERO() scalar(0)
static void sub_000F96C0(void){CHECK(MEM32(esp)==0x1107B4&&MEM32(esp+4)==64);alloc_calls++;eax=ARRAY;esp+=4;}
static void sub_001AEEC0(void){CHECK(ecx==READER);esp+=4;eax=0x5555;}
static void sub_001AF0E0(void){
 CHECK(ecx==READER);uint32_t ra=MEM32(esp),arg=MEM32(esp+4);esp+=8;
 if(ra==0x1107D1){CHECK(arg==2);eax=mode!=0;outer=0;}
 else if(ra==0x110819){CHECK(arg==100+outer);eax=1;inner=0;}
 else if(ra==0x110883){CHECK(arg==100+outer);eax=++inner<2;}
 else {CHECK(ra==0x1108E1&&arg==2);eax=++outer<2;}
}
static void sub_001AEE70(void){CHECK(ecx==READER);eax=MEM32(esp)==0x1107E7?100+outer:200+inner;esp+=4;}
static void sub_001AF320(void){CHECK(ecx==READER&&MEM32(esp+4)==100+outer);eax=mode>=2;esp+=8;}
static void sub_001AF400(void){
 CHECK(ecx==READER);uint32_t ra=MEM32(esp),arg=MEM32(esp+4);
 if(ra==0x110834){CHECK(arg==199+inner);eax=inner?TYPE_STR:TYPE_NUM;}
 else {CHECK(ra==0x110853&&arg==201);eax=VALUE_STR;}
 esp+=8;
}
static void sub_0013B3A0(void){
 CHECK(edx==0);
 if(ecx==TYPE_NUM)eax=0x0D33B8A8;
 else if(ecx==TYPE_STR)eax=0xCB28D32D;
 else {CHECK(ecx==VALUE_STR+1);eax=0x12345678+outer;hash_calls++;}
 esp+=4;
}
static void sub_001AF3F0(void){
 CHECK(ecx==READER&&MEM32(esp+4)==200);number_calls++;
 g_fp_top=(g_fp_top+7)&7;g_fp_stack[g_fp_top]=(outer+1)*1.25;esp+=8;
}
static void sub_001AF120(void){CHECK(ecx==READER);esp+=4;eax=0x4444;}
static void sub_00110550(void){
 CHECK(ecx==OBJ&&MEM32(esp)==0x1108B7);
 CHECK(MEM32(esp+4)==ARRAY+outer*8+8&&MEM32(esp+8)==ARRAY+outer*8);
 CHECK(MEM32(OBJ+4)==outer);MEM32(OBJ+4)++;append_calls++;esp+=12;eax=0;
}
BODY
int main(void){
 unsigned count=0;
 for(mode=0;mode<4;mode++)for(unsigned n=0;n<128;n++){
  memset(memory,0xA5,sizeof(memory));MEM8(VALUE_STR)=mode==3?'!':'#';
  MEM32(0x1F000)=0xCAFEBABE;MEM32(0x1F004)=READER;MEM32(0x1F008)=2;
  memcpy(expected,memory,sizeof(memory));uint32_t zero=0,eight=8,array=ARRAY,rows=mode>=2?2:0;
  memcpy(expected+OBJ,&zero,4);memcpy(expected+OBJ+4,&rows,4);
  memcpy(expected+OBJ+8,&eight,4);memcpy(expected+OBJ+12,&array,4);
  if(mode>=2)for(unsigned i=0;i<2;i++){
   float value=(i+1)*1.25f;uint32_t key=mode==3?0:0x12345678+i;
   memcpy(expected+ARRAY+i*8,&value,4);memcpy(expected+ARRAY+i*8+4,&key,4);
  }
  alloc_calls=append_calls=number_calls=hash_calls=outer=inner=0;
  esp=0x1F000;ecx=OBJ;ebx=0x12345678+n;esi=0x87654321-n;edi=0xA1B2C3D4^n;
  g_ebp=g_seh_ebp=0xDEADBEEF;g_fp_top=n&7;
  sub_00110790();
  CHECK(esp==0x1F00C&&eax==OBJ&&ebx==0x12345678+n&&esi==0x87654321-n&&edi==(0xA1B2C3D4^n));
  CHECK(g_ebp==0xDEADBEEF&&g_seh_ebp==0xDEADBEEF&&g_fp_top==(n&7));
  CHECK(alloc_calls==1&&append_calls==rows&&number_calls==rows&&hash_calls==(mode==2?2:0));
  CHECK(!memcmp(memory,expected,0x1E000));CHECK(!memcmp(memory+0x1F00C,expected+0x1F00C,sizeof(memory)-0x1F00C));count++;
 }
 printf("PASS: %u actual constructor cases; empty/skipped/populated reader, nested numeric/string paths, RET8/nonvolatiles and all non-stack RAM\n",count);return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="dah2-script-record-") as tmp:
    directory=Path(tmp)
    vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name,body in (("correct",actual),("historical",historical)):
        (directory/f"{name}.c").write_text(native.replace("BODY",body))
        command=f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 {name}.c /Fe:{name}.exe'
        result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=directory,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stdout+result.stderr
        result=subprocess.run([str(directory/f"{name}.exe")],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==(0 if name=="correct" else 3),result.stdout+result.stderr
        print(result.stdout.strip() if name=="correct" else "PASS: historical empty-reader interior stub / 36-byte stack-leak mutant rejected")
print("PASS: retail hash/357 bytes/117 instructions and exact fresh regeneration")
