"""Retail 115-byte object-vector cleanup; modeled child-unlink/destructor ABI.
Proves empty/nonempty/null-entry paths restore all four saved registers and RET0,
and clear the vector without touching other non-stack RAM. Not a menu/FPS test.
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
offset=config.va_to_file_offset(0x11A340);blob=image[offset:offset+115]
assert hashlib.sha256(blob).hexdigest()=="23a78e303dfbf309dc13f5255be7b94045bccf788cb5c58a556fe7fe3908f9f2"
ins=list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(blob,0x11A340))
assert len(ins)==51 and ins[-1].address==0x11A3B2 and ins[-1].mnemonic=="ret"
actual=re.search(r"^void sub_0011A340\(void\)\n\{.*?^\}",(ROOT/"src/recomp/gen/recomp_0007.c").read_text(),re.M|re.S).group()
fresh=FunctionTranslator(image,database).translate_function(0x11A340,database[0x11A340])
assert actual==fresh[fresh.index("void sub_0011A340(void)"):].strip()
historical=actual[:actual.index("\nloc_0011A37B:")]
historical=historical.replace("goto loc_0011A382;","{ g_seh_ebp=ebp;sub_0011A382();return; }")
historical=historical.replace("goto loc_0011A37B;","{ g_seh_ebp=ebp;sub_0011A37B();return; }")
historical+="\n    g_seh_ebp=ebp;sub_0011A37B();return;\n}\n"
native=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t eax,ebx,ecx,edx,esp,esi,edi,g_ebp,g_seh_ebp;
static unsigned char memory[0x20000],expected[0x20000];
static unsigned unlink_calls,dtor_calls,cancel,current;
#define OBJ 0x1000u
#define LINK 0x2000u
#define ARRAY 0x3000u
#define CHILD(i) (0x4000u+(i)*0x100u)
static void *at(uint32_t a,unsigned n){CHECK(a<=sizeof(memory)-n);return memory+a;}
#define MEM32(a) (*(uint32_t*)at((uint32_t)(a),4))
#define PUSH32(s,v) do{uint32_t value=(v);(s)-=4;MEM32(s)=value;}while(0)
#define POP32(s,v) do{(v)=MEM32(s);(s)+=4;}while(0)
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define TEST_Z(a,b) (((a)&(b))==0)
#define g_esp esp
static void sub_0011BE50(void){
 CHECK(ecx==LINK&&MEM32(esp)==0x11A368);
 uint32_t child=MEM32(esp+4)-0xB0;CHECK(child>=CHILD(0)&&child<=CHILD(7));
 current=(child-CHILD(0))/0x100;CHECK(MEM32(ARRAY+current*4)==child);
 unlink_calls++;if(cancel)MEM32(ARRAY+current*4)=0;
 eax=0x11111111;ecx=0x22222222;edx=0x33333333;esp+=8;
}
static void destructor(uint32_t target,uint32_t pre_sp){
 CHECK(target==0x123450&&MEM32(esp)==0x11A375&&MEM32(esp+4)==1&&esp==pre_sp-8);
 CHECK(ecx==CHILD(current)&&!cancel);dtor_calls++;eax=0;ecx=0;edx=0;esp+=8;
}
#define RECOMP_ICALL_SAFE(target,sp) destructor(target,sp)
static void sub_001C5270(void){CHECK(0);}
/* Faithful historical empty-vector target: unresolved interior stub. */
static void sub_0011A382(void){esp+=4;}
static void sub_0011A37B(void){CHECK(0);}
BODY
int main(void){
 unsigned count=0;
 for(unsigned length=0;length<=8;length++)for(unsigned mask=0;mask<(1u<<length);mask++)for(unsigned mode=0;mode<2;mode++){
  memset(memory,0xA5,sizeof(memory));MEM32(OBJ+4)=length;MEM32(OBJ+0xC)=ARRAY;
  for(unsigned i=0;i<length;i++){MEM32(ARRAY+i*4)=(mask&(1u<<i))?CHILD(i):0;MEM32(CHILD(i))=0x5000;}
  MEM32(0x5000+0x24)=0x123450;MEM32(0x1F000)=0xCAFEBABE;
  memcpy(expected,memory,sizeof(memory));
  uint32_t zero=0;memcpy(expected+OBJ+4,&zero,4);
  for(unsigned i=0;i<length;i++)memcpy(expected+ARRAY+i*4,&zero,4);
  unlink_calls=dtor_calls=0;cancel=mode;
  esp=0x1F000;ecx=OBJ;edx=LINK;ebx=0x12345678;esi=0x87654321;edi=0xA1B2C3D4;g_ebp=g_seh_ebp=0xDEADBEEF;
  sub_0011A340();
  CHECK(esp==0x1F004&&ebx==0x12345678&&esi==0x87654321&&edi==0xA1B2C3D4&&g_ebp==0xDEADBEEF&&g_seh_ebp==0xDEADBEEF&&eax==0);
  unsigned nonnull=0;for(unsigned i=0;i<length;i++)nonnull+=(mask>>i)&1;
  CHECK(unlink_calls==nonnull&&dtor_calls==(cancel?0:nonnull));
  CHECK(!memcmp(memory,expected,0x1E000));
  CHECK(!memcmp(memory+0x1F000,expected+0x1F000,sizeof(memory)-0x1F000));count++;
 }
 printf("PASS: %u actual vector-cleanup cases; empty/null/nonempty, unlink cancellation, RET0/four saved registers and all non-stack RAM\n",count);return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="dah2-vector-cleanup-") as tmp:
    directory=Path(tmp)
    vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name,body in (("correct",actual),("historical",historical)):
        (directory/f"{name}.c").write_text(native.replace("BODY",body))
        command=f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 {name}.c /Fe:{name}.exe'
        result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=directory,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stdout+result.stderr
        result=subprocess.run([str(directory/f"{name}.exe")],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==(0 if name=="correct" else 3),result.stdout+result.stderr
        print(result.stdout.strip() if name=="correct" else "PASS: historical empty-vector stub / 16-byte stack-leak mutant rejected")
print("PASS: retail hash/115 bytes/51 instructions and exact fresh regeneration")
