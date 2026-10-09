"""Actual six-way retail scene factory; external allocator/constructors modeled.
Covers recognized/unknown hashes, allocation failure, exact argument order,
RET8/nonvolatiles and all non-stack RAM. Not scene rendering or FPS evidence.
"""
from pathlib import Path
import hashlib,json,re,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator
image=(ROOT/"game_files/default.xbe").read_bytes()
assert hashlib.sha256(image).hexdigest()=="906871912263ae25de9f1c8e642ec0443b651b4beaf28b05057281ddc58baa1c"
config.configure_from_xbe(str(ROOT/"game_files/default.xbe"))
start,end=0xB3500,0xB363A
offset=config.va_to_file_offset(start);blob=image[offset:offset+end-start]
assert hashlib.sha256(blob).hexdigest()=="d4fffd395dd055fd0fe32f34fd1b9d31a6ed982ba2ef4e55f37b6e014ea2ac95"
ins=list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(blob,start))
assert len(ins)==102 and ins[-1].address==0xB3637 and ins[-1].op_str=="8"
# Retail registration supplies the function pointer in ECX, not a vtable seed.
registration=config.va_to_file_offset(0xB3640)
assert image[registration:registration+5]==bytes.fromhex("B900350B00")
manual=(ROOT/"src/recomp_manual.c").read_text(encoding="utf-8")
actual=re.search(r"^void sub_000B3500\(void\)\n\{.*?^\}",manual,re.M|re.S).group()
meta=dict(start="0x000B3500",end=end,size=end-start,name="sub_000B3500",
          section=".text",confidence=0.95,detection_method="call_target",
          num_instructions=102,has_prologue=False,calls_to=[],called_by=[])
fresh=FunctionTranslator(image,{start:meta}).translate_function(start,meta)
fresh=fresh[fresh.index("void sub_000B3500(void)"):].strip()
for reg in ("eax","ebx","ecx","edx","esp","esi","edi"):
    fresh=re.sub(r"\b"+reg+r"\b","g_"+reg,fresh)
assert actual==fresh
assert "if (xbox_va == 0x000B3500) return sub_000B3500;" in manual
assert any(int(x["start"],16)==start for x in json.loads((ROOT/"seeds/manual_functions.json").read_text()))
native=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
static uint8_t memory[0x20000],expected[0x20000];
static uint32_t fail,branch,alloc_calls,ctor_calls,string_arg,parent_arg,index_arg;
static const uint32_t keys[]={0x57CD50F7,0x4D9F7C0E,0x46D1D806,0x6E736988,0xBBF1AA61,0x79CB183E};
static const uint32_t sizes[]={0x90,0x8C,0x8C,0x8C,0x78,0x8C};
static const uint32_t alloc_ra[]={0xB353B,0xB3566,0xB3591,0xB35BC,0xB35F0,0xB3617};
static const uint32_t ctor_ra[]={0xB3558,0xB3583,0xB35AE,0xB35D5,0xB3609,0xB3630};
#define OBJ 0x1000u
static void *at(uint32_t a,unsigned n){CHECK(a<=sizeof(memory)-n);return memory+a;}
#define MEM32(a) (*(uint32_t*)at((uint32_t)(a),4))
#define PUSH32(s,v) do{uint32_t value=(v);(s)-=4;MEM32(s)=value;}while(0)
#define POP32(s,v) do{(v)=MEM32(s);(s)+=4;}while(0)
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define CMP_A(a,b) ((uint32_t)(a)>(uint32_t)(b))
#define TEST_Z(a,b) (((a)&(b))==0)
static void sub_000F96C0(void){
 CHECK(branch<6&&MEM32(g_esp)==alloc_ra[branch]&&MEM32(g_esp+4)==sizes[branch]);
 alloc_calls++;g_eax=fail?0:OBJ;g_ecx=0xBAD1;g_edx=0xBAD2;g_esp+=4;
}
static void ctor(unsigned called){
 CHECK(called==branch&&g_ecx==OBJ&&MEM32(g_esp)==ctor_ra[called]);
 CHECK(MEM32(g_esp+4)==string_arg&&MEM32(g_esp+8)==index_arg&&MEM32(g_esp+12)==parent_arg);
 MEM32(OBJ)=string_arg;MEM32(OBJ+4)=index_arg;MEM32(OBJ+8)=parent_arg;
 ctor_calls++;g_esp+=16;g_eax=OBJ;g_ecx=0xBAD3;g_edx=0xBAD4;
}
static void sub_000B3850(void){ctor(0);}
static void sub_000B3F90(void){ctor(1);}
static void sub_000B3BE0(void){ctor(2);}
static void sub_000B3F20(void){ctor(3);}
static void sub_000B40C0(void){ctor(4);}
static void sub_000B3F60(void){ctor(5);}
BODY
int main(void){
 uint32_t hashes[22];unsigned count=0;
 for(unsigned i=0;i<6;i++){hashes[i]=keys[i];hashes[6+i*2]=keys[i]-1;hashes[7+i*2]=keys[i]+1;}
 hashes[18]=0;hashes[19]=0xFFFFFFFF;hashes[20]=0x80000000;hashes[21]=0x6E736987;
 for(unsigned h=0;h<22;h++)for(fail=0;fail<2;fail++)for(unsigned n=0;n<64;n++){
  branch=6;for(unsigned i=0;i<6;i++)if(hashes[h]==keys[i])branch=i;
  memset(memory,0xA5,sizeof(memory));g_esp=0x1F000;MEM32(g_esp)=0xCAFEBABE;
  string_arg=0x12340000+n;index_arg=0x56780000-n;parent_arg=0xA1B20000^n;
  MEM32(g_esp+4)=index_arg;MEM32(g_esp+8)=parent_arg;
  memcpy(expected,memory,sizeof(memory));
  if(branch<6&&!fail){memcpy(expected+OBJ,&string_arg,4);memcpy(expected+OBJ+4,&index_arg,4);memcpy(expected+OBJ+8,&parent_arg,4);}
  g_eax=0xF00DFACE;g_ecx=hashes[h];g_edx=string_arg;
  g_ebx=0x22334400+n;g_esi=0x33445500-n;g_edi=0x44556600^n;
  g_ebp=0xDEADBEEF;g_seh_ebp=0xABCD1234;alloc_calls=ctor_calls=0;
  sub_000B3500();
  CHECK(g_esp==0x1F00C&&g_eax==((branch<6&&!fail)?OBJ:0));
  CHECK(g_ebx==0x22334400+n&&g_esi==0x33445500-n&&g_edi==(0x44556600^n));
  CHECK(g_ebp==0xDEADBEEF&&g_seh_ebp==0xABCD1234);
  CHECK(alloc_calls==(branch<6)&&ctor_calls==(branch<6&&!fail));
  CHECK(!memcmp(memory,expected,0x1E000));
  CHECK(!memcmp(memory+0x1F000,expected+0x1F000,sizeof(memory)-0x1F000));
  count++;
 }
 printf("PASS: %u actual factory cases; six constructors, rejected hashes/allocation failure, exact args, RET8/nonvolatiles/full non-stack RAM\n",count);return 0;
}
'''
historical="void sub_000B3500(void) { g_esp += 4; g_eax = 0; }"
with tempfile.TemporaryDirectory(prefix="dah2-scene-factory-") as tmp:
    directory=Path(tmp)
    vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name,body in (("correct",actual),("historical",historical),("wrong_size",actual.replace("PUSH32(g_esp, 0x78);","PUSH32(g_esp, 0x8C);"))):
        assert name!="wrong_size" or body!=actual
        (directory/f"{name}.c").write_text(native.replace("BODY",body))
        command=f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 {name}.c /Fe:{name}.exe'
        result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=directory,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stdout+result.stderr
        result=subprocess.run([str(directory/f"{name}.exe")],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==(0 if name=="correct" else 3),result.stdout+result.stderr
        print(result.stdout.strip() if name=="correct" else f"PASS: {name} mutant rejected")
print("PASS: retail registration/hash/314 bytes/102 instructions, fresh translation, manual dispatch and discovery seed")
