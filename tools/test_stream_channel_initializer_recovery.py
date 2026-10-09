"""Byte-verified retail stream initializer; external SDK calls modeled by ABI.
Tests setup errors, all channel groupings, format flags, RET0/nonvolatiles and
release/reset/realize call order. This is not an audio-playback or FPS test.
"""
from pathlib import Path
import hashlib, json, re, subprocess, sys, tempfile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator
image = (ROOT / "game_files/default.xbe").read_bytes()
assert hashlib.sha256(image).hexdigest() == "906871912263ae25de9f1c8e642ec0443b651b4beaf28b05057281ddc58baa1c"
config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
start, end = 0x267D4D, 0x267E3C
offset = config.va_to_file_offset(start)
blob = image[offset:offset+end-start]
assert hashlib.sha256(blob).hexdigest() == "b93960e62d4221da737c19ea0911bf4158c235646035a18eaf1deee79072e372"
ins = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(blob, start))
assert len(ins) == 74 and ins[-1].address == end-1 and ins[-1].mnemonic == "ret"
vtable_offset = config.va_to_file_offset(0x2BA738+0x14)
assert int.from_bytes(image[vtable_offset:vtable_offset+4], "little") == start
manual = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
actual = re.search(r"^void sub_00267D4D\(void\)\n\{.*?^\}", manual, re.M | re.S).group()
meta = dict(start="0x00267D4D", end=end, size=end-start, name="sub_00267D4D",
            section="DSOUND", confidence=0.9, detection_method="call_target",
            num_instructions=74, has_prologue=False, calls_to=[], called_by=[])
fresh = FunctionTranslator(image, {start:meta}).translate_function(start, meta)
fresh = fresh[fresh.index("void sub_00267D4D(void)"):].strip()
for reg in ("eax", "ebx", "ecx", "edx", "esp", "esi", "edi"):
    fresh = re.sub(r"\b"+reg+r"\b", "g_"+reg, fresh)
assert actual == fresh
assert "if (xbox_va == 0x00267D4D) return sub_00267D4D;" in manual
assert any(int(entry["start"],16)==start for entry in json.loads((ROOT/"seeds/manual_functions.json").read_text()))
native = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
static uint8_t memory[0x10000], expected[0x10000];
static uint32_t status, groups, old_groups, active, sequence, release_calls, reset_calls, setup_calls, realize_calls;
#define OBJ 0x1000u
#define FMT 0x2000u
static void *at(uint32_t addr,unsigned n){CHECK(addr<=sizeof(memory)-n);return memory+addr;}
static uint32_t *manual_mem32(uint32_t a){return at(a,4);}
static uint8_t *manual_mem8(uint32_t a){return at(a,1);}
#define MEM32(a) (*manual_mem32(a))
#define MEM8(a) (*manual_mem8(a))
#define MEM16(a) (*(uint16_t*)at(a,2))
#define ZX8(v) ((uint32_t)(uint8_t)(v))
#define ZX16(v) ((uint32_t)(uint16_t)(v))
#define LO8(r) ((uint8_t)((r)&0xFF))
#define SET_LO8(r,v) ((r)=((r)&0xFFFFFF00u)|((uint32_t)(uint8_t)(v)))
#define PUSH32(sp,val) do{sp-=4;*manual_mem32(sp)=(uint32_t)(val);}while(0)
#define POP32(sp,dst) do{dst=*manual_mem32(sp);sp+=4;}while(0)
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define CMP_BE(a,b) ((uint32_t)(a)<=(uint32_t)(b))
#define TEST_Z(a,b) (((a)&(b))==0)
#define TEST_S(a,b) ((int32_t)((a)&(b))<0)
static void sub_00267A94(void){
 CHECK(active && sequence++==0 && g_ecx==OBJ && MEM32(g_esp+4)==0);
 CHECK(MEM32(g_esp)==0x267D64);release_calls++;g_esp+=8;g_eax=0x1234;
}
static void sub_00267732(void){
 CHECK(active && groups!=old_groups && sequence++==1 && g_ecx==OBJ);
 CHECK(MEM32(g_esp)==0x267D7F);reset_calls++;g_esp+=4;g_eax=0x5678;
}
static void sub_002687EF(void){
 CHECK(sequence++==(active?(groups!=old_groups?2u:1u):0u) && g_ecx==OBJ);
 CHECK(MEM32(g_esp)==0x267D86);setup_calls++;g_esp+=4;
 if(!status)MEM8(OBJ+0x64)=(uint8_t)groups;
 g_eax=status;g_edx=0x90909090;g_ecx=0x80808080;
}
static void sub_002696A4(void){
 CHECK(active && !status && g_ecx==OBJ && g_esp==0xF000);
 CHECK(MEM32(g_esp)==0xC0DEC0DE);realize_calls++;g_esp+=4;g_eax=0x76543210;
}
BODY
int main(void){
 const unsigned formats[]={0x10801,0x11001,0x12001,0x10469,0x11803,0x10701,0x10001};
 const unsigned patterns[]={0,0xFFFFFFFF,0x12345678,0x87654321};
 unsigned count=0;
 for(unsigned a=0;a<2;a++)for(unsigned ch=1;ch<=8;ch++)
 for(unsigned f=0;f<7;f++)for(unsigned fail=0;fail<2;fail++)
 for(unsigned p=0;p<4;p++)for(unsigned mismatch=0;mismatch<2;mismatch++){
  memset(memory,0xA5,sizeof(memory));active=a;groups=(ch+1)/2;
  old_groups=mismatch?groups+1:groups;status=fail?0x88780032:0;
  sequence=release_calls=reset_calls=setup_calls=realize_calls=0;
  MEM32(OBJ+0x80)=FMT;MEM8(OBJ+0x12)=0x10|a;MEM8(OBJ+0x64)=old_groups;
  MEM16(FMT+0xC)=formats[f]&0xFFFF;MEM8(FMT+0xE)=ch;MEM8(FMT+0xF)=(formats[f]>>8)&0xFF;
  /* The packed test values above use the high byte as bits-per-sample. */
  MEM8(FMT+0xF)=(formats[f]>>8)&0xFF;
  if(f==0)MEM8(FMT+0xF)=8;
  if(f==1)MEM8(FMT+0xF)=16;
  if(f==2)MEM8(FMT+0xF)=32;
  if(f==3){MEM16(FMT+0xC)=0x69;MEM8(FMT+0xF)=4;}
  if(f==4){MEM16(FMT+0xC)=3;MEM8(FMT+0xF)=24;}
  if(f==5){MEM16(FMT+0xC)=1;MEM8(FMT+0xF)=7;}
  if(f==6){MEM16(FMT+0xC)=1;MEM8(FMT+0xF)=0;}
  if(f<3)MEM16(FMT+0xC)=1;
  MEM32(OBJ+0x84)=patterns[p];MEM32(0xF000)=0xC0DEC0DE;
  memcpy(expected,memory,sizeof(memory));
  if(!fail){
   uint32_t flags=patterns[p];
   if(f==3)flags=(flags&0xFFFEFFFFu)|0x20000;
   if(f==0)flags&=~0x30000u;
   if(f==1)flags=(flags&0xFFFDFFFFu)|0x10000;
   if(f==2)flags|=0x30000;
   flags=(flags&~0x7C0000u)|(((ch-1)<<18)&0x7C0000);
   flags=ch>1?flags|0x800000:flags&0xFF7FFFFF;
   memcpy(expected+OBJ+0x84,&flags,4);expected[OBJ+0x64]=groups;
  }
  g_esp=0xF000;g_ecx=OBJ;g_eax=0x12121212;g_ebx=0xABCDEF12;
  g_esi=0x13579BDF;g_edi=0x2468ACE0;g_ebp=g_seh_ebp=0xDEADBEEF;
  sub_00267D4D();
  CHECK(g_esp==0xF004 && g_ebx==0xABCDEF12 && g_esi==0x13579BDF && g_edi==0x2468ACE0);
  CHECK(g_ebp==0xDEADBEEF && g_seh_ebp==0xDEADBEEF);
  CHECK(release_calls==a && reset_calls==(a&&mismatch) && setup_calls==1 && realize_calls==(a&&!fail));
  CHECK(g_eax==(a&&!fail?0x76543210:status));
  CHECK(!memcmp(memory,expected,0xE000));
  CHECK(!memcmp(memory+0xF000,expected+0xF000,sizeof(memory)-0xF000));
  count++;
 }
 printf("PASS: %u actual initializer cases; RET0, nonvolatiles, failures, PCM/ADPCM flags, channel groups and call order\n",count);return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="dah2-stream-channel-") as temporary:
    directory=Path(temporary)
    vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    (directory/"probe.c").write_text(native.replace("BODY",actual))
    command=f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 probe.c /Fe:probe.exe'
    result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=directory,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode==0,result.stdout+result.stderr
    result=subprocess.run([str(directory/"probe.exe")],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode==0,result.stdout+result.stderr
    print(result.stdout.strip())
print("PASS: retail XBE/hash/74 instructions/vtable target, fresh translated body, manual dispatch and regeneration seed")
