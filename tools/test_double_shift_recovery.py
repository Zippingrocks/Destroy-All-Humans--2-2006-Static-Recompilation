"""SHLD/SHRD data-result regression; no claim about translated live flags.
Executes the actual retail 31-byte 64-bit shift helper on the host, plus freshly
translated 16/32-bit double shifts. Native instruction results are the oracle.
"""
from pathlib import Path
import hashlib, re, struct, subprocess, sys, tempfile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator
image=(ROOT/"game_files/default.xbe").read_bytes()
assert hashlib.sha256(image).hexdigest()=="906871912263ae25de9f1c8e642ec0443b651b4beaf28b05057281ddc58baa1c"
config.configure_from_xbe(str(ROOT/"game_files/default.xbe"))
start=0x1C7B70
offset=config.va_to_file_offset(start)
raw=image[offset:offset+31]
decoder=Cs(CS_ARCH_X86,CS_MODE_32)
instructions=list(decoder.disasm(raw,start))
assert len(instructions)==15 and instructions[-1].address==0x1C7B8E
assert [(i.mnemonic,i.op_str) for i in instructions]==[(i.mnemonic,i.op_str) for i in Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,start)]
meta={"name":"sub_001C7B70","end":start+31,"size":31}
fresh=FunctionTranslator(image,{start:meta}).translate_function(start,meta)
actual=re.search(r"^void sub_001C7B70\(void\)\n\{.*?^\}",(ROOT/"src/recomp/gen/recomp_0012.c").read_text(),re.M|re.S).group()
fresh=fresh[fresh.index("void sub_001C7B70(void)"):].strip()
assert actual==fresh
bodies=[actual]
oracles=[raw]
widths=[64]
for name,hexcode,width in [
 ("shift_left32","0fa5d0c3",32),("shift_right32","0fadd0c3",32),
 ("shift_left16","660fa5d0c3",16),("shift_right16","660fadd0c3",16),
 ("shift_alias32","0fa5c0c3",32),("shift_count_alias32","0fa5c1c3",32)]:
    blob=bytes.fromhex(hexcode);fixture=bytearray(image)
    fixture[offset:offset+len(blob)]=blob
    info={"name":"sub_001C7B70","end":start+len(blob),"size":len(blob)}
    translated=FunctionTranslator(bytes(fixture),{start:info}).translate_function(start,info)
    body=translated[translated.index("void sub_001C7B70(void)"):].strip().replace("sub_001C7B70",name)
    bodies.append(body);oracles.append(blob);widths.append(width)
native=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t eax,edx,ecx,esp;
#define LO8(v) ((uint8_t)(v))
#define LO16(v) ((uint16_t)(v))
#define SET_LO8(v,x) ((v)=((v)&0xFFFFFF00u)|(uint8_t)(x))
#define SET_LO16(v,x) ((v)=((v)&0xFFFF0000u)|(uint16_t)(x))
#define CMP_AE(a,b) ((uint32_t)(a)>=(uint32_t)(b))
BODY
typedef void (*oracle_t)(uint32_t*);
static oracle_t make_oracle(const unsigned char *blob,unsigned size){
 /* Load EAX/EDX/ECX from the Windows-x64 RCX argument; R8 retains its address.
    The 31-byte retail helper uses no stack operands or incompatible opcodes. */
 unsigned char wrapper[]={0x49,0x89,0xC8,0x41,0x8B,0x00,0x41,0x8B,0x50,0x04,0x41,0x8B,0x48,0x08,
                         0xE8,0,0,0,0,0x41,0x89,0x00,0x41,0x89,0x50,0x04,0x41,0x89,0x48,0x08,0xC3};
 unsigned char *code=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
 CHECK(code);memcpy(code,wrapper,sizeof(wrapper));
 uint32_t displacement=sizeof(wrapper)-19;memcpy(code+15,&displacement,4);
 memcpy(code+sizeof(wrapper),blob,size);
 DWORD old;CHECK(VirtualProtect(code,4096,PAGE_EXECUTE_READ,&old));CHECK(FlushInstructionCache(GetCurrentProcess(),code,4096));
 return (oracle_t)code;
}
int main(void){
 const uint32_t values[]={0,1,0xFFFFFFFF,0x80000000,0x7FFFFFFF,0x55555555,0xAAAAAAAA,0x0000FFFF,0xFFFF0000,0x12345678,0x87654321,0x9};
 unsigned cases=0;
 ARRAYS
 for(unsigned fn=0;fn<7;fn++){
  oracle_t oracle=make_oracle(blobs[fn],sizes[fn]);
  for(unsigned count=0;count<256;count++)for(unsigned i=0;i<12;i++)for(unsigned j=0;j<12;j++){
   if(widths[fn]==16 && (count&31)>16)continue; /* x86 undefined: not a conformance case */
   uint32_t state[]={values[i],values[j],0xABCD0000|count};
   oracle(state);eax=values[i];edx=values[j];ecx=0xABCD0000|count;esp=0xF000;
   functions[fn]();
   CHECK(eax==state[0]&&edx==state[1]&&ecx==state[2]&&esp==0xF004);cases++;
  }
  CHECK(VirtualFree((void*)oracle,0,MEM_RELEASE));
 }
 printf("PASS: %u native-instruction cases; retail 64-bit helper and fresh 16/32-bit SHLD/SHRD, zero/masked counts and aliases\n",cases);return 0;
}
'''
arrays="\n".join(f"const unsigned char blob{i}[]={{{','.join(hex(b) for b in blob)}}};" for i,blob in enumerate(oracles))
arrays+="\nconst unsigned char *blobs[]={"+",".join(f"blob{i}" for i in range(7))+"};"
arrays+="\nconst unsigned sizes[]={"+",".join(str(len(blob)) for blob in oracles)+"};"
arrays+="\nconst unsigned widths[]={"+",".join(map(str,widths))+"};"
arrays+="\nvoid (*functions[])(void)={sub_001C7B70,shift_left32,shift_right32,shift_left16,shift_right16,shift_alias32,shift_count_alias32};"
with tempfile.TemporaryDirectory(prefix="dah2-double-shift-") as tmp:
    directory=Path(tmp)
    historical=re.sub(r"    \{ uint32_t _cnt = .*?/\* shld \*/",
                      "    edx = (edx << LO8(ecx)) | (eax >> (32 - LO8(ecx))); /* historical */",
                      actual, count=1, flags=re.S)
    assert historical!=actual
    vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name,body in (("correct",actual),("historical",historical)):
        selected=[body]+bodies[1:]
        (directory/f"{name}.c").write_text(native.replace("BODY","\n".join(selected)).replace("ARRAYS",arrays))
        command=f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 {name}.c /Fe:{name}.exe'
        result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=directory,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stdout+result.stderr
        result=subprocess.run([str(directory/f"{name}.exe")],capture_output=True,text=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==(0 if name=="correct" else 3),result.stdout+result.stderr
        print(result.stdout.strip() if name=="correct" else "PASS: historical zero-count corruption mutant rejected")
print("PASS: retail 31 bytes / 15 instructions, compatible native oracle, exact fresh helper regeneration")
