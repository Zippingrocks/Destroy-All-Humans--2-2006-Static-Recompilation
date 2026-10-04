"""Execute 280570's recovered split tail and reject the former stubs."""
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/recomp/gen/recomp_0014.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_00280570\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert "loc_00280593:" in body and "loc_0028059A:" in body
assert "sub_00280593(); return" not in body and "sub_0028059A(); return" not in body
assert body.count("ret 8") == 2

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi;
static unsigned char memory[0x400000];
static void *ptr(uint32_t a,unsigned n){if(a>sizeof(memory)-n)exit(5);return memory+a;}
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define MEM32(a) (*(uint32_t*)ptr((uint32_t)(a),4))
#define PUSH32(s,v) do{uint32_t t=(v);(s)-=4;MEM32(s)=t;}while(0)
#define CMP_EQ(a,b) ((uint32_t)(a)==(uint32_t)(b))
#define TEST_Z(a,b) (((uint32_t)(a)&(uint32_t)(b))==0)
#define TEST_NZ(a,b) (((uint32_t)(a)&(uint32_t)(b))!=0)
#define SET_LO8(r,v) ((r)=((r)&0xffffff00u)|((uint8_t)(v)))
#define RECOMP_ICALL_SAFE(t,s) do{if((t)!=0x00283e00u)exit(6);(void)(s);eax=0x00283b70u;esp+=8;}while(0)
'''
suffix = r'''
int main(void){
  const uint32_t top=0x3ff000;
  MEM32(0x32bf40)=0;MEM32(0x32bf44)=0;MEM32(0x32bf48)=0;
  esp=top-12;MEM32(esp)=0x12345678;MEM32(esp+4)=0x00283e00;MEM32(esp+8)=0;
  sub_00280570();
  if(esp!=top || eax!=1 || MEM32(0x32bf40)!=0x00283e00 || MEM32(0x32bf44)!=0x00283b70){
    fprintf(stderr,"bad esp=%08x eax=%08x fn=%08x callback=%08x\n",esp,eax,MEM32(0x32bf40),MEM32(0x32bf44));return 3;
  }
  puts("PASS: 280570 registers callback and restores exact RET8 stack");
  return 0;
}
'''

historical = body[:body.index("loc_00280593:")] + r'''loc_00280593: ;
    esp += 4; return;
loc_0028059A: ;
    esp += 4; return;
}
'''
out_root = ROOT / "diagnostics/bink_callback_registration_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, candidate in (("recovered", body), ("historical", historical)):
    (out / f"{name}.c").write_text(prefix + candidate + suffix, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /W3 /TC {name}.c /Fe:{name}.exe'
    built = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out,
                           capture_output=True, text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
    if built.returncode:
        print(built.stdout + built.stderr)
    built.check_returncode()
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True,
                            text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if name == "recovered":
        if result.returncode:
            print(result.stderr)
        result.check_returncode(); print(result.stdout, end="")
    else:
        assert result.returncode == 3, result
        print("PASS: historical split-tail callback/stack failure rejected")
print(f"PASS: artifacts: {out}")
