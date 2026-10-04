"""Execute the recovered 204CD0 allocator tail and reject its split mutant."""
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/recomp/gen/recomp_0013.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_00204CD0\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert "loc_00204D39:" in body and body.count("ret 4") == 3
assert "if (CMP_BE(_fa, _fb)) goto loc_00204D2D;" in body

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_ebp,g_seh_ebp;
static unsigned char memory[0x400000];
static void *ptr(uint32_t a,unsigned n){if(a>sizeof(memory)-n)exit(5);return memory+a;}
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define MEM32(a) (*(uint32_t*)ptr((uint32_t)(a),4))
#define PUSH32(s,v) do{uint32_t t=(v);(s)-=4;MEM32(s)=t;}while(0)
#define POP32(s,v) do{(v)=MEM32(s);(s)+=4;}while(0)
#define CMP_EQ(a,b) ((uint32_t)(a)==(uint32_t)(b))
#define CMP_BE(a,b) ((uint32_t)(a)<=(uint32_t)(b))
static void sub_00204D70(void){eax=0x100000;esp+=8;}
'''
suffix = r'''
int main(void){
  const uint32_t top=0x3ff000;
  eax=ecx=edx=0;ebx=0xb0b0b0b0;esi=0x51515151;edi=0xd1d1d1d1;
  esp=top-8;MEM32(esp)=0x12345678;MEM32(esp+4)=0x398;
  MEM32(0x3244b8)=0;MEM32(0x3244bc)=0;
  sub_00204CD0();
  if(esp!=top || eax!=0x100000 || ebx!=0xb0b0b0b0 || esi!=0x51515151 || edi!=0xd1d1d1d1){
    fprintf(stderr,"bad esp=%08x eax=%08x ebx=%08x esi=%08x edi=%08x\n",esp,eax,ebx,esi,edi);return 3;
  }
  puts("PASS: 204CD0 restores exact RET4 stack and callee-saved registers");
  return 0;
}
'''

historical = (body[:body.index("    if (CMP_BE(_fa, _fb))")] +
              "\nloc_00204D39: ;\n    return;\n}\n")
out_root = ROOT / "diagnostics/allocator_tail_test"
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
        result.check_returncode()
        print(result.stdout, end="")
    else:
        assert result.returncode == 3, result
        print("PASS: historical 0x14-byte split-tail stack leak rejected")
print(f"PASS: artifacts: {out}")
