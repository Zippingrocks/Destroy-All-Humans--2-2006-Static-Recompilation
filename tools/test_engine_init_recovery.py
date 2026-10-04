"""Exercise recovered initializer bodies; called registration/base helpers are doubles."""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / 'diagnostics/engine_init_test'
out.mkdir(exist_ok=True)
bodies = []
for chunk, address in [('0003','00093CC0'), ('0011','001A2D20'), ('0012','001C46C0'), ('0012','001E8370')]:
    source = (root / f'src/recomp/gen/recomp_{chunk}.c').read_text()
    bodies.append(re.search(rf'^void sub_{address}\(void\)\n\{{.*?^\}}', source, re.M | re.S).group())
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x30000];
static unsigned registrations;
static unsigned registration_set;
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_001CF740(void) {
    uint32_t callbacks=MEM32(esp+4);
    assert(ecx==0x1000);
    if (!registration_set) {
        assert(MEM32(esp+8)==(registrations?20:7));
        assert(MEM32(esp+12)==(registrations?7:20));
        assert(MEM32(callbacks)==(registrations?0x1A2CF0:0x1A2350));
        assert(MEM32(callbacks+12)==(registrations?0x1A20E0:0x1A2030));
    } else {
        assert(MEM32(esp+8)==(registrations?9:0xFFFFFFFFu));
        assert(MEM32(esp+12)==(registrations?0xFFFFFFFFu:9));
        assert(MEM32(callbacks)==(registrations?0x1E8140:0x1E8300));
        assert(MEM32(callbacks+12)==(registrations?0x1E7700:0x1E7C80));
    }
    registrations++; esp+=16;
}
void sub_001C2FA0(void) {
    assert(ecx==0x1000 && MEM32(esp+4)==11 && MEM32(esp+8)==22 && MEM32(esp+12)==33);
    esp+=16;
}
'''
suffix = r'''
static void prepare(void) {
    memset(memory,0xCC,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
    esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
}
static void saved(void) { assert(esi==0xABC && edi==0xDEF && ebx==0x123); }
int main(void) {
    prepare(); sub_00093CC0(); saved(); assert(esp==0x20004 && eax==0x1000);
    assert(MEM32(0x1000)==0x118 && MEM32(0x10D8)==0x80);
    assert(MEM32(0x10DC)==0x3A921669 && MEM32(0x10E0)==0x88B2EE0A && MEM32(0x1114)==0xA141094D);
    for(unsigned i=2;i<14;i++) assert(MEM32(0x10DC+i*4)==0);
    prepare(); MEM32(esp+4)=0x1000; sub_001A2D20(); saved();
    assert(esp==0x20004 && registrations==2);
    prepare(); registration_set=1; registrations=0;
    MEM32(esp+4)=0x1000; sub_001E8370(); saved();
    assert(esp==0x20004 && registrations==2);
    prepare(); MEM32(esp+4)=11; MEM32(esp+8)=22; MEM32(esp+12)=33;
    sub_001C46C0(); saved(); assert(esp==0x20010 && eax==0x1000 && MEM32(0x1000)==0x2B9820);
    puts("PASS: initialization defaults, both callback registrations, constructor arguments/vtable and guest ABI");
}
'''
(out / 'test.c').write_text(prefix + '\n'.join(bodies) + suffix)
vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
subprocess.run([str(out / 'test.exe')], cwd=out, check=True)
