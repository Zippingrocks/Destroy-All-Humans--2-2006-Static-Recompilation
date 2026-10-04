"""Test actual recovered menu callback, with strict doubles for its callees."""
import re
import subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
source = (root / 'src/recomp/gen/recomp_0007.c').read_text()
body = re.search(r'^void sub_001276E0\(void\)\n\{.*?^\}', source, re.M | re.S).group()
factory_source = (root / 'src/recomp/gen/recomp_0006.c').read_text()
body += '\n' + re.search(r'^void sub_00101C00\(void\)\n\{.*?^\}', factory_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_00106870\(void\)\n\{.*?^\}', factory_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_0010C0A0\(void\)\n\{.*?^\}', source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_0010E310\(void\)\n\{.*?^\}', source, re.M | re.S).group()
listener_source = (root / 'src/recomp/gen/recomp_0004.c').read_text()
body += '\n' + re.search(r'^void sub_000A9CC0\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
listener_source = (root / 'src/recomp/gen/recomp_0003.c').read_text()
body += '\n' + re.search(r'^void sub_0008F860\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_00089F10\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_00087300\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_00087CF0\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_00089BF0\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_000892B0\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
body += '\n' + re.search(r'^void sub_00087800\(void\)\n\{.*?^\}', listener_source, re.M | re.S).group()
array_source = (root / 'src/recomp/gen/recomp_0008.c').read_text()
body += '\n' + re.search(r'^void sub_0014A320\(void\)\n\{.*?^\}', array_source, re.M | re.S).group()
out = root / 'diagnostics/menu_callback_test'
out.mkdir(exist_ok=True)
prefix = r'''
#include <stdio.h>
#include <assert.h>
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_esi,g_edi,g_ebp,g_seh_ebp;
RECOMP_TLS double g_fp_stack[8];
RECOMP_TLS int g_fp_top;
RECOMP_TLS RecompXmm g_xmm0,g_xmm1,g_xmm2,g_xmm3;
RECOMP_TLS int g_fp_cmp;
volatile uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_trace_idx;
volatile uint64_t g_icall_count;
void recomp_icall_fail_log(uint32_t va) { (void)va; assert(0); }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; assert(0); return 0; }
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; assert(0); return 0; }
recomp_func_t recomp_lookup_kernel(uint32_t va) { (void)va; assert(0); return 0; }
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x400000];
static unsigned value, calls;
void sub_00087300(void);
void sub_000892B0(void);
uint32_t recomp_ensure_thread_stack(void) { assert(0); return 0; }
void sub_001AF480(void) {
    assert(ecx==0x1000 && MEM32(esp+4)==0xFFFFFFFF);
    eax=0x7339F559; esp+=8; calls++;
}
void sub_001AF130(void) {
    assert(ecx==0x1000 && MEM32(esp+4)==1);
    eax=1; esp+=8; calls++;
}
void sub_001AF360(void) {
    assert(ecx==0x1000 && MEM32(esp+4)==1);
    eax=value; esp+=8; calls++;
}
void sub_00106780(void) {
    assert(ecx==0x1000 && MEM32(esp+4)==1); esp+=8; calls++;
}
void sub_0013C3F0(void) {
    g_fp_top=(g_fp_top+7)&7; g_fp_stack[g_fp_top]=fabs(MEMF(esp+4)); esp+=8;
}
void sub_00107290(void) {
    assert(ecx==0x1000 && MEM32(esp+4)==1 && MEM32(esp+8)==1);
    esp+=12; calls++;
}
void sub_001AF3F0(void) {
    assert(ecx==0x2000 && MEM32(esp+4)==7);
    g_fp_top=(g_fp_top+7)&7; g_fp_stack[g_fp_top]=2.5; esp+=8; calls++;
}
void sub_0008F7B0(void) {
    assert(ecx==0x1000 && MEM32(esp+4)==0x12345678); esp+=8; calls++;
}
'''
known = {'sub_001276E0', 'sub_00101C00', 'sub_00106870', 'sub_0010C0A0', 'sub_0013C3F0', 'sub_00107290', 'sub_00106780', 'sub_001AF480', 'sub_001AF130', 'sub_001AF360'}
known.update({'sub_0010E310','sub_001AF3F0'})
known.add('sub_000A9CC0')
known.update({'sub_0008F860','sub_0008F7B0'})
known.add('sub_0014A320')
known.add('sub_00089F10')
known.add('sub_00087300')
known.add('sub_00087CF0')
known.update({'sub_00089BF0','sub_000892B0'})
known.add('sub_00087800')
stubs = '\n'.join(f'void {name}(void) {{ assert(!"unexpected {name}"); }}'
                  for name in sorted(set(re.findall(r'sub_[0-9A-F]+(?=\()', body))-known))
suffix = r'''
int main(void) {
    g_xbox_mem_offset=(ptrdiff_t)memory;
    for(unsigned v=0;v<3;v++) for(unsigned old=0;old<2;old++) {
        memset(memory,0,sizeof(memory));
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
        value=v; calls=0; MEM32(0x30FDE4)=0x4000; MEM8(0x7059)=old;
        sub_001276E0();
        assert(esp==0x20004 && esi==0xABC && edi==0xDEF && ebx==0x123);
        assert(eax==0 && calls==3 && MEM8(0x7059)==(v==0));
    }
    const unsigned misses[]={0,0xFFFFFFFF,0x80000001,0x40000001};
    for(unsigned i=0;i<4;i++) {
        esp=0x20000; ecx=misses[i]; edx=0x8765; esi=0xABC; edi=0xDEF; ebx=0x123;
        sub_00101C00();
        assert(esp==0x2000C && esi==0xABC && edi==0xDEF && ebx==0x123 && eax==0);
    }
    for(unsigned i=0;i<5;i++) {
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123; calls=0;
        MEM32(esp+4)=i<4 ? misses[i] : 0x01E5156C; MEM32(esp+8)=2;
        sub_00106870();
        assert(esp==0x2000C && esi==0xABC && edi==0xDEF && ebx==0x123);
        assert(eax==(i<4 ? 0xFFFFFFFF : 0) && calls==(i==4));
    }
    for(unsigned flags=0;flags<=0x60;flags+=0x20) {
    memset(memory,0,sizeof(memory));
    esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123; calls=0; g_fp_top=0;
    MEMF(0x29B7A8)=1.0f; MEMF(0x29BBD4)=0.00001f;
    MEM32(0x103C)=flags;
    MEMF(esp+4)=10; MEMF(esp+8)=20; MEMF(esp+12)=640; MEMF(esp+16)=480;
    sub_0010C0A0();
    assert(esp==0x20014 && esi==0xABC && edi==0xDEF && ebx==0x123 && calls==(flags!=0) && g_fp_top==0);
    assert(MEMF(0x10B4)==10 && MEMF(0x10B8)==20 && MEMF(0x10BC)==649 && MEMF(0x10C0)==499);
    assert(MEMF(0x1040)==((flags&0x20)?640:0) && MEMF(0x1044)==((flags&0x40)?480:0));
    }
    const unsigned method_ids[]={0x0C5A9A59,0x09C653C7};
    const unsigned fields[]={0x138,0x140};
    for(unsigned i=0;i<2;i++) {
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123; calls=0; g_fp_top=0;
        MEM32(0x30FD08)=0x2000; MEM32(esp+4)=method_ids[i]; MEM32(esp+8)=7;
        sub_0010E310();
        assert(esp==0x2000C && esi==0xABC && edi==0xDEF && ebx==0x123 && calls==1 && g_fp_top==0);
        assert(MEMF(0x1000+fields[i])==2.5f);
    }
    for(unsigned i=0;i<3;i++) {
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
        MEM32(esp+4)=0x2000; MEM32(0x2004)=i;
        sub_000A9CC0();
        assert(esp==0x20008 && esi==0xABC && edi==0xDEF && ebx==0x123);
    }
    for(unsigned i=0;i<2;i++) {
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123; calls=0;
        MEM32(esp+4)=0x2000; MEM32(0x2004)=i?0xD2EB1B81:0; MEM32(0x2008)=0x12345678;
        sub_0008F860();
        assert(esp==0x20008 && esi==0xABC && edi==0xDEF && ebx==0x123 && calls==i);
    }
    for(unsigned n=0;n<=10;n++) for(unsigned first=0;first<=n;first++) for(unsigned last=first;last<=n;last++) {
        memset(memory,0,sizeof(memory));
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
        MEM32(0x1000)=n;
        for(unsigned i=0;i<n;i++) for(unsigned b=0;b<32;b++) MEM8(0x1004+i*32+b)=(unsigned char)(i*17+b);
        MEM32(esp+4)=0x1004+first*32; MEM32(esp+8)=0x1004+last*32;
        sub_0014A320();
        assert(esp==0x2000C && esi==0xABC && edi==0xDEF && ebx==0x123 && MEM32(0x1000)==n-(last-first));
        for(unsigned i=0;i<n-(last-first);i++) for(unsigned b=0;b<29;b++) {
            unsigned original=i<first?i:i+last-first;
            assert(MEM8(0x1004+i*32+b)==(unsigned char)(original*17+b));
        }
    }
    for(unsigned n=0;n<=10;n++) for(unsigned first=0;first<=n;first++) {
        memset(memory,0,sizeof(memory));
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
        MEM32(0x1000)=n;
        for(unsigned i=0;i<n;i++) for(unsigned b=0;b<32;b++) MEM8(0x1004+i*32+b)=(unsigned char)(i*17+b);
        MEM32(esp+4)=0x1004+(first+1)*32; MEM32(esp+8)=0x1004+first*32;
        sub_00087CF0();
        assert(esp==0x2000C && esi==0xABC && edi==0xDEF && ebx==0x123 && MEM32(0x1000)==n+1);
        for(unsigned i=0;i<n+1;i++) if(i!=first) for(unsigned b=0;b<32;b++) {
            unsigned original=i<first?i:i-1;
            assert(MEM8(0x1004+i*32+b)==(unsigned char)(original*17+b));
        }
    }
    for(unsigned n=0;n<=10;n++) for(unsigned key=0;key<=22;key++) {
        memset(memory,0,sizeof(memory));
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
        MEM32(0x1000)=n;
        for(unsigned i=0;i<n;i++) MEM32(0x1004+i*32+28)=2*i+2;
        MEM32(0x301C)=key; MEM32(esp+4)=0x2000; MEM32(esp+8)=0x3000;
        sub_00087300();
        unsigned index=(key>=2 && key%2==0 && key/2<=n)?key/2-1:n;
        assert(esp==0x2000C && esi==0xABC && edi==0xDEF && ebx==0x123);
        assert(MEM32(0x2000)==0x1004+32*index);
    }
    memset(memory,0,sizeof(memory));
    esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123;
    MEM32(0x2CA6A0)=0x3000;
    sub_00089F10();
    assert(esp==0x20004 && esi==0xABC && edi==0xDEF && ebx==0x123);
    for(unsigned mode=0;mode<2;mode++) {
        memset(memory,0,sizeof(memory));
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123; calls=0; g_fp_top=0;
        MEM8(0x1050)=mode; MEMF(esp+4)=0.033f; MEMF(0x2A3DB4)=1.0f;
        for(unsigned i=0;i<3;i++) MEM32(0x1094+0x58*i)=0x1094+0x58*i;
        sub_00089BF0();
        assert(esp==0x20008 && esi==0xABC && edi==0xDEF && ebx==0x123 && calls==0 && g_fp_top==0);
    }
    for(unsigned n=0;n<2;n++) for(unsigned cycle=0;cycle<8;cycle++) {
        memset(memory,0,sizeof(memory));
        esp=0x20000; ecx=0x1000; esi=0xABC; edi=0xDEF; ebx=0x123; g_fp_top=0;
        MEM32(0x1004)=n; MEM32(0x104C)=cycle;
        MEMF(0x2A63D8)=2; MEMF(0x2A63E0)=1;
        sub_00087800();
        assert(esp==0x20004 && esi==0xABC && edi==0xDEF && ebx==0x123 && g_fp_top==0);
        assert(MEM32(0x104C)==(n?(cycle+1)%8:cycle));
        if(n) assert(MEM32(0x108C)==0x3F100000 && MEM32(0x10E4)==0x3F100000 && MEM32(0x113C)==0x3F100000);
    }
    puts("PASS: menu callbacks, record lookup/insertion/erasure, empty updates and cycle rollover; fields, FP balance and guest ABI");
}
'''
(out / 'test.c').write_text(prefix+stubs+body+suffix)
vcvars=Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
cmd=f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{root / "src/recomp"}" test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "'+cmd+'"',cwd=out,check=True)
subprocess.run([str(out/'test.exe')],cwd=out,check=True)
