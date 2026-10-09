"""Verify the full retail 12FFB0 pool allocator and its regenerated C body.

Restored extent is 12FFB0..1301DA exclusive, 554 bytes/164 instructions.
Native tests execute the actual generated function with bounded guest RAM and
independently modeled eight-slot pool effects. No game/UI launch.
"""
from pathlib import Path
import json
import re
import subprocess
import sys
import tempfile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator

START, END = 0x12FFB0, 0x1301DA
xbe = ROOT / "game_files/default.xbe"
config.configure_from_xbe(str(xbe))
image = xbe.read_bytes()
section = next(s for s in config._SECTIONS if s.va <= START < s.va + s.raw_size)
offset = section.raw_addr + START - section.va
retail = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(image[offset:offset + END - START], START))
assert len(retail) == 164 and sum(i.size for i in retail) == 554
assert retail[-1].address == 0x1301D9 and retail[-1].mnemonic == "ret"
assert next(i for i in retail if i.address == 0x130014).op_str == "0x10"
assert next(i for i in retail if i.address == 0x130016).op_str == "0x640"
assert next(i for i in retail if i.address == 0x13001B).op_str == "dword ptr [edx + 4]"
assert [(i.mnemonic, i.op_str) for i in retail[-4:]] == [
    ("pop", "edi"), ("pop", "esi"), ("pop", "ebx"), ("ret", "")]

entries = json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text())
database = {}
for entry in entries:
    address = int(entry["start"], 16)
    entry["end"] = int(entry["end"], 16)
    database[address] = entry
info = dict(database[START], end=END, size=END-START)
database[START] = info
generated = FunctionTranslator(image, database).translate_function(START, info)
regenerated = generated[generated.index("void sub_0012FFB0(void)"):].strip()
source = (ROOT / "src/recomp/gen/recomp_0008.c").read_text(encoding="utf-8")
body = re.search(r"^void sub_0012FFB0\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert body == regenerated, "Full retail extent does not regenerate to the actual repaired body"
assert "sub_00130001();" not in body and "loc_001301BD:" in body
# The split was falsely seeded by an absolute word in an XMV table, and had
# no retail direct callers. Keep its old isolated symbol untouched; only its
# invalid fallthrough from the real allocator is removed.
surrogate = database[0x130001]
assert not surrogate["called_by"] and surrogate["detection_method"] == "seed_vtable_thunk"
references = []
for s in config._SECTIONS:
    blob = image[s.raw_addr:s.raw_addr+s.raw_size]
    pos = 0
    while True:
        pos = blob.find((0x130001).to_bytes(4, "little"), pos)
        if pos < 0:
            break
        references.append(s.va+pos)
        pos += 1
assert references == [0x249AD0], references

prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v);exit(3);}}while(0)
static uint32_t eax,ecx,edx,esp,ebx,esi,edi,ebp,g_ebp,g_seh_ebp;
static unsigned char memory[0x400000],expected[0x400000];
static uint32_t allocation_result, expected_pool;
static unsigned calls[4],cases;
#define g_esp esp
static void *pointer(unsigned char *base,uint32_t a,unsigned n) {
    CHECK(a <= sizeof(memory)-n);return base+a;
}
#define MEM8(a) (*(uint8_t *)pointer(memory,(uint32_t)(a),1))
#define MEM16(a) (*(uint16_t *)pointer(memory,(uint32_t)(a),2))
#define MEM32(a) (*(uint32_t *)pointer(memory,(uint32_t)(a),4))
#define E8(a) (*(uint8_t *)pointer(expected,(uint32_t)(a),1))
#define E16(a) (*(uint16_t *)pointer(expected,(uint32_t)(a),2))
#define E32(a) (*(uint32_t *)pointer(expected,(uint32_t)(a),4))
#define LO8(v) ((uint8_t)(v))
#define LO16(v) ((uint16_t)(v))
#define CMP_EQ(a,b) ((uint32_t)(a)==(uint32_t)(b))
#define CMP_NE(a,b) ((uint32_t)(a)!=(uint32_t)(b))
#define CMP_L(a,b) ((int32_t)(a)<(int32_t)(b))
#define PUSH32(s,v) do {uint32_t t=(v);(s)-=4;MEM32(s)=t;}while(0)
#define POP32(s,v) do {(v)=MEM32(s);(s)+=4;}while(0)
static void sub_001552D0(void) {
    CHECK(MEM32(esp)==0x12FFF3);CHECK(esi==expected_pool);
    ++calls[0];eax=0x1000;ecx=0xDEADBEEF;edx=0xABABABAB;esp+=4;
}
static void sub_00139860(void) {
    CHECK(MEM32(esp)==0x130006 && ecx==0x2000);
    ++calls[1];eax=0x30FE80;ecx=0xCCCCCCCC;edx=0xDDDDDDDD;esp+=4;
}
static void sub_001398A0(void) {
    CHECK(MEM32(esp)==0x130025 && edi==allocation_result);
    ++calls[3];eax=0x30FE80;ecx=0xCCCCCCCC;edx=0xDDDDDDDD;esp+=4;
}
static void indirect(uint32_t target,uint32_t saved) {
    CHECK(target==0x123456 && ecx==0x2000);
    CHECK(MEM32(esp)==0x13001E && MEM32(esp+4)==0x640 && MEM32(esp+8)==0x10);
    CHECK(saved==esp+12 && esi==expected_pool);
    ++calls[2];eax=allocation_result;ecx=0xCCCCCCCC;edx=0xDDDDDDDD;esp+=12;
}
#define RECOMP_ICALL_SAFE(t,s) indirect((t),(s))
'''
suffix = r'''
static void check_call(uint32_t pool,int path) {
    const uint32_t sp=0x3FF000,old_ebx=0x11223344,old_esi=0x55667788,old_edi=0xAABBCCDD;
    uint32_t wanted,free_head,total,free_count,active;
    eax=0xABCDEF01;ecx=pool;edx=0x76543210;esp=sp;
    ebx=old_ebx;esi=old_esi;edi=old_edi;ebp=0xC0C0C0C0;g_ebp=ebp;g_seh_ebp=0x12121212;
    expected_pool=pool;memset(calls,0,sizeof(calls));MEM32(sp)=0x87654321;
    free_head=MEM32(pool+8);total=MEM32(pool+12);free_count=MEM32(pool+16);active=MEM32(pool+4);
    memcpy(expected,memory,sizeof(memory));E32(sp-4)=old_ebx;E32(sp-8)=old_esi;
    if(path==0) {
        wanted=free_head;
        E32(pool+8)=E32(free_head+0xC0);E32(free_head+0xC0)=active;
        E32(pool+4)=free_head;E32(pool+16)=free_count-1;
    } else if(path==1) wanted=0;
    else {
        E32(sp-12)=old_edi;E32(sp-16)=0x130025;
        E32(sp-20)=0x640;E32(sp-24)=0x13001E;
        wanted=allocation_result ? allocation_result+7*0xC8 : 0;
        if(allocation_result) {
            for(unsigned i=0;i<8;++i) {
                uint32_t slot=allocation_result+i*0xC8;
                E32(slot)=0x2B117C;E32(slot+4)=slot+4;E32(slot+8)=slot+4;
                E32(slot+12)=0;E16(slot+16)=0xFFFF;E8(slot+0xC4)=(uint8_t)i;
                E32(slot+0xC0)=i==7 ? active : i ? slot-0xC8 : 0;
            }
            E32(pool+4)=wanted;E32(pool+8)=allocation_result+6*0xC8;
            E32(pool+12)=total+8;E32(pool+16)=free_count+7;
        }
    }
    sub_0012FFB0();
    CHECK(eax==wanted && eax!=0x30FE80 && esp==sp+4);
    CHECK(ebx==old_ebx && esi==old_esi && edi==old_edi && ebp==0xC0C0C0C0);
    CHECK(g_ebp==0xC0C0C0C0 && g_seh_ebp==0x12121212);
    for(unsigned i=0;i<4;++i) CHECK(calls[i]==(path==2));
    if(memcmp(memory,expected,sizeof(memory))) {
        for(unsigned i=0;i<sizeof(memory);++i) if(memory[i]!=expected[i]) {
            fprintf(stderr,"RAM mismatch at %X got=%02X expected=%02X\n",i,memory[i],expected[i]);break;
        }
        exit(3);
    }
    ++cases;
}
static void setup(uint32_t total,uint32_t cap,uint32_t active) {
    memset(memory,0xCD,sizeof(memory));
    MEM32(0x1000+0x7E18)=0xA000;MEM32(0xA000+0x3A8)=0x2000;
    MEM32(0x2000)=0x3000;MEM32(0x3004)=0x123456;
    MEM32(0x6000+4)=active;MEM32(0x6000+8)=0;
    MEM32(0x6000+12)=total;MEM32(0x6000+16)=0;MEM32(0x6000+20)=cap;
}
int main(void) {
    uint32_t totals[]={0,8,16,0x7FFFFFFF,0xFFFFFFFF};
    uint32_t caps[]={0,8,16,0x7FFFFFFF,0xFFFFFFFF};
    for(unsigned t=0;t<5;++t) for(unsigned c=0;c<5;++c) for(unsigned a=0;a<2;++a)
    for(unsigned success=0;success<2;++success) {
        setup(totals[t],caps[c],a?0x5000:0);
        allocation_result=success?0x10000:0;
        check_call(0x6000,caps[c] && (int32_t)totals[t]>=(int32_t)caps[c] ? 1 : 2);
    }
    for(unsigned c=0;c<5;++c) for(unsigned a=0;a<2;++a) {
        setup(8,caps[c],a?0x5000:0);
        allocation_result=0x10000;MEM32(0x6008)=0x14000;MEM32(0x6010)=9;
        MEM32(0x140C0)=0x15000;check_call(0x6000,0);
    }
    setup(0,0,0);allocation_result=0x10000;check_call(0x6000,2);
    for(unsigned i=0;i<7;++i) check_call(0x6000,0);
    CHECK(MEM32(0x6008)==0);allocation_result=0x20000;check_call(0x6000,2);
    CHECK(MEM32(0x600C)==16);
    printf("PASS: %u native allocator cases; eight-slot construction/reuse, signed exhaustion, failure, exact RAM and RET0/callee-save ABI\n",cases);
    return 0;
}
'''
historical = body[:body.index("    PUSH32(esp, 0x00130006u);")] + """
    eax = 0x30FE80; /* historical truncated130001 left139860's singleton */
    return;
}
"""
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
with tempfile.TemporaryDirectory(prefix="dah2-pool-allocator-") as directory:
    out = Path(directory)
    for name, implementation, should_fail in (
            ("recovered", body, False), ("historical_truncation", historical, True),
            ("missing_pop", body.replace("    POP32(esp, edi);\n    POP32(esp, esi);\n    POP32(esp, ebx);",
                                        "    POP32(esp, esi);\n    POP32(esp, ebx);"), True)):
        (out / f"{name}.c").write_text(prefix+implementation+suffix, encoding="utf-8")
        command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
        subprocess.run('cmd.exe /d /s /c "'+command+'"', cwd=out, check=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)
        result = subprocess.run([str(out/f"{name}.exe")], capture_output=True, text=True,
                                timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        if should_fail:
            assert result.returncode == 3, result
            print("PASS: "+name+" mutant rejected")
        else:
            if result.returncode:
                print(result.stdout+result.stderr)
            result.check_returncode()
            print(result.stdout, end="")
print("PASS: verified554-byte/164-instruction retail extent; actual C equals fresh translation; false split has no direct caller")
