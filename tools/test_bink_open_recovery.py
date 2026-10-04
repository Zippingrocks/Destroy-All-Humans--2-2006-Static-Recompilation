"""Compile the actual full BinkOpen body and test bounded rejection paths.

No game, emulator, media decoder, or UI is started. File callbacks are strict
test doubles. Success here means a file-open callback succeeded; every supplied
header is deliberately invalid or contains zero frames, so BinkOpen must fail.
The historical false-success mutant must return1 without reading or closing.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image = (ROOT / "game_files/default.xbe").read_bytes()


def retail_bytes(address, size):
    section = next(s for s in config._SECTIONS if s.va <= address < s.va + s.raw_size)
    offset = section.raw_addr + address - section.va
    return image[offset:offset + size]


instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(retail_bytes(0x280C10, 0xF00), 0x280C10))
assert len(instructions) == 979
assert all(i.mnemonic == "int3" for i in instructions[-15:])
assert [(i.address, i.mnemonic, i.op_str) for i in instructions[-22:-15]] == [
    (0x281AF2, "pop", "ebx"), (0x281AF3, "pop", "edi"),
    (0x281AF4, "pop", "esi"), (0x281AF5, "mov", "eax, ebp"),
    (0x281AF7, "pop", "ebp"), (0x281AF8, "add", "esp, 0x3d8"),
    (0x281AFE, "ret", "8"),
]
assert instructions[-16].address + instructions[-16].size == 0x281B01
branch_targets = {int(i.op_str, 16) for i in instructions[:-15]
                  if i.mnemonic.startswith("j") and i.op_str.startswith("0x")}
assert all(0x280C10 <= target < 0x281B01 for target in branch_targets)
by_address = {i.address: i for i in instructions}
assert by_address[0x280CB4].mnemonic == "jne" and by_address[0x280CB4].op_str == "0x280cd7"
assert by_address[0x280CD7].op_str == "0x2c"
assert by_address[0x280CB0].op_str == "esi"
assert by_address[0x280CE8].op_str == "dword ptr [esp + 0x16c]"

source = (ROOT / "src/recomp/gen/recomp_0014.c").read_text(encoding="utf-8")
match = re.search(r"^void sub_00280C10\(void\)\n\{.*?^\}", source, re.M | re.S)
assert match, "Actual full function is missing"
body = match.group()
labels = {int(label, 16) for label in re.findall(r"^loc_([0-9A-F]{8}):", body, re.M)}
gotos = {int(label, 16) for label in re.findall(r"goto loc_([0-9A-F]{8})", body)}
assert gotos <= labels, f"Unresolved body labels: {gotos - labels}"
assert branch_targets <= labels, f"Missing retail branch targets: {branch_targets - labels}"
assert all(0x280C10 <= label < 0x281B01 for label in labels)
assert "TODO" not in body
assert "sub_00280C82()" not in body, "Recovered entry still escapes into the old split fragment"
assert "loc_00281AF2:" in body

helpers = set(re.findall(r"\b(sub_[0-9A-F]{8})\(\)", body))
allowed_helpers = {"sub_00280540", "sub_002846D0"}
helper_stubs = "\n".join(f'static void {name}(void) {{ unexpected("{name}"); }}'
                         for name in sorted(helpers - allowed_helpers))

prefix = r'''
#define RECOMP_GENERATED_CODE
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "recomp/recomp_types.h"
ptrdiff_t g_xbox_mem_offset;
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_ebp,g_seh_ebp;
RECOMP_TLS double g_fp_stack[8];
RECOMP_TLS int g_fp_top,g_fp_cmp;
static unsigned char memory[0x400000];
static uint32_t initial_sp,base_sp,io_address,flags,custom_open,magic;
static unsigned open_success,callback_error,opens,reads,closes,clocks,errors,case_number;
static const uint32_t read_callback=0x770010,close_callback=0x770020;
static const uint32_t path_address=0x10000,clock_value=0x13572468;
static unsigned historical;
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL case %u line %d: %s\n",case_number,__LINE__,#x); exit(3); } } while(0)
static void unexpected(const char *name) { fprintf(stderr,"Unreachable helper %s, case %u\n",name,case_number); exit(4); }
uint32_t recomp_ensure_thread_stack(void) { unexpected("stack repair"); return 0; }
static void sub_002846D0(void) {
    CHECK(esp==base_sp-4 && MEM32(esp)==0x280C53);
    ++clocks; eax=clock_value; esp+=4;
}
static void sub_00280540(void) {
    uint32_t return_address=MEM32(esp), source_address=MEM32(esp+4);
    ++errors;
    if(!open_success) CHECK(return_address==0x280CC9 && source_address==0x2BBE4C);
    else CHECK(return_address==0x280D4C && source_address==0x2BBE04);
    /* Retail error helper copies the NUL-terminated text and RET4. */
    strcpy((char*)XBOX_PTR(0x3242B8),(const char*)XBOX_PTR(source_address));
    eax=source_address+(uint32_t)strlen((char*)XBOX_PTR(source_address));
    ecx=0x3242B8+(uint32_t)strlen((char*)XBOX_PTR(source_address));
    SET_LO8(edx,0); esp+=8;
}
static void indirect(uint32_t target,uint32_t saved_sp) {
    uint32_t ret=MEM32(esp);
    if(target==0x289310 || target==0x770000) {
        CHECK(++opens==1 && saved_sp==base_sp && esp==base_sp-16 && ret==0x280CB2);
        CHECK(target==(((flags&0x2000000)&&custom_open)?custom_open:0x289310));
        CHECK(MEM32(esp+4)==base_sp+0x15C && MEM32(esp+8)==path_address && MEM32(esp+12)==flags);
        CHECK(MEM32(0x32BF84)==0 && MEM32(base_sp+0x304)==clock_value);
        CHECK(MEM8(0x3242B8)==0);
        io_address=MEM32(esp+4);
        if(open_success) {
            MEM32(io_address)=read_callback; MEM32(io_address+0x14)=close_callback;
            CHECK(MEM32(io_address+0x1C)==0);
        } else if(callback_error) strcpy((char*)XBOX_PTR(0x3242B8),"fixture open error");
        eax=open_success; esp+=16; return;
    }
    if(target==read_callback) {
        uint32_t destination=MEM32(esp+12);
        CHECK(++reads==1 && opens==1 && open_success && saved_sp==base_sp);
        CHECK(esp==base_sp-20 && ret==0x280CEF);
        CHECK(MEM32(esp+4)==io_address && MEM32(esp+8)==0);
        CHECK(destination==base_sp+0x20 && MEM32(esp+16)==44);
        memset((void*)XBOX_PTR(destination),0,44);
        MEM32(destination)=magic; MEM32(destination+4)=0x1234;
        /* Bad magic has nonzero frames, valid BIK[fghi] headers have zero. */
        MEM32(destination+8)=(magic==0xDEADBEEFu)?1:0;
        MEM32(destination+20)=640; MEM32(destination+24)=448;
        MEM32(destination+28)=2997; MEM32(destination+32)=100;
        eax=44; esp+=20; return;
    }
    if(target==close_callback) {
        CHECK(++closes==1 && opens==1 && reads==1);
        CHECK(saved_sp==base_sp-4 && esp==base_sp-12 && ret==0x28151B);
        CHECK(MEM32(esp+4)==io_address);
        eax=0xBADC0DE; esp+=8; return;
    }
    unexpected("indirect callback");
}
#undef RECOMP_ICALL_SAFE
#define RECOMP_ICALL_SAFE(t,s) indirect((t),(s))
'''

suffix = r'''
int main(void) {
    uint32_t flag_values[]={0,0x4000,0x2000000,0x2004000};
    uint32_t magic_values[]={0x664B4942,0x674B4942,0x684B4942,0x694B4942,0xDEADBEEF};
    historical=HISTORICAL;
    for(unsigned fi=0;fi<4;++fi)
    for(unsigned ci=0;ci<2;++ci)
    for(unsigned success=0;success<2;++success)
    for(unsigned err=0;err<2;++err)
    for(unsigned mi=0;mi<5;++mi)
    for(unsigned alignment=0;alignment<4;++alignment) {
        ++case_number;
        memset(memory,0xCD,sizeof(memory)); g_xbox_mem_offset=(ptrdiff_t)memory;
        flags=flag_values[fi]; magic=magic_values[mi]; custom_open=ci?0x770000:0;
        open_success=success; callback_error=err;
        opens=reads=closes=clocks=errors=0; io_address=0;
        initial_sp=0x3E0000+alignment*4; base_sp=initial_sp-0x3E4;
        eax=0xAABBCCDD; ecx=0x99887766; edx=0x55667788; esp=initial_sp;
        ebx=0x12345678; esi=0x87654321; edi=0x9988CCDD;
        g_ebp=0xDEADBEEF; g_seh_ebp=0xBADF00D;
        g_fp_top=3; g_fp_cmp=7;
        for(unsigned i=0;i<8;++i)g_fp_stack[i]=1000.0+i;
        MEM32(initial_sp)=0x1A8518; MEM32(initial_sp+4)=path_address; MEM32(initial_sp+8)=flags;
        MEM32(0x32BF60)=0x12345678; MEM32(0x32BF64)=0x87654321;
        MEM32(0x32BF84)=custom_open;
        strcpy((char*)XBOX_PTR(path_address),"d:\\movies\\fixture.bik");
        ERROR_TEXT_INITIALIZERS
        sub_00280C10();
        CHECK(esp==initial_sp+12);
        CHECK(ebx==0x12345678 && esi==0x87654321 && edi==0x9988CCDD);
        CHECK(g_ebp==0xDEADBEEF && g_seh_ebp==0xBADF00D);
        CHECK(MEM32(initial_sp-0x3DC)==0xBADF00D);
        CHECK(MEM32(initial_sp)==0x1A8518 && MEM32(initial_sp+4)==path_address && MEM32(initial_sp+8)==flags);
        CHECK(g_fp_top==3 && g_fp_cmp==7);
        for(unsigned i=0;i<8;++i)CHECK(g_fp_stack[i]==1000.0+i);
        CHECK(clocks==1 && opens==1 && MEM32(0x32BF84)==0);
        CHECK(MEM32(0x32BF60)==((flags&0x4000)?0x12345678:1));
        CHECK(MEM32(0x32BF64)==((flags&0x4000)?0x87654321:0));
        if(historical && open_success) {
            CHECK(eax==1 && reads==0 && closes==0 && errors==0);
            CHECK(MEM8(0x3242B8)==0);
        } else {
            CHECK(eax==0 && reads==open_success && closes==open_success);
            const char *wanted;
            if(!open_success) {
                wanted=callback_error?"fixture open error":"Error opening file.";
                CHECK(errors==(callback_error?0:1));
            } else if(magic==0xDEADBEEFu) {
                wanted="Not a Bink file."; CHECK(errors==0);
            } else {
                wanted="The file doesn't contain any compressed frames yet."; CHECK(errors==1);
            }
            CHECK(strcmp((const char*)XBOX_PTR(0x3242B8),wanted)==0);
        }
    }
    printf("PASS: %u %s full-body cases; callbacks, header validation, cleanup, globals and RET8 ABI\n",
           case_number,historical?"historical false-success reproduction":"retail rejection");
    return 0;
}
'''

initializers = []
for address in (0x2BBE04, 0x2BBE39, 0x2BBE4C):
    data = retail_bytes(address, 100).split(b"\0", 1)[0] + b"\0"
    escaped = "".join(f"\\x{value:02x}" for value in data)
    initializers.append(f'memcpy((void*)XBOX_PTR(0x{address:X}),"{escaped}",{len(data)});')
suffix = suffix.replace("ERROR_TEXT_INITIALIZERS", "\n        ".join(initializers))

old_branch = "    if (TEST_NZ(_fa, _fb)) goto loc_00280CD7; /* jne: not equal / not zero */"
assert body.count(old_branch) == 1
fake_success = """    if (TEST_NZ(_fa, _fb)) {
        POP32(esp, edi); POP32(esp, esi); POP32(esp, ebp);
        esp += 0x3D8; esp += 12; return; /* historical false success */
    }"""
mutant = body.replace(old_branch, fake_success)
out_root = ROOT / "diagnostics/bink_open_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
for name, implementation, historical in [("recovered", body, 0), ("historical_false_success", mutant, 1)]:
    (out / f"{name}.c").write_text(prefix + helper_stubs + "\n" + implementation +
                                  suffix.replace("HISTORICAL", str(historical)), encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /W3 /TC /I"{ROOT / "src"}" {name}.c /Fe:{name}.exe'
    compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out,
                              capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if compiled.returncode: print(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True, text=True, timeout=20,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode: print(result.stderr)
    result.check_returncode()
    print(result.stdout, end="")
print(f"PASS: XBE extent, all branch targets and negative mutant verified; artifacts: {out}")
