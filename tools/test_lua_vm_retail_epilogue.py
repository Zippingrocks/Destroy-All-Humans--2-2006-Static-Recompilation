"""Native 21964C epilogue equivalence and historical forced-restart rejection.

Only bounded generated epilogues are compiled. Retail code is verified directly
from the authorized local XBE; no game, renderer, emulator or UI is launched.
"""
from pathlib import Path
import hashlib
import re
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config

XBE = ROOT / "game_files/default.xbe"
image = XBE.read_bytes()
assert hashlib.sha256(image).hexdigest() == "906871912263ae25de9f1c8e642ec0443b651b4beaf28b05057281ddc58baa1c"
config.configure_from_xbe(str(XBE))
start, end = 0x21964C, 0x21965A
offset = config.va_to_file_offset(start)
retail = image[offset:offset + end - start]
assert retail == bytes.fromhex("892F5F5E8BC55D5B83C420C20400"), retail.hex()
instructions = [(ins.address, ins.mnemonic, ins.op_str, ins.size)
                for ins in Cs(CS_ARCH_X86, CS_MODE_32).disasm(retail, start)]
assert instructions == [
    (0x21964C, "mov", "dword ptr [edi], ebp", 2),
    (0x21964E, "pop", "edi", 1),
    (0x21964F, "pop", "esi", 1),
    (0x219650, "mov", "eax, ebp", 2),
    (0x219652, "pop", "ebp", 1),
    (0x219653, "pop", "ebx", 1),
    (0x219654, "add", "esp, 0x20", 3),
    (0x219657, "ret", "4", 3),
], instructions

generated = (ROOT / "src/recomp/gen/recomp_0013.c").read_text(encoding="utf-8")
parent = re.search(r"^void sub_00218D70\(void\)\n\{.*?^\}", generated, re.M | re.S)
assert parent
inline_match = re.search(r"^loc_0021964C: ;\n(.*?)^loc_0021965A: ;", parent.group(), re.M | re.S)
assert inline_match
inline = inline_match.group(1).rstrip()
assert "goto" not in inline and "g_dah2_postloader_stack_calls" not in inline, inline
assert inline.count("dah2_capture_return_landmark(0x0021964Cu, ebp);") == 1
assert inline.count("dah2_vm_native_trace_exit(2u, trace_native_function, esp);") == 1
isolated_match = re.search(r"^void sub_0021964C\(void\)\n\{.*?^\}", generated, re.M | re.S)
assert isolated_match
isolated = isolated_match.group()
assert "ebp = g_seh_ebp;" in isolated and "dah2_capture_return_landmark" in isolated

# Observing the restored local EBP does not alter any guest instruction. The
# generated runtime intentionally keeps that C local separate from g_seh_ebp.
tail = "    esp += 8; return; /* ret 4 */"
observed_tail = "    observed_frame = ebp;\n" + tail
assert inline.count(tail) == isolated.count(tail) == 1
inline = inline.replace(tail, observed_tail)
isolated = isolated.replace(tail, observed_tail)
historical = r"""
    if (g_dah2_postloader_stack_calls == 6u &&
        g_dah2_input_shell_parent_reentries == 0u) {
        uint32_t _function = MEM32(esp + 0x18u);
        uint32_t _code = MEM32(_function + 0x18u);
        if (MEM32(esp + 0x10u) == _code + 0x98u) {
            ++g_dah2_input_shell_parent_reentries;
            MEM32(edi) = ebp;
            MEM32(esp + 0x10u) = _code;
            goto loc_00218DF1;
        }
    }
"""
capture = "    dah2_capture_return_landmark(0x0021964Cu, ebp);"
mutant_inline = inline.replace(capture, capture + "\n" + historical)
assert mutant_inline != inline

prefix = f'#include "{(ROOT / "src/recomp/recomp_types.h").as_posix()}"\n' + r"""
#include <stdio.h>
#include <stdlib.h>
#undef fprintf
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_ebp,g_seh_ebp,g_seh_head;
ptrdiff_t g_xbox_mem_offset;
static unsigned char memory[0x10000],before[0x10000],expected[0x10000];
static uint32_t input_frame,observed_frame,g_dah2_postloader_stack_calls;
static uint32_t g_dah2_input_shell_parent_reentries,dispatch_count;
static uint32_t capture_count,capture_va,capture_frame,capture_sp;
static uint32_t exit_count,exit_stage,exit_function,exit_sp;
static const uint32_t trace_native_function = 0x76543210u;
void dah2_watch_natalia_x_access(uint32_t a,const char *f,int line){(void)a;(void)f;(void)line;abort();}
void dah2_watch_timing_link_access(uint32_t a,const char *f,int line){(void)a;(void)f;(void)line;abort();}
static void dah2_capture_return_landmark(uint32_t va,uint32_t frame) {
    ++capture_count;capture_va=va;capture_frame=frame;capture_sp=esp;
}
static void dah2_vm_native_trace_exit(uint32_t stage,uint32_t function,uint32_t sp) {
    ++exit_count;exit_stage=stage;exit_function=function;exit_sp=sp;
}
typedef struct {uint32_t a,c,d,sp,b,si,di,bp,ip;} Cpu;
static uint32_t read32(const unsigned char *ram,uint32_t address) {
    if(address>sizeof(memory)-4)abort();
    return (uint32_t)ram[address] | ((uint32_t)ram[address+1]<<8) |
           ((uint32_t)ram[address+2]<<16) | ((uint32_t)ram[address+3]<<24);
}
static void write32(unsigned char *ram,uint32_t address,uint32_t value) {
    if(address>sizeof(memory)-4)abort();
    for(unsigned n=0;n<4;n++)ram[address+n]=(unsigned char)(value>>(n*8));
}
static const unsigned char retail_code[] = {RETAIL_BYTES};
/* Independent byte-driven x86 execution, not a second copy of generated C. */
static void reference(Cpu *cpu,unsigned char *ram) {
    unsigned pc=0,instructions=0;
    while(pc<sizeof(retail_code)) {
        unsigned opcode=retail_code[pc++];++instructions;
        if(opcode==0x89) {if(retail_code[pc++]!=0x2f)abort();write32(ram,cpu->di,cpu->bp);}
        else if(opcode==0x8b) {if(retail_code[pc++]!=0xc5)abort();cpu->a=cpu->bp;}
        else if(opcode==0x5f) {cpu->di=read32(ram,cpu->sp);cpu->sp+=4;}
        else if(opcode==0x5e) {cpu->si=read32(ram,cpu->sp);cpu->sp+=4;}
        else if(opcode==0x5d) {cpu->bp=read32(ram,cpu->sp);cpu->sp+=4;}
        else if(opcode==0x5b) {cpu->b=read32(ram,cpu->sp);cpu->sp+=4;}
        else if(opcode==0x83) {if(retail_code[pc++]!=0xc4)abort();cpu->sp+=(int8_t)retail_code[pc++];}
        else if(opcode==0xc2) {
            unsigned cleanup=retail_code[pc] | (retail_code[pc+1]<<8);pc+=2;
            cpu->ip=read32(ram,cpu->sp);cpu->sp+=4+cleanup;
        } else abort();
    }
    if(instructions!=8)abort();
}
static uint32_t random_bits=0x13579bdfu;
static uint32_t next(void){random_bits=random_bits*1664525u+1013904223u;return random_bits;}
""".replace("RETAIL_BYTES", ",".join(f"0x{byte:02x}" for byte in retail))

suffix = r"""
static int check_case(unsigned number,unsigned isolated_form) {
    for(unsigned n=0;n<sizeof(memory);n++)memory[n]=(unsigned char)next();
    Cpu original={next(),next(),next(),0x9000u+(next()%0x800u&~3u),next(),next(),
                  0x1000u+(next()%0x200u&~3u),0x4000u+(next()%0x2000u&~3u),0};
    const uint32_t function=0x2000u+(next()%0x200u&~3u);
    const uint32_t code=0x3000u+(next()%0x200u&~3u);
    static const uint32_t counts[]={6,0,5,7,0xffffffffu};
    g_dah2_postloader_stack_calls=counts[number%5];
    const uint32_t initial_reentries=(number/5)%2;
    g_dah2_input_shell_parent_reentries=initial_reentries;
    const uint32_t ip_delta=(number/10)%3==0 ? 0x98u : (number/10)%3==1 ? 0u : 0x99u;
    write32(memory,original.sp,next());write32(memory,original.sp+4,next());
    write32(memory,original.sp+8,next());write32(memory,original.sp+12,next());
    write32(memory,original.sp+0x10,code+ip_delta);
    write32(memory,original.sp+0x18,function);write32(memory,function+0x18,code);
    const uint32_t return_address=next(),argument=next();
    write32(memory,original.sp+0x30,return_address);
    write32(memory,original.sp+0x34,argument);
    memcpy(before,memory,sizeof(memory));memcpy(expected,memory,sizeof(memory));
    Cpu wanted=original;reference(&wanted,expected);
    if(wanted.sp!=original.sp+0x38 || wanted.ip!=return_address ||
       wanted.a!=original.bp || wanted.c!=original.c || wanted.d!=original.d ||
       read32(expected,original.di)!=original.bp)abort();
    eax=original.a;ecx=original.c;edx=original.d;esp=original.sp;
    ebx=original.b;esi=original.si;edi=original.di;
    input_frame=original.bp;g_seh_ebp=original.bp;g_ebp=0xabcdef01u;
    observed_frame=0;capture_count=exit_count=dispatch_count=0;
    if(isolated_form)sub_0021964C();else run_inline();
    const int match=esp==wanted.sp && eax==wanted.a && ecx==wanted.c && edx==wanted.d &&
        ebx==wanted.b && esi==wanted.si && edi==wanted.di && observed_frame==wanted.bp &&
        !memcmp(memory,expected,sizeof(memory)) && g_seh_ebp==original.bp && g_ebp==0xabcdef01u &&
        g_dah2_input_shell_parent_reentries==initial_reentries && !dispatch_count &&
        capture_count==1 && capture_va==0x21964cu && capture_frame==original.bp &&
        capture_sp==original.sp &&
        (isolated_form ? exit_count==0 : exit_count==1 && exit_stage==2 &&
            exit_function==trace_native_function && exit_sp==original.sp+0x30u);
    if(!match) {
        fprintf(stderr,"retail mismatch case=%u isolated=%u callbacks=%u reentries=%u delta=%x dispatch=%u esp=%x wanted=%x\n",
                number,isolated_form,g_dah2_postloader_stack_calls,initial_reentries,ip_delta,
                dispatch_count,esp,wanted.sp);
        return 0;
    }
    /* Only the Lua-top word may change; return/argument, function/code and all
     * stack bytes remain intact even with historical trigger callbacks=6/IP+98. */
    unsigned changed=0;
    for(unsigned n=0;n<sizeof(memory);n++)if(memory[n]!=before[n]) {
        if(n<original.di || n>=original.di+4)abort();changed++;
    }
    if(changed>4 || read32(memory,original.sp+0x30)!=return_address ||
       read32(memory,original.sp+0x34)!=argument ||
       read32(memory,original.sp+0x10)!=code+ip_delta)abort();
    return 1;
}
int main(void) {
    g_xbox_mem_offset=(ptrdiff_t)(uintptr_t)memory;
    unsigned cases=0;
    for(unsigned n=0;n<2048;n++)for(unsigned form=0;form<2;form++) {
        if(!check_case(n,form))return 3;cases++;
    }
    printf("PASS: %u actual inline/isolated epilogue cases, verified14 retail bytes/8insns, completeRAM/Luatop/RET4/nonvolatiles/EAX and observational hooks\n",cases);
    return 0;
}
"""


def translation(inline_candidate):
    # The trap represents a forbidden redispatch, not a replacement VM path.
    return (prefix + "\nstatic void run_inline(void) {\n    uint32_t ebp=input_frame;\n" +
            inline_candidate + "\nloc_00218DF1: ;\n    ++dispatch_count;return;\n}\n" +
            isolated + "\n" + suffix)


with tempfile.TemporaryDirectory(prefix="dah2-retail-vm-epilogue-") as temporary:
    directory = Path(temporary)
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    for name, candidate in (("retail", inline), ("historical", mutant_inline)):
        (directory / f"{name}.c").write_text(translation(candidate), encoding="utf-8")
        command = (f'call "{vcvars}" >nul && cl /nologo /TC /W4 /O2 '
                   f'/I"{ROOT / "src"}" {name}.c /Fe:{name}.exe')
        built = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=directory,
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if built.returncode:
            raise AssertionError(built.stdout + built.stderr)
        completed = subprocess.run([str(directory / f"{name}.exe")], cwd=directory,
            capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        if name == "retail":
            assert completed.returncode == 0, completed.stdout + completed.stderr
            print(completed.stdout.strip())
        else:
            assert completed.returncode == 3, completed.stdout + completed.stderr
            assert "callbacks=6 reentries=0 delta=98 dispatch=1" in completed.stderr, completed.stderr
            print("PASS: historical callback6/IP+98 forced restart mutant rejected; normal RET4 required")
