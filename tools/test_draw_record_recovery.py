"""Compare native draw-record recovery and its real caller to retail x86.

No emulator/game process. An independent narrow instruction interpreter runs
the actual 16E200 and 15B160 bytes from the user's XBE, including both packed
flag adjustments, jump-table branches, partial-register writes, and RET 0x30.
"""
import ctypes as ct
import math
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image = (ROOT / "game_files/default.xbe").read_bytes()
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
instructions = {}
for begin, end in [(0x16E200, 0x16E3E6), (0x15B160, 0x15B1DC)]:
    s = next(s for s in config._SECTIONS if s.va <= begin < s.va+s.raw_size)
    offset = s.raw_addr+begin-s.va
    decoded = list(decoder.disasm(image[offset:offset+end-begin], begin))
    assert decoded[-1].address+decoded[-1].size == end
    instructions.update((i.address, i) for i in decoded)
assert len([a for a in instructions if 0x16E200 <= a < 0x16E3E6]) == 157
assert [(instructions[a].mnemonic, instructions[a].op_str) for a in range(0x16E3DF, 0x16E3E4)] == [
    ("pop", "edi"), ("pop", "esi"), ("pop", "ebp"), ("pop", "ebx"), ("ret", "0x30")]

def function(path, name):
    source = (ROOT/path).read_text(encoding="utf-8")
    return re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M|re.S).group()

fixed = function("src/recomp_manual.c", "sub_0016E200")
old = function("src/recomp/gen/recomp_0009.c", "sub_0016E200").replace("sub_0016E200", "historical")
caller = function("src/recomp/gen/recomp_0009.c", "sub_0015B160")
oldcaller = caller.replace("sub_0015B160", "historical_caller").replace("sub_0016E200", "historical")
prefix = r'''
#include <stdint.h>
#include <stdlib.h>
typedef union RecompXmm { float f[4]; uint32_t u[4]; } RecompXmm;
typedef void (*recomp_func_t)(void);
static uint32_t regs[9];
static unsigned char memory[0x400000];
static RecompXmm vectors[1];
#define g_eax regs[0]
#define g_ecx regs[1]
#define g_edx regs[2]
#define g_esp regs[3]
#define g_ebx regs[4]
#define g_esi regs[5]
#define g_edi regs[6]
#define g_ebp regs[7]
#define g_seh_ebp regs[8]
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define xmm0 vectors[0]
static uint32_t *manual_mem32(uint32_t a) { return (uint32_t *)(memory+a); }
static uint8_t *manual_mem8(uint32_t a) { return memory+a; }
#define MEM32(a) (*manual_mem32(a))
#define MEM16(a) (*(uint16_t *)(memory+(a)))
#define MEM8(a) (memory[(a)])
#define MEMF(a) (*(float *)(memory+(a)))
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
static RecompXmm scalar(float v) { RecompXmm r={{0}}; r.f[0]=v; return r; }
#define XMM_SCALAR(v) scalar(v)
#define LO8(v) ((uint8_t)(v))
#define LO16(v) ((uint16_t)(v))
#define SET_LO8(r,v) ((r)=((r)&0xFFFFFF00u)|(uint8_t)(v))
#define SET_LO16(r,v) ((r)=((r)&0xFFFF0000u)|(uint16_t)(v))
#define ZX8(v) ((uint32_t)(uint8_t)(v))
#define ZX16(v) ((uint32_t)(uint16_t)(v))
#define CMP_AE(a,b) ((uint32_t)(a)>=(uint32_t)(b))
static recomp_func_t recomp_lookup_manual(uint32_t a) { (void)a; return 0; }
static recomp_func_t recomp_lookup(uint32_t a) { (void)a; return 0; }
static recomp_func_t recomp_lookup_kernel(uint32_t a) { (void)a; return 0; }
static void recomp_icall_fail_log(uint32_t a) { (void)a; abort(); }
'''
suffix = r'''
__declspec(dllexport) void *test_memory(void) { return memory; }
__declspec(dllexport) void *test_regs(void) { return regs; }
__declspec(dllexport) void *test_vectors(void) { return vectors; }
__declspec(dllexport) void test_run(int which) {
    if(which==0) sub_0016E200(); else if(which==1) historical();
    else if(which==2) sub_0015B160(); else historical_caller();
}
'''
out = ROOT/"diagnostics/draw_record_recovery_test"
out.mkdir(exist_ok=True)
(out/"draw_record.c").write_text(prefix+fixed+old+caller+oldcaller+suffix, encoding="utf-8")
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
command = f'call "{vcvars}" >nul && cl /nologo /Od /fp:strict /TC /LD draw_record.c /Fe:draw_record.dll'
subprocess.run('cmd.exe /d /s /c "'+command+'"', cwd=out, check=True)
native = ct.CDLL(str(out/"draw_record.dll"))
views = {}
for name, kind, length in [("memory", ct.c_ubyte, 0x400000), ("regs", ct.c_uint32, 9), ("vectors", ct.c_uint32, 4)]:
    getter = getattr(native, "test_"+name)
    getter.restype = ct.c_void_p
    views[name] = (kind*length).from_address(getter())
native.test_run.argtypes = [ct.c_int]
names = ["eax", "ecx", "edx", "esp", "ebx", "esi", "edi", "ebp"]

def number(value): return struct.unpack("<f", struct.pack("<I", value))[0]

class Machine:
    """Retail-instruction oracle independent of the recovered C bitfield code."""
    def __init__(self, memory, regs, vectors):
        self.memory, self.regs, self.vectors = bytearray(memory), dict(regs), list(vectors)
        self.zero, self.carry, self.visited = False, False, set()
    def address(self, operand):
        m = operand.mem
        return (self.regs.get(decoder.reg_name(m.base), 0)+self.regs.get(decoder.reg_name(m.index), 0)*m.scale+m.disp)&0xFFFFFFFF
    def register(self, operand):
        name = decoder.reg_name(operand.reg)
        if name in names: return name, 32
        if name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"): return "e"+name, 16
        if name in ("al", "bl", "cl", "dl"): return "e"+name[0]+"x", 8
        raise AssertionError(name)
    def get(self, operand):
        if operand.type == X86_OP_IMM: return operand.imm&0xFFFFFFFF
        if operand.type == X86_OP_MEM:
            a = self.address(operand)
            return int.from_bytes(self.memory[a:a+operand.size], "little")
        if decoder.reg_name(operand.reg) == "xmm0": return self.vectors[0]
        name, width = self.register(operand)
        return self.regs[name]&((1<<width)-1)
    def put(self, operand, value):
        if operand.type == X86_OP_MEM:
            a = self.address(operand)
            self.memory[a:a+operand.size] = (value&((1<<(8*operand.size))-1)).to_bytes(operand.size, "little")
        elif decoder.reg_name(operand.reg) == "xmm0": self.vectors[0] = value&0xFFFFFFFF
        else:
            name, width = self.register(operand)
            mask = (1<<width)-1
            self.regs[name] = (self.regs[name]&~mask)|(value&mask)
    def push(self, value):
        self.regs["esp"] -= 4
        struct.pack_into("<I", self.memory, self.regs["esp"], value)
    def pop(self):
        value = struct.unpack_from("<I", self.memory, self.regs["esp"])[0]
        self.regs["esp"] += 4
        return value
    def run(self, ip):
        for _ in range(1000):
            i = instructions[ip]
            self.visited.add(ip)
            op, a = i.mnemonic, i.operands
            ip += i.size
            if op in ("mov", "movzx"): self.put(a[0], self.get(a[1]))
            elif op == "lea": self.put(a[0], self.address(a[1]))
            elif op in ("add", "sub", "and", "xor", "or", "shl"):
                left, right = self.get(a[0]), self.get(a[1])
                value = {"add": lambda:left+right, "sub":lambda:left-right, "and":lambda:left&right,
                         "xor":lambda:left^right, "or":lambda:left|right, "shl":lambda:left<<right}[op]()
                self.put(a[0], value)
            elif op == "inc": self.put(a[0], self.get(a[0])+1)
            elif op == "shrd": self.put(a[0], (self.get(a[0])>>self.get(a[2]))|(self.get(a[1])<<(32-self.get(a[2]))))
            elif op == "cdq": self.regs["edx"] = 0xFFFFFFFF if self.regs["eax"]&0x80000000 else 0
            elif op == "push": self.push(self.get(a[0]))
            elif op == "pop": self.put(a[0], self.pop())
            elif op == "cmp":
                self.zero = self.get(a[0]) == self.get(a[1])
                self.carry = self.get(a[0]) < self.get(a[1])
            elif op in ("je", "jne", "jbe", "ja", "jae", "jb", "jmp"):
                take = {"je":self.zero, "jne":not self.zero, "jbe":self.carry or self.zero,
                        "ja":not self.carry and not self.zero, "jae":not self.carry, "jb":self.carry, "jmp":True}[op]
                if take: ip = self.get(a[0])
            elif op == "call": self.push(ip); ip = self.get(a[0])
            elif op == "ret":
                ip = self.pop()
                self.regs["esp"] += self.get(a[0]) if a else 0
                if ip == 0xFEEDFACE: return
            elif op == "movss":
                self.put(a[0], self.get(a[1]))
                if a[0].type == X86_OP_REG and a[1].type == X86_OP_MEM: self.vectors[1:] = [0, 0, 0]
            elif op == "comiss":
                left, right = number(self.get(a[0])), number(self.get(a[1]))
                unordered = math.isnan(left) or math.isnan(right)
                self.zero, self.carry = unordered or left == right, unordered or left < right
            else: raise AssertionError(f"Unsupported {i.address:08X}: {op} {i.op_str}")
        raise AssertionError("Retail instruction budget exhausted")

base = bytearray(0x400000)
for s in config._SECTIONS:
    if s.va+s.raw_size <= len(base): base[s.va:s.va+s.raw_size] = image[s.raw_addr:s.raw_addr+s.raw_size]
assert list(base[0x16E3F8:0x16E403]) == [0,1,2,2,1,2,2,2,2,3,3]
assert struct.unpack_from("<4I", base, 0x16E3E8) == (0x16E3BB,0x16E3B0,0x16E3CB,0x16E3C0)
visited, cases = set(), 0
def setup(kind, value, override, caller=False, overlap=0):
    memory = bytearray(base)
    source, destination = 0x10000, 0x11000 if not overlap else 0x10000+overlap-1
    for a in range(0x10000, 0x12000): memory[a] = (a*43+a//17+13)%251
    def dword(a,v): struct.pack_into("<I", memory, a, v)
    dword(0x2CB8DC, 0x12000)
    memory[0x12070] = override
    dword(source+0x40, 0x21ABCD55|((kind&3)<<30))
    dword(source+0x44, 0xBAD5BEE0|(kind>>2))
    struct.pack_into("<f", memory, source+0x18, value)
    if caller:
        dword(source+0x68, destination)
        struct.pack_into("<H", memory, source+0x90, 0)
        args = [0x12345678,0x9ABCDEF0,0x12341234,0x45674567,0x89AB89AB,0xCDEFCDEF]
    else:
        args = [0x12345678,0x9ABCDEF0,source,0x12341234,0x45674567,0x89AB89AB,0xCDEFCDEF,
                0x78907890,0x11221122,0xA5A5B5B5,0xDEADBEEE,0xF1234ABC]
    stack = 0x3F0000-4*(len(args)+1)
    struct.pack_into("<"+"I"*(len(args)+1), memory, stack, 0xFEEDFACE, *args)
    regs = dict(zip(names, [0x10203040,source if caller else destination,0x50607080,stack,
                           0x20304050,0x30405060,0x40506070,0x50607080]))
    vectors = [0xCAFEBABE,0xDABBAD00,0x12345678,0xFEDCBA98]
    return memory, regs, vectors

def load(state):
    memory, regs, vectors = state
    ct.memmove(ct.addressof(views["memory"]), bytes(memory), len(memory))
    views["regs"][:] = [regs[n] for n in names]+[regs["ebp"]]
    views["vectors"][:] = vectors

def check(state, caller=False):
    global cases
    reference = Machine(*state)
    reference.run(0x15B160 if caller else 0x16E200)
    visited.update(reference.visited)
    load(state)
    native.test_run(2 if caller else 0)
    actual = dict(zip(names, list(views["regs"])[:8]))
    assert actual == reference.regs, (cases, actual, reference.regs)
    assert list(views["vectors"]) == reference.vectors, (cases, "XMM0")
    actual_memory = bytes(views["memory"])
    if actual_memory != reference.memory:
        a = next(i for i,(a,b) in enumerate(zip(actual_memory,reference.memory)) if a!=b)
        raise AssertionError((cases, hex(a), actual_memory[a:a+16],reference.memory[a:a+16]))
    assert actual["esp"] == 0x3F0000
    cases += 1

for kind in range(32):
    for value in (0.5,1.0,2.0,float("nan")):
        for override in (0,1): check(setup(kind,value,override))
for overlap in (1,5,17):
    for kind in (0,1,4,9,10,31): check(setup(kind,0.5,1,overlap=overlap))
for kind in range(32): check(setup(kind,0.5,kind&1,caller=True),caller=True)
state = setup(4,0.5,0,caller=True)
load(state)
native.test_run(3)
assert views["regs"][3] == 0x3F0000-0x44, hex(views["regs"][3])
assert views["regs"][5] != state[1]["esi"]
print(f"PASS: {cases} actual-body/retail cases; {len(visited)} retail instruction addresses; all memory, GPR, XMM0, ABI effects match")
print("PASS: actual historical caller reproduces 0x44-byte leak per emission (three = live 0xCC frame leak) and clobbered ESI")
