"""Compare native 15CD50 recovery to the local XBE's actual instructions.

Compiles the actual manual body and actual generated 13B550/13B480 trig
helpers. An independent small instruction interpreter executes all three
retail bodies, using a fixture of the retail-initialized cosine lookup table.
No game process is started.
The reference shares the project's double-backed x87 model; this is not a
claim of 80-bit x87 or wall-clock timing equivalence.
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
spans = [(0x15CD50, 0x15CE8B), (0x13B550, 0x13B578), (0x13B480, 0x13B525)]
instructions = {}
for begin, end in spans:
    section = next(s for s in config._SECTIONS if s.va <= begin < s.va + s.raw_size)
    offset = section.raw_addr + begin - section.va
    decoded = list(decoder.disasm(image[offset:offset + end-begin], begin))
    assert decoded[-1].address + decoded[-1].size == end
    instructions.update((i.address, i) for i in decoded)
assert len([a for a in instructions if 0x15CD50 <= a < 0x15CE8B]) == 68
assert [(instructions[a].mnemonic, instructions[a].op_str) for a in (0x15CD69, 0x15CD9F, 0x15CE86, 0x15CE87, 0x15CE8A)] == [
    ("je", "0x15cdb6"), ("call", "0x13b550"), ("pop", "esi"), ("add", "esp, 8"), ("ret", "")]

def function(path, name):
    source = (ROOT / path).read_text(encoding="utf-8")
    return re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S).group()

fixed = function("src/recomp_manual.c", "sub_0015CD50")
old = function("src/recomp/gen/recomp_0009.c", "sub_0015CD50").replace("void sub_0015CD50", "void historical")
trig = "\n".join(function("src/recomp/gen/recomp_0008.c", f"sub_{a:08X}") for a in (0x13B480, 0x13B550))
prefix = r'''
#include <stdint.h>
#include <math.h>
typedef union RecompXmm { float f[4]; double d[2]; uint32_t u[4]; uint64_t q[2]; } RecompXmm;
static uint32_t regs[9];
static unsigned char memory[0x400000];
static RecompXmm vectors[8];
static double g_fp_stack[8];
static int g_fp_top;
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
#define xmm1 vectors[1]
#define xmm2 vectors[2]
#define xmm3 vectors[3]
#define xmm4 vectors[4]
#define xmm5 vectors[5]
#define xmm6 vectors[6]
#define xmm7 vectors[7]
#define g_xmm4 vectors[4]
#define g_xmm5 vectors[5]
#define g_xmm6 vectors[6]
#define g_xmm7 vectors[7]
static uint32_t *manual_mem32(uint32_t a) { return (uint32_t *)(memory+a); }
#define MEM32(a) (*manual_mem32(a))
#define MEMF(a) (*(float *)(memory+(a)))
#define PUSH32(sp,v) do { uint32_t value=(v); (sp)-=4; MEM32(sp)=value; } while(0)
#define POP32(sp,v) do { (v)=MEM32(sp); (sp)+=4; } while(0)
static RecompXmm scalar(float v) { RecompXmm r={{0}}; r.f[0]=v; return r; }
#define XMM_ZERO() scalar(0)
#define XMM_SCALAR(v) scalar(v)
#define LO8(v) ((v)&255u)
#define TEST_Z(a,b) (((a)&(b))==0)
void sub_0015CDB6(void) { esp+=4; }
'''
suffix = r'''
__declspec(dllexport) void *test_memory(void) { return memory; }
__declspec(dllexport) void *test_regs(void) { return regs; }
__declspec(dllexport) void *test_vectors(void) { return vectors; }
__declspec(dllexport) void *test_fp(void) { return g_fp_stack; }
__declspec(dllexport) void *test_top(void) { return &g_fp_top; }
__declspec(dllexport) void test_run(int old) { if(old) historical(); else sub_0015CD50(); }
'''
out = ROOT / "diagnostics/projection_recovery_test"
out.mkdir(exist_ok=True)
(out / "projection.c").write_text(prefix + trig + fixed + old + suffix, encoding="utf-8")
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
command = f'call "{vcvars}" >nul && cl /nologo /Od /fp:strict /TC /LD projection.c /Fe:projection.dll'
subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
native = ct.CDLL(str(out / "projection.dll"))
views = {}
for name, kind, length in [("memory", ct.c_ubyte, 0x400000), ("regs", ct.c_uint32, 9),
                           ("vectors", ct.c_uint32, 32), ("fp", ct.c_double, 8), ("top", ct.c_int, 1)]:
    getter = getattr(native, "test_" + name)
    getter.restype = ct.c_void_p
    views[name] = (kind * length).from_address(getter())
native.test_run.argtypes = [ct.c_int]

def bits(value): return struct.unpack("<I", struct.pack("<f", value))[0]
def number(value): return struct.unpack("<f", struct.pack("<I", value))[0]
def rounded(value): return number(bits(value))
def signed(value): return ct.c_int32(value).value

class Machine:
    """Deliberately narrow retail-instruction oracle, not a function formula."""
    def __init__(self, memory, regs, vectors, fp, top):
        self.memory, self.regs, self.vectors = bytearray(memory), dict(regs), [list(v) for v in vectors]
        self.fp, self.top, self.zero, self.below_equal = list(fp), top, False, False
        self.visited = set()
    def address(self, operand):
        m = operand.mem
        return (self.regs.get(decoder.reg_name(m.base), 0) + self.regs.get(decoder.reg_name(m.index), 0)*m.scale + m.disp) & 0xFFFFFFFF
    def get(self, operand):
        if operand.type == X86_OP_IMM: return operand.imm & 0xFFFFFFFF
        if operand.type == X86_OP_MEM: return struct.unpack_from("<I", self.memory, self.address(operand))[0]
        name = decoder.reg_name(operand.reg)
        if name.startswith("xmm"): return self.vectors[int(name[3:])][0]
        if name in ("al", "cl"): return self.regs["e"+name[0]+"x"] & 255
        return self.regs[name]
    def put(self, operand, value):
        value &= 0xFFFFFFFF
        if operand.type == X86_OP_MEM: struct.pack_into("<I", self.memory, self.address(operand), value)
        else:
            name = decoder.reg_name(operand.reg)
            if name.startswith("xmm"): self.vectors[int(name[3:])][0] = value
            else: self.regs[name] = value
    def push(self, value):
        self.regs["esp"] -= 4
        struct.pack_into("<I", self.memory, self.regs["esp"], value)
    def pop(self):
        value = struct.unpack_from("<I", self.memory, self.regs["esp"])[0]
        self.regs["esp"] += 4
        return value
    def fp_push(self, value):
        self.top = (self.top - 1) & 7
        self.fp[self.top] = value
    def fp_pop(self):
        self.top = (self.top + 1) & 7
    def run(self):
        ip = 0x15CD50
        for _ in range(1000):
            i = instructions[ip]
            self.visited.add(ip)
            op, a = i.mnemonic, i.operands
            ip += i.size
            if op == "mov": self.put(a[0], self.get(a[1]))
            elif op in ("add", "sub", "and", "xor", "sar"):
                left, right = self.get(a[0]), self.get(a[1])
                value = {"add": lambda: left+right, "sub": lambda: left-right,
                         "and": lambda: left & right, "xor": lambda: left ^ right,
                         "sar": lambda: signed(left) >> right}[op]()
                self.put(a[0], value)
            elif op == "push": self.push(self.get(a[0]))
            elif op == "pop": self.put(a[0], self.pop())
            elif op == "test": self.zero = not (self.get(a[0]) & self.get(a[1]))
            elif op in ("je", "jbe", "jmp"):
                if op == "jmp" or (self.zero if op == "je" else self.below_equal): ip = a[0].imm
            elif op == "call": self.push(ip); ip = a[0].imm
            elif op == "ret":
                ip = self.pop()
                self.regs["esp"] += a[0].imm if a else 0
                if ip == 0xFEEDFACE: return
            elif op == "movss":
                self.put(a[0], self.get(a[1]))
                if a[0].type == X86_OP_REG and a[1].type == X86_OP_MEM:
                    self.vectors[int(decoder.reg_name(a[0].reg)[3:])][1:] = [0, 0, 0]
            elif op == "movaps":
                self.vectors[int(decoder.reg_name(a[0].reg)[3:])] = self.vectors[int(decoder.reg_name(a[1].reg)[3:])].copy()
            elif op == "xorps": self.vectors[int(decoder.reg_name(a[0].reg)[3:])] = [0]*4
            elif op in ("addss", "subss", "mulss", "divss"):
                left, right = number(self.get(a[0])), number(self.get(a[1]))
                value = {"addss": lambda: left+right, "subss": lambda: left-right,
                         "mulss": lambda: left*right, "divss": lambda: left/right}[op]()
                self.put(a[0], bits(value))
            elif op == "comiss": self.below_equal = number(self.get(a[0])) <= number(self.get(a[1]))
            elif op == "cvtsi2ss": self.put(a[0], bits(float(signed(self.get(a[1])))))
            elif op == "cvttss2si": self.put(a[0], int(number(self.get(a[1]))))
            elif op == "fld": self.fp_push(number(self.get(a[0])))
            elif op == "fldln2": self.fp_push(math.log(2))
            elif op == "fxch":
                next_slot = (self.top+1)&7
                self.fp[self.top], self.fp[next_slot] = self.fp[next_slot], self.fp[self.top]
            elif op == "fyl2x":
                self.fp[(self.top+1)&7] *= math.log2(self.fp[self.top]); self.fp_pop()
            elif op == "fdivp":
                self.fp[(self.top+1)&7] /= self.fp[self.top]; self.fp_pop()
            elif op == "fdiv": self.fp[self.top] /= number(self.get(a[0]))
            elif op == "fmul": self.fp[self.top] *= number(self.get(a[0]))
            elif op == "fstp": self.put(a[0], bits(self.fp[self.top])); self.fp_pop()
            else: raise AssertionError(f"Unsupported retail instruction {i.address:08X}: {op} {i.op_str}")
        raise AssertionError("Retail instruction budget exhausted")

base = bytearray(0x400000)
for section in config._SECTIONS:
    if section.va + section.raw_size <= len(base):
        base[section.va:section.va+section.raw_size] = image[section.raw_addr:section.raw_addr+section.raw_size]
# Runtime .bss table: retail 13B400..13B427 / 13C3B0 constructs 33 cosine
# entries, first rounding each (pi/2 * 1/32 * index) argument to float.
quarter_turn = struct.unpack_from("<f", base, 0x2C9BB0)[0]
step = struct.unpack_from("<f", base, 0x2AB374)[0]
assert step == 1/32
for index in range(33):
    struct.pack_into("<f", base, 0x3102F8+4*index,
                     math.cos(rounded(quarter_turn*step*index)))
reg_names = ["eax", "ecx", "edx", "esp", "ebx", "esi", "edi", "ebp", "seh"]
cases, all_visited, old_failures = 0, set(), set()
for camera in (False, True):
    for width, height in [(320, 240), (640, 480), (864, 480), (1280, 720)]:
        for fov in (math.pi/4, math.pi/3, math.pi/2):
            for scale in (0.5, 1.0, 1.25):
                memory = bytearray(base)
                viewport, camera_va, params, renderer = 0x380000, 0x381000, 0x382000, 0x383000
                def u(address, value): struct.pack_into("<I", memory, address, value)
                def f(address, value): struct.pack_into("<f", memory, address, value)
                u(0x2CA6A0, renderer); u(viewport+0x90, camera_va if camera else 0)
                u(camera_va+0xE8, params); f(params+0x28, fov); f(params+0x2C, scale)
                u(viewport+0x88, width); u(viewport+0x8C, height); f(viewport+0xB0, scale)
                f(viewport+0xA0, -17.25)
                u(renderer+0x228, 640); u(renderer+0x22C, 480)
                f(renderer+0x1E8, 1.125); f(renderer+0x1EC, 0.875)
                initial = [0x1111, viewport, 0x3333, 0x3EFFFC, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888]
                u(initial[3], 0xFEEDFACE)
                vectors = [[bits(1.0+j/8+i/16) for j in range(4)] for i in range(8)]
                fp, top = [100.0+i for i in range(8)], 3
                oracle = Machine(memory, zip(reg_names, initial), vectors, fp, top)
                oracle.run(); all_visited.update(oracle.visited)
                def load_native():
                    ct.memmove(views["memory"], bytes(memory), len(memory))
                    views["regs"][:] = initial
                    views["vectors"][:] = [v for row in vectors for v in row]
                    views["fp"][:] = fp; views["top"][0] = top
                load_native(); native.test_run(0)
                assert list(views["regs"]) == [oracle.regs[n] for n in reg_names], (camera, width, "GPR/ABI")
                assert list(views["vectors"]) == [v for row in oracle.vectors for v in row], (camera, width, "SSE")
                assert views["top"][0] == oracle.top == top, "x87 stack imbalance"
                for actual, expected in zip(views["fp"], oracle.fp):
                    assert math.isclose(actual, expected, rel_tol=2e-14, abs_tol=2e-14), (actual, expected)
                actual = bytes(views["memory"])
                assert actual == oracle.memory, (camera, width, height, fov, scale, "memory mismatch")
                if camera not in old_failures:
                    load_native(); native.test_run(1)
                    assert views["regs"][3] != 0x3F0000 or views["regs"][5] != initial[5]
                    old_failures.add(camera)
                cases += 1
assert old_failures == {False, True}
assert {0x15CD9F, 0x15CDB6, 0x15CE8A}.issubset(all_visited)
print(f"PASS: {cases} native projection cases match retail instruction execution, including real trig helpers")
print(f"PASS: {len(all_visited)} retail instruction addresses exercised; both historical truncated paths rejected")
print("Scope: project double-backed x87 model; not an 80-bit precision or timing proof")
