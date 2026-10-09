"""Native XG texture-header regression against actual retail x86 bytes.

No game/emulator process is opened. The independent instruction oracle runs
retail BSF and its actual 2D/cube/volume header call chain. Regenerated BSF/BSR
fixtures test aliases, 16-bit writes, memory, zero preservation, and live ZF.
"""
import ctypes as ct
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM

config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image = (ROOT / "game_files/default.xbe").read_bytes()
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
section = next(s for s in config._SECTIONS if s.va <= 0x260DC0 < s.va+s.raw_size)
offset = section.raw_addr + 0x260DC0-section.va
decoded = list(decoder.disasm(image[offset:offset+0x2B9], 0x260DC0))
assert decoded[-1].address+decoded[-1].size == 0x261079
instructions = {i.address: i for i in decoded}
assert image[offset+0x1C:offset+0x26].hex() == "51890c240fbc042459c3"
assert [(i.mnemonic, i.op_str) for i in decoded if 0x260DDC <= i.address < 0x260DE6] == [
    ("push", "ecx"), ("mov", "dword ptr [esp], ecx"),
    ("bsf", "eax, dword ptr [esp]"), ("pop", "ecx"), ("ret", "")]
assert [i.address for i in decoded if i.mnemonic == "call" and i.operands[0].imm == 0x260DDC] == [
    0x260E6D, 0x260E78, 0x260E85]

source = (ROOT / "src/recomp/gen/recomp_missing_complete.c").read_text()
names = ["sub_00260DC0", "sub_00260DDC", "sub_00260DE6", "sub_00260DF9",
         "sub_00260F98", "sub_00261025", "sub_0026104F"]
def function(name):
    match = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    assert match, name
    return match.group()
bodies = [function(name) for name in names]
database = {0x260DDC: {"name": "sub_00260DDC", "end": 0x260DE6, "size": 10}}
generated = FunctionTranslator(image, database).translate_function(0x260DDC, database[0x260DDC])
assert generated[generated.index("void sub_00260DDC(void)"):].strip() == function("sub_00260DDC")
assert "TODO: bsf" not in function("sub_00260DDC")
historical_bodies = []
for body in bodies:
    if "void sub_00260DDC" in body:
        body = re.sub(r"    \{ uint32_t _bs_value = .*?\} \} /\* bsf.*?\*/",
                      "    /* historical unimplemented bsf */", body, flags=re.S)
    for name in names:
        body = body.replace(name, "historical_"+name)
    historical_bodies.append(body)

synthetic = [
    ("bsf_alias", "0fbcc00f94c1c3"),
    ("bsr_alias", "0fbdc00f94c1c3"),
    ("bsf16_source_overwrite", "660fbcc1b9000000000f94c2c3"),
    ("bsr_memory_overwrite", "0fbd02c702000000000f94c1c3"),
    ("bsf_alias_branch", "0fbcc07407b901000000eb05b902000000c3"),
]
synthetic_bodies = []
for label, hexcode in synthetic:
    raw = bytes.fromhex(hexcode)
    fixture = bytearray(image)
    begin = 0x260DDC
    file_offset = section.raw_addr+begin-section.va
    fixture[file_offset:file_offset+len(raw)] = raw
    info = {"name": "sub_00260DDC", "end": begin+len(raw), "size": len(raw)}
    code = FunctionTranslator(bytes(fixture), {begin: info}).translate_function(begin, info)
    body = code[code.index("void sub_00260DDC(void)"):].strip()
    assert "TODO" not in body, label
    synthetic_bodies.append(body.replace("sub_00260DDC", label))

prefix = r'''
#include <stdint.h>
#include <string.h>
static uint32_t regs[8];
static unsigned char memory[0x400000];
#define eax regs[0]
#define ecx regs[1]
#define edx regs[2]
#define esp regs[3]
#define ebx regs[4]
#define esi regs[5]
#define edi regs[6]
#define g_ebp regs[7]
#define MEM32(a) (*(uint32_t *)(memory+(a)))
#define MEM16(a) (*(uint16_t *)(memory+(a)))
#define MEM8(a) (memory[(a)])
#define LO8(a) ((uint8_t)(a))
#define LO16(a) ((uint16_t)(a))
#define SET_LO8(r,v) ((r)=((r)&0xFFFFFF00u)|(uint8_t)(v))
#define SET_LO16(r,v) ((r)=((r)&0xFFFF0000u)|(uint16_t)(v))
#define PUSH32(sp,v) do {uint32_t tmp=(v);(sp)-=4;MEM32(sp)=tmp;} while(0)
#define POP32(sp,v) do {(v)=MEM32(sp);(sp)+=4;} while(0)
#define CMP_EQ(a,b) ((a)==(b))
#define CMP_NE(a,b) ((a)!=(b))
#define CMP_BE(a,b) ((uint32_t)(a)<=(uint32_t)(b))
#define CMP_A(a,b) ((uint32_t)(a)>(uint32_t)(b))
#define TEST_NZ(a,b) (((a)&(b))!=0)
#define TEST_Z(a,b) (((a)&(b))==0)
'''
exports = names[1:2] + names[4:] + ["historical_"+name for name in names[1:2]+names[4:]]
exports += [label for label, _ in synthetic]
suffix = '\n__declspec(dllexport) void *test_memory(void) {return memory;}\n'
suffix += '__declspec(dllexport) void *test_regs(void) {return regs;}\n'
suffix += '__declspec(dllexport) void test_run(int which) {switch(which) {\n'
suffix += '\n'.join(f'case {i}: {name}(); break;' for i, name in enumerate(exports))+'\n}}\n'
out = ROOT / "diagnostics/xg_texture_header_bsf_recovery_test"
out.mkdir(exist_ok=True)
(out / "header_bsf.c").write_text(prefix+'\n'.join(bodies+historical_bodies+synthetic_bodies)+suffix)
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /LD header_bsf.c /Fe:header_bsf.dll'
subprocess.run('cmd.exe /d /s /c "'+command+'"', cwd=out, check=True)
native = ct.CDLL(str(out / "header_bsf.dll"))
native.test_memory.restype = native.test_regs.restype = ct.c_void_p
memory = (ct.c_ubyte * 0x400000).from_address(native.test_memory())
regs = (ct.c_uint32 * 8).from_address(native.test_regs())
native.test_run.argtypes = [ct.c_int]
register_names = ["eax", "ecx", "edx", "esp", "ebx", "esi", "edi", "ebp"]

class Machine:
    """Independent interpreter of actual retail bytes, not the C packing code."""
    def __init__(self, data, values):
        self.memory, self.regs = bytearray(data), dict(zip(register_names, values))
        self.zero, self.carry, self.visited = False, False, set()
    def address(self, operand):
        m = operand.mem
        return (self.regs.get(decoder.reg_name(m.base), 0)+self.regs.get(decoder.reg_name(m.index), 0)*m.scale+m.disp)&0xFFFFFFFF
    def register(self, operand):
        name = decoder.reg_name(operand.reg)
        if name in register_names: return name, 32
        if name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"): return "e"+name, 16
        if name in ("al", "bl", "cl", "dl"): return "e"+name[0]+"x", 8
        raise AssertionError(name)
    def get(self, operand):
        if operand.type == X86_OP_IMM: return operand.imm&0xFFFFFFFF
        if operand.type == X86_OP_MEM:
            a = self.address(operand)
            return int.from_bytes(self.memory[a:a+operand.size], "little")
        name, width = self.register(operand)
        return self.regs[name]&((1<<width)-1)
    def put(self, operand, value):
        if operand.type == X86_OP_MEM:
            a = self.address(operand)
            self.memory[a:a+operand.size] = (value&((1<<(8*operand.size))-1)).to_bytes(operand.size, "little")
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
        for _ in range(10000):
            i = instructions[ip]
            self.visited.add(ip)
            op, a = i.mnemonic, i.operands
            ip += i.size
            if op == "mov": self.put(a[0], self.get(a[1]))
            elif op == "lea": self.put(a[0], self.address(a[1]))
            elif op in ("add", "sub", "and", "xor", "or", "shl", "shr", "sbb", "imul"):
                left, right = self.get(a[0]), self.get(a[1])
                old_carry = self.carry
                shift = right&31
                value = {"add":lambda:left+right, "sub":lambda:left-right,
                         "and":lambda:left&right, "xor":lambda:left^right, "or":lambda:left|right,
                         "shl":lambda:left<<shift, "shr":lambda:left>>shift,
                         "sbb":lambda:left-right-int(old_carry), "imul":lambda:left*right}[op]()
                self.put(a[0], value)
                result = self.get(a[0])
                self.zero = result == 0
                if op == "add": self.carry = value > 0xFFFFFFFF
                elif op in ("sub", "sbb"): self.carry = value < 0
                elif op in ("and", "xor", "or"): self.carry = False
                elif op == "shl" and shift: self.carry = bool((left>>(32-shift))&1)
                elif op == "shr" and shift: self.carry = bool((left>>(shift-1))&1)
            elif op in ("inc", "dec"):
                self.put(a[0], self.get(a[0])+(1 if op == "inc" else -1))
                self.zero = self.get(a[0]) == 0
            elif op == "neg":
                value = self.get(a[0])
                self.put(a[0], -value)
                self.carry, self.zero = value != 0, value == 0
            elif op == "bsf":
                value = self.get(a[1])
                self.zero = value == 0
                if value: self.put(a[0], (value & -value).bit_length()-1)
            elif op == "push": self.push(self.get(a[0]))
            elif op == "pop": self.put(a[0], self.pop())
            elif op in ("cmp", "test"):
                left, right = self.get(a[0]), self.get(a[1])
                self.zero = left == right if op == "cmp" else (left&right) == 0
                self.carry = left < right if op == "cmp" else False
            elif op == "setne": self.put(a[0], int(not self.zero))
            elif op in ("je", "jne", "jbe", "ja", "jmp"):
                take = {"je":self.zero, "jne":not self.zero, "jbe":self.carry or self.zero,
                        "ja":not self.carry and not self.zero, "jmp":True}[op]
                if take: ip = self.get(a[0])
            elif op == "call": self.push(ip); ip = self.get(a[0])
            elif op == "leave": self.regs["esp"] = self.regs["ebp"]; self.regs["ebp"] = self.pop()
            elif op == "ret":
                ip = self.pop()
                self.regs["esp"] += self.get(a[0]) if a else 0
                if ip == 0xFEEDFACE: return
            else: raise AssertionError(f"Unsupported {i.address:08X}: {op} {i.op_str}")
        raise AssertionError("Retail instruction budget exhausted")

base = bytearray(0x400000)
for s in config._SECTIONS:
    if s.va+s.raw_size <= len(base): base[s.va:s.va+s.raw_size] = image[s.raw_addr:s.raw_addr+s.raw_size]
seeds = [0, 0x13579BDF, 0xFEDCBA98]
rng = random.Random(0x260DDC)
values = [0]+[1<<bit for bit in range(32)]+[rng.getrandbits(32) for _ in range(256)]
cases, historical_failures, visited = 0, 0, set()
def setup(eax=0x13579BDF, ecx=0x2468ACE0, args=()):
    data = bytearray(base)
    state = [eax,ecx,0x30000,0x3F0000,0x0BADBEEF,0x12345678,0x87654321,0x003EF000]
    struct.pack_into('<I', data, state[3], 0xFEEDFACE)
    for index, value in enumerate(args): struct.pack_into('<I', data, state[3]+4*(index+1), value)
    return data, state
def invoke(name, data, state):
    ct.memmove(memory, bytes(data), len(data))
    regs[:] = state
    native.test_run(exports.index(name))
    return list(regs)
for value in values:
    for seed in seeds:
        data, state = setup(seed, value)
        oracle = Machine(data, state)
        oracle.run(0x260DDC)
        got = invoke('sub_00260DDC', data, state)
        assert got == [oracle.regs[name] for name in register_names], (value, seed, got)
        assert bytes(memory[0x3EFFF8:0x3F0008]) == bytes(oracle.memory[0x3EFFF8:0x3F0008])
        old = invoke('historical_sub_00260DDC', data, state)
        historical_failures += old[0] != got[0]
        visited.update(oracle.visited)
        cases += 1

# Proven title formats: separate run17/fire_texture_parity_20261008.json
# verifies retail/candidate base-level payload identity for these dimensions.
title = [(256,256,1,15,0x08810F29), (32,32,1,12,0x05510C29),
         (64,16,1,12,0x04610C29), (64,64,5,12,0x06650C29),
         (128,128,6,12,0x07760C29), (512,256,7,15,0x08970F29),
         (256,256,7,12,0x08870C29), (256,256,7,15,0x08870F29),
         (64,64,5,15,0x06650F29), (256,128,6,12,0x07860C29),
         (64,64,1,15,0x06610F29)]
header_cases = []
for w,h,mips,fmt,packed in title:
    header_cases.append(('sub_00261025', 0x261025, (w,h,mips,0,fmt,0,0x350000,0x86A20200,0), packed))
header_cases += [
    ('sub_00261025',0x261025,(128,64,0,0,12,0,0x350000,0x80001000,0),None),
    ('sub_00261025',0x261025,(640,480,1,0,0x12,0,0x350000,0x80001000,2560),None),
    ('sub_00261025',0x261025,(64,32,3,0x10000,15,0,0x350000,0x80001000,0),None),
    ('sub_0026104F',0x26104F,(64,0,0,12,0,0x350000,0x80002000,0),None),
    ('sub_00260F98',0x260F98,(64,32,4,0,0,12,0,0,1,0x80003000,0x350000),None),
]
for name, begin, args, expected in header_cases:
    data, state = setup(args=args)
    oracle = Machine(data, state)
    oracle.run(begin)
    got = invoke(name, data, state)
    assert bytes(memory[0x350000:0x350014]) == bytes(oracle.memory[0x350000:0x350014]), (name,args)
    assert got[:7] == [oracle.regs[name] for name in register_names[:7]], (name,args,got,oracle.regs)
    if expected is not None: assert struct.unpack_from('<I', bytes(memory),0x35000C)[0] == expected
    old = invoke('historical_'+name, data, state)
    historical_failures += bytes(memory[0x35000C:0x350010]) != bytes(oracle.memory[0x35000C:0x350010])
    visited.update(oracle.visited)
    cases += 1

for label, _ in synthetic:
    for value in values:
        data, state = setup(value if 'alias' in label else 0xA5A50077, value)
        struct.pack_into('<I', data,0x30000,value)
        got = invoke(label, data, state)
        masked = value&0xFFFF if label.startswith('bsf16') else value
        index = ((masked&-masked).bit_length()-1 if label.startswith('bsf') else masked.bit_length()-1) if masked else state[0]
        if label.startswith('bsf16'):
            expected = (state[0]&0xFFFF0000)|(index&0xFFFF)
            assert got[0] == expected and got[1] == 0 and got[2]&0xFF == (masked == 0), (label,value,got)
        else:
            assert got[0] == index, (label,value,got,index)
            if label.endswith('branch'): assert got[1] == (2 if not masked else 1)
            else: assert got[1]&0xFF == (masked == 0)
        assert got[3] == state[3]+4
        assert got[4:] == state[4:]
        cases += 1
assert historical_failures > 500
assert {0x260E6D,0x260E78,0x260E85,0x261046,0x261070} <= visited
summary = dict(cases=cases,historical_failures=historical_failures,
               retail_instructions_visited=len(visited), title_formats_verified=len(title),
               exact_helper_bytes='51890c240fbc042459c3', regeneration_matches=True)
(out / 'result.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS',json.dumps(summary))
