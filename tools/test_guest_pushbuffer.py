"""Compile and exercise the actual bridge parser with synthetic guest memory.

No renderer, emulator, UI, or full project build is started. The C functions are
extracted from guest_nv2a_bridge.c so regressions test the production decoder,
not a Python reimplementation. Requires the installed MSVC C compiler.
"""

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/guest_nv2a_bridge.c").read_text(encoding="utf-8")
DEFINITIONS = SOURCE[SOURCE.index("#define DAH2_PB_ADDRESS_MASK"):SOURCE.index("static int dah2_guest_span_valid")]
BOUNDS = SOURCE[SOURCE.index("static int dah2_read_guest_ring"):SOURCE.index("static int dah2_guest_gpu_init_locked")]
PARSER = SOURCE[SOURCE.index("static int dah2_pb_cursor_valid"):SOURCE.index("void dah2_guest_gpu_commit(")]

PREFIX = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef int SRWLOCK;
typedef void IDirect3D8;
typedef void IDirect3DDevice8;
#define SRWLOCK_INIT 0
#define DEVICE 0x00010000u
#define CPU_BASE 0x86E01000u
#define PHYS_BASE 0x06E01000u
#define RING_SIZE 0x200000u
static uint32_t device_memory[1024];
static uint32_t ring_memory[RING_SIZE / 4];
static uint32_t methods[256], parameters[256], subchannels[256];
static unsigned int method_count;
static int span(uint32_t address, uint32_t size) {
    if (!size || address > UINT32_MAX - size) return 0;
    return (address >= DEVICE && address + size <= DEVICE + sizeof(device_memory)) ||
           (address >= CPU_BASE && address + size <= CPU_BASE + sizeof(ring_memory));
}
static uint32_t *word(uint32_t address) {
    assert((address & 3u) == 0 && span(address, 4));
    if (address >= CPU_BASE) return &ring_memory[(address - CPU_BASE) / 4];
    return &device_memory[(address - DEVICE) / 4];
}
#define MEM32(address) (*word((uint32_t)(address)))
#define XBOX_PTR(address) ((uintptr_t)word((uint32_t)(address)))
static int dah2_guest_span_valid(uint32_t address, uint32_t size) { return span(address, size); }
static long InterlockedIncrement(volatile long *value) { return ++*value; }
static int dah2_guest_gpu_init_locked(void) { return 1; }
static void pgraph_d3d11_method(int subchannel, uint32_t method, uint32_t parameter) {
    assert(method_count < 256);
    methods[method_count] = method;
    parameters[method_count] = parameter;
    subchannels[method_count++] = (uint32_t)subchannel;
}
'''

SUFFIX = r'''
static uint32_t packet(unsigned int count, unsigned int method) {
    return (count << 18) | method;
}
static void reset(void) {
    memset(&g_bridge, 0, sizeof(g_bridge));
    memset(device_memory, 0, sizeof(device_memory));
    memset(ring_memory, 0, sizeof(ring_memory));
    method_count = 0;
    MEM32(DEVICE) = CPU_BASE;
    MEM32(DEVICE + 4) = CPU_BASE + 0xFDFC;
    MEM32(DEVICE + 0x24) = CPU_BASE;
    MEM32(DEVICE + 0x28) = CPU_BASE + RING_SIZE;
    MEM32(DEVICE + 0x2C) = 7;
    MEM32(DEVICE + 0x30) = DEVICE + 0x200;
    MEM32(DEVICE + 0x200) = 3;
}
static void commit(unsigned int offset) { dah2_guest_gpu_commit_locked(DEVICE, CPU_BASE + offset); }
static void attach(void) { commit(0); }
int main(void) {
    uint32_t preview[2];
    reset();
    ring_memory[0]=0x12345678; ring_memory[1]=0xFEDCBA98;
    assert(dah2_guest_gpu_read_physical(PHYS_BASE, preview, sizeof(preview)));
    assert(preview[0]==ring_memory[0] && preview[1]==ring_memory[1]);
    assert(!dah2_guest_gpu_read_physical(PHYS_BASE, preview, 0));
    assert(!dah2_guest_gpu_read_physical(0x08000000, preview, 4));
    assert(!dah2_guest_gpu_read_physical(0x07FFFFFC, preview, 8));
    assert(!dah2_guest_gpu_read_physical(0xFFFFFFFF, preview, 8));
    assert(!dah2_guest_gpu_read_physical(PHYS_BASE-4, preview, 4));
    assert(!dah2_guest_gpu_read_physical(PHYS_BASE+RING_SIZE-4, preview, 8));
    /* Initialization prefix must precede the post-init diagnostic PUT. */
    reset();
    ring_memory[0] = packet(1, 0x300); ring_memory[1] = 0x111;
    dah2_guest_gpu_note_pb_base(DEVICE, CPU_BASE + 0xA90);
    commit(8);
    assert(method_count == 1 && parameters[0] == 0x111);
    assert(g_bridge.pb_start == PHYS_BASE && g_bridge.pb_end == PHYS_BASE + RING_SIZE);
    assert(MEM32(DEVICE + 0x200) == 7);
    /* Changing the reservation threshold must not reattach/replay the ring. */
    MEM32(DEVICE + 4) = CPU_BASE + 0x1FDFC;
    ring_memory[2] = packet(1, 0x304); ring_memory[3] = 0x222;
    commit(16);
    assert(method_count == 2 && parameters[1] == 0x222 && !g_bridge.malformed);

    /* Explicit retail rollover: execute tail JMP and then the new prefix. */
    reset(); attach();
    g_bridge.cursor = PHYS_BASE + 0x1000;
    ring_memory[0x1000 / 4] = PHYS_BASE | 1;
    ring_memory[0] = packet(1, 0x300); ring_memory[1] = 0x333;
    commit(8);
    assert(method_count == 1 && parameters[0] == 0x333 && !g_bridge.malformed);

    /* Old jump is a different packet form and preserves its 29-bit target. */
    reset();
    ring_memory[0] = 0x20000000u | (PHYS_BASE + 0x40);
    ring_memory[0x40 / 4] = packet(1, 0x300); ring_memory[0x44 / 4] = 0x444;
    commit(0x48);
    assert(method_count == 1 && parameters[0] == 0x444 && !g_bridge.malformed);

    /* CALL executes the subroutine, RET resumes the caller exactly once. */
    reset();
    ring_memory[0] = (PHYS_BASE + 0x40) | 2;
    ring_memory[1] = packet(1, 0x304); ring_memory[2] = 0x666;
    ring_memory[0x40 / 4] = packet(1, 0x300); ring_memory[0x44 / 4] = 0x555;
    ring_memory[0x48 / 4] = DAH2_PB_RETURN;
    commit(12);
    assert(method_count == 2 && parameters[0] == 0x555 && parameters[1] == 0x666);
    assert(!g_bridge.return_active && !g_bridge.malformed);

    reset();
    ring_memory[0] = (PHYS_BASE + 0x40) | 2;
    ring_memory[0x40 / 4] = (PHYS_BASE + 0x80) | 2;
    commit(4);
    assert(method_count == 0 && g_bridge.malformed == 1 && g_bridge.return_active);
    assert(g_bridge.return_cursor == PHYS_BASE + 4 && g_bridge.cursor == PHYS_BASE + 0x40);
    assert(MEM32(DEVICE + 0x200) == 3);

    reset(); ring_memory[0] = DAH2_PB_RETURN; commit(4);
    assert(method_count == 0 && g_bridge.malformed == 1 && g_bridge.cursor == PHYS_BASE);

    /* A high invalid target must not be masked back into this allocation. */
    reset(); ring_memory[0] = 0x90000000u | PHYS_BASE | 1; commit(4);
    assert(g_bridge.malformed == 1 && g_bridge.cursor == PHYS_BASE);

    /* Reaching the allocation bound does not invent a rollover jump. */
    reset(); attach(); g_bridge.cursor = PHYS_BASE + RING_SIZE;
    ring_memory[0] = packet(1, 0x300); ring_memory[1] = 0x777;
    commit(8);
    assert(method_count == 0 && g_bridge.malformed == 1 && g_bridge.cursor == PHYS_BASE + RING_SIZE);

    /* Partial publication must not issue and then replay half a packet. */
    reset(); ring_memory[0] = packet(2, 0x300); ring_memory[1] = 0x888; ring_memory[2] = 0x999;
    commit(8);
    assert(method_count == 0 && g_bridge.cursor == PHYS_BASE && MEM32(DEVICE + 0x200) == 3);
    commit(12);
    assert(method_count == 2 && parameters[0] == 0x888 && parameters[1] == 0x999);
    assert(methods[0] == 0x300 && methods[1] == 0x304);

    /* Zero-count packets are valid; non-incrementing methods keep address. */
    reset(); ring_memory[0] = 0; ring_memory[1] = 0x40000000u | packet(2, 0x300);
    ring_memory[2] = 0xAAA; ring_memory[3] = 0xBBB; commit(16);
    assert(method_count == 2 && methods[0] == 0x300 && methods[1] == 0x300 && !g_bridge.malformed);

    reset(); ring_memory[0] = 0xE0030003u; commit(4);
    assert(!method_count && g_bridge.malformed == 1 && g_bridge.cursor == PHYS_BASE);

    /* A loop is bounded by consumed words, with no fabricated completion. */
    reset(); ring_memory[0] = PHYS_BASE | 1; commit(4);
    assert(!method_count && g_bridge.malformed == 1 && g_bridge.words == RING_SIZE / 4 + 32);
    assert(MEM32(DEVICE + 0x200) == 3);

    /* A zero allocation from failed initialization is not a ring. */
    reset(); MEM32(DEVICE + 0x24) = 0; commit(4);
    assert(!g_bridge.commits && !method_count);
    puts("PASS: actual C parser bounds, init prefix, reservation changes, old/new JMP, CALL/RET, no implicit wrap, atomic packets, budget and completion");
    return 0;
}
'''


def main():
    out = ROOT / "diagnostics/guest_pushbuffer_test"
    out.mkdir(exist_ok=True)
    suffix = SUFFIX
    retail_path = ROOT / "diagnostics/codex_parity_20260925/retail_boot_checkpoints02.json"
    if retail_path.exists():
        retail = json.loads(retail_path.read_text(encoding="utf-8"))
        cases = []
        expected = {"device_post_init": 452, "first_swap": 620}
        for checkpoint in retail["checkpoints"]:
            if checkpoint["name"] not in expected:
                continue
            record = checkpoint["push_buffer_prefix"]
            data = bytes.fromhex(record["hex"])
            put = int(checkpoint["device_head"]["u32_le"][0], 16) - int(record["address"], 16)
            values = ",".join(f"0x{int.from_bytes(data[i:i+4], 'little'):08x}u" for i in range(0, len(data), 4))
            cases.append("{ static const uint32_t retail[] = {" + values + "};\n"
                         "reset(); memcpy(ring_memory, retail, sizeof(retail));\n"
                         f"commit(0x{put:x}); assert(method_count == {expected[checkpoint['name']]} && !g_bridge.malformed); }}\n")
        # Raise only the recording capacity; decoder behavior is unchanged.
        prefix = PREFIX.replace("[256]", "[1024]").replace("method_count < 256", "method_count < 1024")
        suffix = suffix.replace('    puts("PASS:', "\n".join(cases) + '    puts("PASS:')
    else:
        prefix = PREFIX
    (out / "test.c").write_text(prefix + DEFINITIONS + BOUNDS + PARSER + suffix, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /W4 /TC test.c /Fe:test.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True)
    subprocess.run([str(out / "test.exe")], cwd=out, check=True)


if __name__ == "__main__":
    main()
