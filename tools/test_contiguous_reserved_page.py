"""Exercise the actual bridge allocator against XAPI's fixed first-page arena."""
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / 'xboxrecomp/src/kernel/kernel_bridge.c').read_text(encoding='utf-8')
body = source[source.index('#define XBOX_PHYSICAL_MIRROR_BASE'):source.index('static void bridge_MmAllocateContiguousMemoryEx')]
out = root / 'diagnostics/contiguous_reserved_test'
out.mkdir(exist_ok=True)
prefix = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define XBOX_CONTIG_SIZE 0x100000u
static unsigned char memory[XBOX_CONTIG_SIZE];
static ptrdiff_t g_xbox_mem_offset;
'''
suffix = r'''
int main(void) {
    g_xbox_mem_offset=(ptrdiff_t)memory-0x80000000u;
    memset(memory,0xAB,sizeof(memory));
    uint32_t first=bridge_alloc_contiguous(512,4096);
    assert(first==0x80001000u);
    uint32_t second=bridge_alloc_contiguous(16,4096);
    assert(second==0x80002000u);
    assert(memory[0]==0xAB && memory[4095]==0xAB);
    assert(memory[4096]==0 && memory[4096+511]==0);
    memset(memory,0xCC,4096); /* Original XAPI small-allocation fill. */
    assert(memory[first-0x80000000u]==0);
    assert(bridge_free_contiguous(first));
    assert(bridge_alloc_contiguous(256,4096)==first);
    assert(bridge_free_contiguous(second));
    assert(bridge_alloc_contiguous(16,4096)==second);
    assert(!bridge_free_contiguous(0x80000000u));
    puts("PASS: fixed XAPI page stays disjoint; zero fill, reuse and tail reclaim remain valid");
}
'''
(out / 'test.c').write_text(prefix+body+suffix)
vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
command = f'call "{vcvars}" >nul && cl /nologo /Od /TC test.c /Fe:test.exe'
subprocess.run('cmd.exe /d /s /c "'+command+'"', cwd=out, check=True)
subprocess.run([str(out / 'test.exe')], cwd=out, check=True)
