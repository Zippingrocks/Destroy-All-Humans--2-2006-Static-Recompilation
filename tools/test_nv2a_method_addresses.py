"""Compile actual PGRAPH method dispatch with a mock D3D device; no UI/GPU.

Literal hardware addresses deliberately avoid sharing a mistaken define with
the implementation. See nv2a_regs.h (xemu) and the captured retail stream.
"""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "xboxrecomp/src/nv2a/nv2a_pgraph_d3d11.c"
HARNESS = r'''
#include "nv2a/nv2a_pgraph_d3d11.c"
#include <assert.h>
static unsigned clear_calls;
static DWORD clear_flags, clear_color;
static HRESULT STDMETHODCALLTYPE mock_clear(IDirect3DDevice8 *d, DWORD n,
    const D3DRECT *r, DWORD f, D3DCOLOR c, float z, DWORD s) {
    assert(d && n == 0 && !r && z == 1.0f && s == 0);
    clear_calls++; clear_flags=f; clear_color=c; return 0;
}
static IDirect3DDevice8Vtbl vt;
static IDirect3DDevice8 dev;
IDirect3DDevice8 *xbox_GetD3DDevice(void) { return &dev; }
UINT d3d8_GetBackbufferWidth(void) { return 640; }
UINT d3d8_GetBackbufferHeight(void) { return 480; }
static unsigned reads;
static int mock_read(uint32_t address, void *output, uint32_t size) {
    assert(address==0x073C1000 && size==128);
    reads++;
    for(unsigned i=0;i<32;i++) ((uint32_t *)output)[i]=0xFEED0000+i;
    return 1;
}
int main(int argc, char **argv) {
    (void)argv;
    SetEnvironmentVariableA("DAH2_PARITY_GPU", argc>1 ? "1" : NULL);
    vt.Clear=mock_clear; dev.lpVtbl=&vt;
    pgraph_d3d11_init();
    assert(pgraph_d3d11_method(0,0x1D90,0x12345678));
    assert(pgraph_d3d11_method(0,0x1D98,0x027F0000));
    assert(pgraph_d3d11_method(0,0x1D9C,0x01DF0000));
    assert(g_pg.clear_color==0x12345678 && g_pg.clear_rect_h==0x027F0000);
    assert(g_pg.clear_rect_v==0x01DF0000);
    for (unsigned i=0;i<8;i++) {
        unsigned bits=(i&1 ? 0xF0:0)|(i&2 ? 1:0)|(i&4 ? 2:0);
        assert(pgraph_d3d11_method(0,0x1D94,bits));
        assert(clear_flags==i && clear_color==0x12345678);
    }
    assert(clear_calls==8 && g_pg.stats.clears==8);
    pgraph_d3d11_method(0,0x01D0,0xF3);
    pgraph_d3d11_method(0,0x01D4,0xDEADBEEF);
    assert(clear_calls==8 && g_pg.clear_color==0x12345678);
    assert(pgraph_d3d11_method(0,0x030C,1) && g_pg.depth_test==1);
    pgraph_d3d11_method(0,0x0354,0); /* depth function, not enable */
    assert(g_pg.depth_test==1);
    assert(pgraph_d3d11_method(0,0x0308,1) && g_pg.cull_enable==1);
    pgraph_d3d11_method(0,0x039C,0); /* front face, not enable */
    assert(g_pg.cull_enable==1);
    for(unsigned stage=0;stage<4;stage++) {
        assert(pgraph_d3d11_method(0,0x1B0C+stage*0x40,0x40000000));
        pgraph_d3d11_method(0,0x1B08+stage*0x40,0x00010303);
        assert(g_pg.tex[stage].enabled && g_pg.tex[stage].control0==0x40000000);
        assert(pgraph_d3d11_method(0,0x1B0C+stage*0x40,0));
        assert(!g_pg.tex[stage].enabled);
    }
    assert(NV097_SET_SHADE_MODE==0x037C);
    pgraph_d3d11_set_guest_reader(mock_read);
    pgraph_d3d11_method(0,0x1720,0x073C1000);
    pgraph_d3d11_method(0,0x1760,0x1C42);
    pgraph_d3d11_method(0,0x1E9C,1);
    pgraph_d3d11_method(0,0x0B00,0xABCD1234);
    pgraph_d3d11_method(0,0x0B04,0xABCD5678);
    pgraph_d3d11_method(0,0x1EA4,191);
    pgraph_d3d11_method(0,0x0B80,0x3F800000);
    pgraph_d3d11_method(0,0x1E9C,0x40000000); /* no wrap to word zero */
    pgraph_d3d11_method(0,0x0B00,0xDEADBEEF);
    for(unsigned draw=0;draw<5;draw++) {
        pgraph_d3d11_method(0,0x17FC,6);
        pgraph_d3d11_method(0,0x1800,0x00010000);
        pgraph_d3d11_method(0,0x17FC,0);
    }
    assert(reads==(argc>1 ? 2u : 0u));
    puts("PASS: actual literal-address dispatch, clear flags/color, all texture stages, depth/cull enables, old aliases rejected");
    return 0;
}
'''
out = ROOT / "diagnostics/nv2a_method_test"
out.mkdir(exist_ok=True)
run = Path(tempfile.mkdtemp(prefix="run_", dir=out))
(run / "method_test.c").write_text(HARNESS, encoding="utf-8")
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
include = ROOT / "xboxrecomp/src"
vertex_program = ROOT / "xboxrecomp/src/nv2a/nv2a_vertex_program.c"
command = (f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{include}" '
           f'method_test.c "{vertex_program}" /Fe:method_test.exe')
compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=run,
                          capture_output=True, text=True,
                          creationflags=subprocess.CREATE_NO_WINDOW)
if compiled.returncode:
    print(compiled.stdout + compiled.stderr)
compiled.check_returncode()
result = subprocess.run([str(run / "method_test.exe")], cwd=run,
                        capture_output=True, text=True, timeout=20,
                        creationflags=subprocess.CREATE_NO_WINDOW)
print(result.stdout, end="")
if result.returncode:
    print(result.stderr)
result.check_returncode()
assert "[PARITY-GPU]" not in result.stderr
capture = subprocess.run([str(run / "method_test.exe"), "capture"], cwd=run,
                         capture_output=True, text=True, timeout=20,
                         creationflags=subprocess.CREATE_NO_WINDOW)
capture.check_returncode()
events = [json.loads(line[len("[PARITY-GPU] "):]) for line in capture.stderr.splitlines()
          if line.startswith("[PARITY-GPU] ")]
assert len(events) == 2
for ordinal, event in enumerate(events, 1):
    assert event["draw"] == ordinal and event["timing_perturbed"]
    assert event["program"][0] == "0x00000000"
    assert event["program"][4:6] == ["0xabcd1234", "0xabcd5678"]
    assert event["constants"][764] == "0x3f800000"
    assert event["registers"][0x1760//4] == "0x00001c42"
    previews = event["vertex_previews"]
    assert previews[0]["first_128_bytes"] == [f"0x{0xFEED0000+i:08x}" for i in range(32)]
    assert all(item["first_128_bytes"] is None for item in previews[1:])
assert capture.stderr.count("[PARITY-GPU-INDEX]") == 2
print("PASS: bounded GPU capture, exact upload ordering, safe load limits, memory callback and disabled no-read path")
print(f"Artifacts: {run}")
