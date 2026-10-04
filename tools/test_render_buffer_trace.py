"""Compile actual bounded trace header; verify opt-in and guest-state purity."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
out = ROOT/"diagnostics/render_buffer_trace_test"
out.mkdir(exist_ok=True)
header = (ROOT/"src/recomp/render_buffer_trace.h").as_posix()
source = r'''
#include <stdint.h>
#include <string.h>
static unsigned char memory[0x20000], original[0x20000];
static uint32_t registers[8]={1,2,3,0x10000,5,6,7,8};
#define g_esp registers[3]
#define XBOX_PTR(a) ((uintptr_t)(memory+(uint32_t)(a)))
#include "HEADER"
int main(void) {
    uint32_t before[8];
    memset(memory,0,sizeof(memory));
    *(uint32_t *)(memory+0x1668)=1;
    *(uint32_t *)(memory+0x168C)=0x2000;
    *(uint32_t *)(memory+0x1694)=0x3000;
    *(uint32_t *)(memory+0x1698)=0x4000;
    *(uint32_t *)(memory+0x16A0)=0x5000;
    *(uint32_t *)(memory+0x2004)=0x4000;
    *(uint32_t *)(memory+0x3004)=0x5000;
    *(uint32_t *)(memory+0x10000)=0x12345678;
    *(uint32_t *)(memory+0x10004)=0x6000;
    *(uint32_t *)(memory+0x10008)=4;
    for(unsigned i=0;i<112;i++) memory[0x4000+i]=(unsigned char)(i+1);
    memcpy(original,memory,sizeof(memory)); memcpy(before,registers,sizeof(before));
    for(unsigned i=0;i<16;i++) {
        Dah2RenderBufferTrace trace=dah2_render_trace_begin(0x1000,0);
        dah2_render_trace_end(trace,0);
        trace=dah2_render_trace_begin(0x1000,1);
        dah2_render_trace_end(trace,1);
    }
    return memcmp(original,memory,sizeof(memory)) || memcmp(before,registers,sizeof(before));
}
'''.replace("HEADER",header)
(out/"trace.c").write_text(source,encoding="utf-8")
vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
command=f'call "{vcvars}" >nul && cl /nologo /Od /TC trace.c /Fe:trace.exe'
subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True)
for enabled in (False,True):
    environment=dict(os.environ,DAH2_PARITY_GPU="1" if enabled else "0")
    result=subprocess.run([str(out/"trace.exe")],env=environment,capture_output=True,text=True,timeout=10,check=True)
    lines=result.stderr.splitlines()
    assert len(lines)==(32 if enabled else 0),len(lines)
    if enabled:
        records=[json.loads(line.split("] ",1)[1]) for line in lines]
        assert sum(r["stage"]=="170B80.entry" for r in records)==4
        assert sum(r["stage"]=="170C30.entry" for r in records)==12
        sample=next(r for r in records if r["stage"]=="170C30.exit")
        assert sample["written_vertices"][0]=="04030201"
        assert sample["written_vertex_va"]=="00004000"
        assert sample["index_data"]=="00005000"
print("PASS: actual trace header compiles; disabled is silent; enabled is bounded to4 locks/12producers; guest memory/GPR untouched")
