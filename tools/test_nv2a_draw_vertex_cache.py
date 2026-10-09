"""Verify a per-draw index cache against actual DAH2 scene shaders and packing.

This compiles the existing CPU vertex interpreter and extracts the current scene
packer verbatim. Recorded shaders/constants are paired with deterministic test
vertices; fixture vertices are never fed into a game process. Every expanded
output byte, stop position and failure status must match the uncached path.
"""

from __future__ import annotations

import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NV2A = ROOT / "xboxrecomp/src/nv2a"
CAPTURE = ROOT / "diagnostics/codex_parity_20260925/recomp_runs/run713/pgraph_full_overlay_20261008.json"


def array_words(values: list[int]) -> str:
    return ",".join(f"0x{value:08X}u" for value in values)


def main() -> None:
    captured = json.loads(CAPTURE.read_text(encoding="utf-8"))
    fixtures = []
    seen = set()
    for draw in captured["draws"]:
        t = draw["telemetry"]
        if t["profile"] < 6 or t["reason"] or t["count"] < 100:
            continue
        key = (t["texture"], t["count"])
        if key in seen:
            continue
        seen.add(key)
        fixtures.append(draw)
    assert fixtures
    declarations = []
    for n, draw in enumerate(fixtures):
        words = [int(v, 16) for v in draw["program"]]
        constants = [struct.unpack("<I", struct.pack("<f", v))[0] for v in draw["constants"]]
        declarations.append(
            f"static const uint32_t program{n}[544]={{{array_words(words)}}};\n"
            f"static const uint32_t constants{n}[768]={{{array_words(constants)}}};"
        )
    rows = []
    for n, draw in enumerate(fixtures):
        regs = [int(v, 16) for v in draw["registers"]]
        rows.append(
            f"{{program{n},constants{n},{regs[0x1EA0//4]}u,"
            f"0x{regs[0x394//4]:08X}u,{draw['telemetry']['count']}u}}"
        )
    renderer = (NV2A / "nv2a_indexed_draw.h").read_text(encoding="utf-8")
    vertex_type = re.search(
        r"typedef struct \{\s*float x,y,z,rhw;uint32_t diffuse,specular;"
        r"float u0,v0,u1,v1;\s*\} PgraphSceneVertex;", renderer
    )
    assert vertex_type
    pack_start = renderer.index("static int pgraph_pack_scene_vertex(")
    pack_end = renderer.index("static int pgraph_pack_vertex(", pack_start)
    packer = renderer[pack_start:pack_end]
    # Actual register constant, to avoid hard-coding the clip register in tests.
    regs_header = (NV2A / "nv2a_regs.h").read_text(encoding="utf-8")
    clip = re.search(r"#\s*define\s+NV097_SET_CLIP_MAX\s+(0x[0-9A-Fa-f]+)", regs_header)
    assert clip
    clip_index = int(clip.group(1), 16) // 4
    rows = []
    for n, draw in enumerate(fixtures):
        regs = [int(v, 16) for v in draw["registers"]]
        rows.append(
            f"{{program{n},constants{n},{regs[0x1EA0//4]}u,"
            f"0x{regs[clip_index]:08X}u,{draw['telemetry']['count']}u}}"
        )
    test = r'''
#include "nv2a_vertex_program.h"
#include "nv2a_draw_vertex_cache.h"
#include <math.h>
#include <stdio.h>
#include <time.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(3);}}while(0)
static uint32_t clip_bits;
#define NV097_SET_CLIP_MAX 0
#define PG_REG(method) clip_bits
static float u2f(uint32_t b){float f;memcpy(&f,&b,4);return f;}
VERTEX_TYPE
PACKER
typedef struct Fixture {const uint32_t *p,*c;unsigned start;uint32_t clip,count;} Fixture;
DECLARATIONS
static const Fixture fixtures[]={ROWS};
static unsigned transformed,cached_hits;
static void inputs(uint32_t index,unsigned phase,float a[16][4]) {
    memset(a,0,sizeof(float)*64);
    for(unsigned i=0;i<16;i++)a[i][3]=1;
    a[0][0]=(float)((int)(index%31)-15)/8.0f;
    a[0][1]=(float)((int)(index%17)-8)/8.0f;
    a[0][2]=(float)((int)(index%13)-6)/8.0f;
    a[1][0]=0.25f;a[1][1]=0.5f;a[1][2]=0.75f;
    a[2][0]=0.6f;a[2][1]=0.3f;a[2][2]=0.1f;a[2][3]=0;
    for(unsigned c=0;c<4;c++)a[3][c]=(float)((index+c+phase)%8)/255.0f;
    a[4][0]=(float)(index%9)/8.0f;a[4][1]=(float)(index%7)/6.0f;
    a[0][0]+=(float)phase/16.0f;
}
static int expand(const Fixture *f,const uint32_t *indices,unsigned count,unsigned phase,
    int cached,int fault_position,PgraphSceneVertex *out,unsigned *stopped) {
    NV2ADrawVertexCache cache={0};float constants[192][4];
    memcpy(constants,f->c,sizeof(constants));clip_bits=f->clip;
    /* Changes across draw boundaries exercise invalidation without a global cache. */
    constants[187][0]+=(float)phase/8.0f;
    if(cached)nv2a_draw_vertex_cache_init(&cache,indices,count);
    for(unsigned i=0;i<count;i++) {
        uint32_t previous;
        if(cached && nv2a_draw_vertex_cache_find(&cache,indices[i],&previous)) {
            CHECK(previous<i);out[i]=out[previous];continue;
        }
        /* Only an unseen source index can fail: repeated vertices share the same
         * frozen arrays and state within the synchronous draw. */
        if((int)i==fault_position){*stopped=i;cached_hits+=cache.hits;nv2a_draw_vertex_cache_destroy(&cache);return 1001;}
        float a[16][4];NV2AVertexResult r;inputs(indices[i],phase,a);
        transformed++;
        int status=nv2a_vp_execute_mov(f->p,136,f->start,a,constants,&r);
        if(status!=NV2A_VP_OK){*stopped=i;nv2a_draw_vertex_cache_destroy(&cache);return status;}
        if(!pgraph_pack_scene_vertex(&r,&out[i])){*stopped=i;nv2a_draw_vertex_cache_destroy(&cache);return 1002;}
        if(cached)nv2a_draw_vertex_cache_store(&cache,indices[i],i);
    }
    *stopped=count;cached_hits+=cache.hits;nv2a_draw_vertex_cache_destroy(&cache);return 0;
}
static void boundaries(void) {
    uint32_t index[8192],position;NV2ADrawVertexCache c={0};
    for(unsigned i=0;i<8192;i++)index[i]=UINT32_MAX-7u+(i%8u);
    nv2a_draw_vertex_cache_init(&c,index,8192);CHECK(c.span==8);
    CHECK(!nv2a_draw_vertex_cache_find(&c,index[0],&position));
    nv2a_draw_vertex_cache_store(&c,index[0],0);
    CHECK(nv2a_draw_vertex_cache_find(&c,index[8],&position)&&position==0);
    CHECK(!nv2a_draw_vertex_cache_find(&c,0,&position));
    nv2a_draw_vertex_cache_store(&c,index[0],999);
    CHECK(nv2a_draw_vertex_cache_find(&c,index[0],&position)&&position==0);
    nv2a_draw_vertex_cache_destroy(&c);
    nv2a_draw_vertex_cache_init(&c,index,8192);
    CHECK(!nv2a_draw_vertex_cache_find(&c,index[0],&position));
    nv2a_draw_vertex_cache_destroy(&c);
    index[0]=0;index[1]=UINT32_MAX;
    nv2a_draw_vertex_cache_init(&c,index,8192);CHECK(!c.positions);nv2a_draw_vertex_cache_destroy(&c);
    for(unsigned i=0;i<8192;i++)index[i]=i%4096u;
    nv2a_draw_vertex_cache_init(&c,index,8192);CHECK(c.span==4096);nv2a_draw_vertex_cache_destroy(&c);
    index[8191]=4096;
    nv2a_draw_vertex_cache_init(&c,index,8192);CHECK(!c.positions);nv2a_draw_vertex_cache_destroy(&c);
    nv2a_draw_vertex_cache_init(&c,index,63);CHECK(!c.positions);nv2a_draw_vertex_cache_destroy(&c);
}
int main(void) {
    boundaries();
    unsigned cases=0,total_full=0,total_cached=0;
    for(unsigned f=0;f<sizeof(fixtures)/sizeof(fixtures[0]);f++) {
        unsigned count=fixtures[f].count;
        uint32_t *indices=malloc(count*sizeof(*indices));
        PgraphSceneVertex *a=malloc(count*sizeof(*a)),*b=malloc(count*sizeof(*b));
        CHECK(indices&&a&&b);
        /* Degenerate connectors/repeated strip indices and nonzero origins. */
        for(unsigned i=0;i<count;i++)indices[i]=1000u+((i/3u)%31u);
        for(unsigned phase=0;phase<4;phase++)for(unsigned fault=0;fault<2;fault++) {
            unsigned sa,sb;int fault_at=fault?30:-1;
            memset(a,0xCD,count*sizeof(*a));memset(b,0xCD,count*sizeof(*b));
            unsigned before=transformed;
            int ra=expand(&fixtures[f],indices,count,phase,0,fault_at,a,&sa);
            total_full+=transformed-before;before=transformed;
            int rb=expand(&fixtures[f],indices,count,phase,1,fault_at,b,&sb);
            total_cached+=transformed-before;
            CHECK(ra==rb && sa==sb);
            CHECK(!memcmp(a,b,sa*sizeof(*a)));
            if(!fault){CHECK(ra==0);CHECK(transformed-before<=31u);}
            cases++;
        }
        free(indices);free(a);free(b);
    }
    CHECK(total_cached<total_full);
    printf("PASS: %u draw cases; exact expanded bytes, statuses and stop positions\n",cases);
    printf("Vertex executions: uncached=%u cached=%u avoided=%u hits=%u\n",
        total_full,total_cached,total_full-total_cached,cached_hits);
    return 0;
}
'''
    for key, value in {
        "VERTEX_TYPE": vertex_type.group(0),
        "PACKER": packer,
        "DECLARATIONS": "\n".join(declarations),
        "ROWS": ",".join(rows),
    }.items():
        test = test.replace(key, value)
    output_root = ROOT / "diagnostics/nv2a_draw_vertex_cache_test"
    output_root.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run_", dir=output_root))
    (output / "test.c").write_text(test, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = (
        f'call "{vcvars}" >nul && cl /nologo /O2 /TC /I"{NV2A}" '
        f'test.c "{NV2A / "nv2a_vertex_program.c"}" /Fe:test.exe'
    )
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=output, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    result = subprocess.run([str(output / "test.exe")], capture_output=True,
                            text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    print(result.stdout, end="")
    if result.returncode:
        print(result.stderr, end="")
    result.check_returncode()
    print(f"Fixtures: {len(fixtures)} captured scene draws; artifacts: {output}")


if __name__ == "__main__":
    main()
