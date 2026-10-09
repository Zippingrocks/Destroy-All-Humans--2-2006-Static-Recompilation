"""Compile faithful programmable INLINE_ARRAY decoding against the retail fire draw.

Tests use authentic captured inline words and current reader, packer, submission
and overflow code extracted verbatim. They run in an isolated native executable;
no game process receives test vertices or reconstructed geometry.
"""
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NV2A = ROOT / "xboxrecomp/src/nv2a"
CAPTURE = ROOT / "diagnostics/codex_parity_20260925/xemu_runs/run17/fire_sequence_20261008_00_raw_state.json"


def words(values):
    return ",".join(f"0x{value:08X}u" for value in values)


def main():
    decoded = json.loads(CAPTURE.read_text(encoding="utf-8"))
    draw = next(d for frame in decoded["frames"] for d in frame["draws"] if d["inlineWords"] == 28)
    formats = draw["arrayFormats"]
    payload = [c["parameter"] for c in draw["drawCommands"] if c["method"] == 0x1818]
    registers = {int(k): v for k, v in draw["rawRegisters"].items()}
    assert len(payload) == 28 and formats[:3] == [0x42, 0x22, 0x40]
    assert draw["programStart"] == 0 and registers[0x1E94] == 6
    # The previously verified four-MOV program transfers position, UV, color,
    # and the SDK's c187.x fog constant without rebuilding any guest geometry.
    program = [0, 0x0020001B, 0x0836106C, 0x2070F800,
               0, 0x0020021B, 0x0836106C, 0x2070F848,
               0, 0x0020041B, 0x0836106C, 0x2070F818,
               0, 0x00376000, 0x0C36106C, 0x2070F829]
    renderer = (NV2A / "nv2a_indexed_draw.h").read_text(encoding="utf-8")
    state_source = (NV2A / "nv2a_pgraph_d3d11.c").read_text(encoding="utf-8")
    reader_start = renderer.index("static int pgraph_read_vertex(")
    reader_end = renderer.index("typedef struct {", reader_start)
    pack_start = renderer.index("static int pgraph_pack_vertex(")
    pack_end = renderer.index("static void pgraph_movie_vertex_alpha(", pack_start)
    submit_start = state_source.index("static void submit_draw(void)")
    submit_end = state_source.index("int pgraph_d3d11_method(", submit_start)
    bounds_start = state_source.index("    case NV097_INLINE_ARRAY:") + len("    case NV097_INLINE_ARRAY:")
    bounds_end = state_source.index("    /* ── Clear ── */", bounds_start)
    vertex_type = re.search(
        r"typedef struct \{\s*float x, y, z, rhw;\s*uint32_t color;\s*float u, v;\s*\} OutputVertex;",
        state_source
    )
    assert vertex_type
    test = r'''
#include "nv2a_vertex_program.h"
#include "nv2a_inline_array.h"
#include "nv2a_regs.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(3);}}while(0)
#define MAX_INLINE_VERTS 16384
enum {PGRAPH_REJECT_STATE=1,PGRAPH_REJECT_SHADER,PGRAPH_REJECT_MEMORY,
 PGRAPH_REJECT_OUTPUT,PGRAPH_REJECT_DEVICE,PGRAPH_REJECT_LIMIT,PGRAPH_REJECT_TOPOLOGY,PGRAPH_REJECT_INLINE};
VERTEX_TYPE
static struct {
 uint32_t index_source,index_count,inline_count,indices[MAX_INLINE_VERTS],inline_data[64],registers[2048];
 uint32_t program[544];float constants[192][4];
 unsigned draw_error;int in_draw;struct {unsigned frames;} stats;
} g_pg;
static NV2AInlineArrayLayout g_pg_inline_layout;
static NV2AVPPreparedProgram test_prepared;
static volatile uint32_t g_dah2_pgraph_draw_memory_failures[64][11];
static unsigned guest_reads;
static int guest_read(uint32_t address,void *data,size_t bytes){guest_reads++;return 0;}
static int (*g_pg_guest_reader)(uint32_t,void *,size_t)=guest_read;
#define PG_REG(method) g_pg.registers[(method)/4]
static float u2f(uint32_t bits){float value;memcpy(&value,&bits,4);return value;}
READER
PACKER
static unsigned submitted,rejected,last_reason,last_detail,submitted_source,submitted_count;
static void submit_indexed_draw(void){
 submitted++;submitted_source=g_pg.index_source;submitted_count=g_pg.index_count;
 for(unsigned i=0;i<g_pg.index_count;i++)CHECK(g_pg.indices[i]==i);
}
static void pgraph_reject_draw(unsigned reason,uint32_t detail){
 rejected++;last_reason=reason;last_detail=detail;
}
SUBMIT
static int append_inline(uint32_t param) {BOUNDS}
static const uint32_t retail_formats[16]={FORMATS};
static const uint32_t retail_words[28]={PAYLOAD};
static const uint32_t retail_program[16]={PROGRAM};
static unsigned cases;
static void setup(void) {
 memset(&g_pg,0,sizeof(g_pg));guest_reads=0;
 g_pg.inline_count=28;g_pg.index_source=3;
 memcpy(g_pg.inline_data,retail_words,sizeof(retail_words));
 memcpy(g_pg.program,retail_program,sizeof(retail_program));
 CHECK(nv2a_vp_prepare_mov(g_pg.program,136,0,&test_prepared,NULL)==NV2A_VP_OK);
 for(unsigned c=0;c<4;c++)g_pg.constants[187][c]=1;
 for(unsigned a=0;a<16;a++)g_pg.registers[(NV097_SET_VERTEX_DATA_ARRAY_FORMAT+a*4)/4]=retail_formats[a];
 g_pg.registers[NV097_SET_TRANSFORM_EXECUTION_MODE/4]=6;
 g_pg.registers[NV097_SET_CLIP_MAX/4]=CLIP;
 unsigned bad;CHECK(nv2a_inline_array_layout(retail_formats,&g_pg_inline_layout,&bad)==NV2A_VP_OK);
}
static void fixture(void) {
 setup();uint32_t count=99;unsigned bad;
 CHECK(g_pg_inline_layout.enabled_mask==7u&&g_pg_inline_layout.stride_bytes==28);
 CHECK(g_pg_inline_layout.offsets[0]==0&&g_pg_inline_layout.offsets[1]==16&&g_pg_inline_layout.offsets[2]==24);
 CHECK(nv2a_inline_array_count(&g_pg_inline_layout,28,16384,&count)==NV2A_VP_OK&&count==4);
 for(unsigned i=0;i<count;i++) {
  float input[16][4];NV2AVertexResult result,direct;OutputVertex output;
  CHECK(nv2a_inline_array_read(&g_pg_inline_layout,retail_words,28,i,input,&bad)==NV2A_VP_OK);
  CHECK(nv2a_vp_execute_mov(g_pg.program,136,0,input,g_pg.constants,&direct)==NV2A_VP_OK);
  CHECK(pgraph_read_vertex(i,7,&result,0,&test_prepared));CHECK(!memcmp(&result,&direct,sizeof(result)));
  CHECK(!memcmp(result.output[0],retail_words+i*7,16));
  CHECK(result.output[9][0]==u2f(retail_words[i*7+4])&&result.output[9][1]==u2f(retail_words[i*7+5]));
  CHECK(result.output[9][2]==0&&result.output[9][3]==1);
  uint32_t argb=retail_words[i*7+6];
  CHECK(result.output[3][0]==((argb>>16)&255)/255.0f);
  CHECK(result.output[3][1]==((argb>>8)&255)/255.0f);
  CHECK(result.output[3][2]==(argb&255)/255.0f&&result.output[3][3]==(argb>>24)/255.0f);
  CHECK(pgraph_pack_vertex(&result,&output,640,480,1));
  CHECK(output.x==u2f(retail_words[i*7])&&output.y==u2f(retail_words[i*7+1]));
  CHECK(output.z==u2f(retail_words[i*7+2])/u2f(CLIP));
  CHECK(output.rhw==1.0f/u2f(retail_words[i*7+3])&&output.color==argb);
  CHECK(output.u==u2f(retail_words[i*7+4])&&output.v==u2f(retail_words[i*7+5]));
  g_pg.index_source=1;CHECK(!pgraph_pack_vertex(&result,&output,640,480,1));g_pg.index_source=3;
  ++cases;
 }
 CHECK(guest_reads==0);
 NV2AVertexResult result,before;memset(&result,0xCD,sizeof(result));before=result;
 CHECK(!pgraph_read_vertex(4,7,&result,0,&test_prepared)&&!memcmp(&result,&before,sizeof(result)));
 CHECK(!pgraph_read_vertex(0,15,&result,0,&test_prepared)&&!memcmp(&result,&before,sizeof(result)));
 ++cases;
}
static void alignment(void) {
 uint32_t formats[16]={0},data[5]={0};NV2AInlineArrayLayout layout;unsigned bad;
 formats[0]=0xAB12;formats[2]=0xFF31;formats[7]=0xDD40;formats[9]=0xCC12;
 CHECK(nv2a_inline_array_layout(formats,&layout,&bad)==NV2A_VP_OK);
 CHECK(layout.offsets[0]==0&&layout.offsets[2]==4&&layout.offsets[7]==10&&layout.offsets[9]==16);
 CHECK(layout.stride_bytes==20);
 float first=2.5f,last=5.125f;int16_t signed_values[3]={-32768,0,32767};uint32_t argb=0x12345678;
 memcpy(data,&first,4);memcpy((unsigned char *)data+4,signed_values,6);
 memcpy((unsigned char *)data+10,&argb,4);memcpy((unsigned char *)data+16,&last,4);
 float input[16][4];
 CHECK(nv2a_inline_array_read(&layout,data,5,0,input,&bad)==NV2A_VP_OK);
 CHECK(input[0][0]==first&&input[0][3]==1&&input[9][0]==last);
 CHECK(input[2][0]==-1&&input[2][1]==0&&input[2][2]==1&&input[2][3]==1);
 CHECK(input[7][0]==0x34/255.0f&&input[7][1]==0x56/255.0f&&input[7][2]==0x78/255.0f&&input[7][3]==0x12/255.0f);
 CHECK(input[1][0]==0&&input[1][1]==0&&input[1][2]==0&&input[1][3]==1);
 ++cases;
}
static void failures(void) {
 setup();NV2AInlineArrayLayout layout,before;unsigned bad;uint32_t formats[16];
 memcpy(formats,retail_formats,sizeof(formats));memset(&layout,0xCD,sizeof(layout));before=layout;
 formats[3]=0x45;
 CHECK(nv2a_inline_array_layout(formats,&layout,&bad)==NV2A_VP_UNSUPPORTED_FORMAT&&bad==3);
 CHECK(!memcmp(&layout,&before,sizeof(layout)));
 memset(formats,0,sizeof(formats));
 CHECK(nv2a_inline_array_layout(formats,&layout,&bad)==NV2A_VP_INVALID_ARGUMENT);
 uint32_t count=0xDEADBEEF;
 for(unsigned length=0;length<28;length++)if(length%7) {
  CHECK(nv2a_inline_array_count(&g_pg_inline_layout,length,16384,&count)==NV2A_VP_INVALID_ARGUMENT);
  CHECK(count==0xDEADBEEF);++cases;
 }
 CHECK(nv2a_inline_array_count(&g_pg_inline_layout,16384*7u,16384,&count)==NV2A_VP_OK&&count==16384);
 CHECK(nv2a_inline_array_count(&g_pg_inline_layout,16385*7u,16384,&count)==NV2A_VP_INVALID_ARGUMENT);
 float output[16][4],saved[16][4];memset(output,0xCD,sizeof(output));memcpy(saved,output,sizeof(output));
 CHECK(nv2a_inline_array_read(&g_pg_inline_layout,retail_words,28,UINT32_MAX,output,&bad)==NV2A_VP_INVALID_ARGUMENT);
 CHECK(!memcmp(saved,output,sizeof(output)));++cases;
}
static void submission(void) {
 setup();submitted=rejected=0;g_pg.index_source=0;
 submit_draw();CHECK(submitted==1&&rejected==0&&submitted_source==3&&submitted_count==4);
 CHECK(!g_pg.inline_count&&!g_pg.index_count&&!g_pg.index_source);++cases;
 setup();submitted=rejected=0;g_pg.inline_count=27;g_pg.index_source=0;
 submit_draw();CHECK(!submitted&&rejected==1&&last_reason==PGRAPH_REJECT_LIMIT);++cases;
 setup();submitted=rejected=0;g_pg.registers[(NV097_SET_VERTEX_DATA_ARRAY_FORMAT+12)/4]=0x45;
 submit_draw();CHECK(!submitted&&rejected==1&&last_reason==PGRAPH_REJECT_STATE);
 CHECK(last_detail==NV097_SET_VERTEX_DATA_ARRAY_FORMAT+12);++cases;
 setup();submitted=rejected=0;g_pg.registers[NV097_SET_TRANSFORM_EXECUTION_MODE/4]=4;
 submit_draw();CHECK(!submitted&&rejected==1&&last_reason==PGRAPH_REJECT_INLINE);++cases;
 setup();g_pg.in_draw=1;g_pg.inline_count=63;g_pg.index_count=0;
 CHECK(append_inline(0x12345678)==1&&g_pg.inline_count==64&&g_pg.inline_data[63]==0x12345678);
 CHECK(append_inline(0x87654321)==1&&g_pg.inline_count==64&&g_pg.draw_error==PGRAPH_REJECT_LIMIT);++cases;
}
int main(void) {
 fixture();alignment();failures();submission();
 printf("PASS: %u native inline cases; retail28 words ->4 real VM vertices, exact packed XY/Z/RHW/UV/color; bounded layout, shared submission and overflow\n",cases);
 return 0;
}
'''
    substitutions = {
        "VERTEX_TYPE": vertex_type.group(0),
        "READER": renderer[reader_start:reader_end],
        "PACKER": renderer[pack_start:pack_end],
        "SUBMIT": state_source[submit_start:submit_end],
        "BOUNDS": state_source[bounds_start:bounds_end],
        "FORMATS": words(formats),
        "PAYLOAD": words(payload),
        "PROGRAM": words(program),
        "CLIP": f"0x{registers[0x398]:08X}u",
    }
    for key, value in substitutions.items():
        test = re.sub(r"\b" + key + r"\b", lambda _match: value, test)
    output_root = ROOT / "diagnostics/nv2a_inline_array_test"
    output_root.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run_", dir=output_root))
    (output / "test.c").write_text(test, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /O2 /TC /I"{NV2A}" test.c "{NV2A / "nv2a_vertex_program.c"}" /Fe:test.exe'
    compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=output,
                              capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    result = subprocess.run([str(output / "test.exe")], capture_output=True, text=True,
                            timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    print(result.stdout, end="")
    if result.returncode:
        print(result.stderr, end="")
    result.check_returncode()
    print(f"Artifacts: {output}")


if __name__ == "__main__":
    main()
