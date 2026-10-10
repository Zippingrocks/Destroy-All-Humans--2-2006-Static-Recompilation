"""Compare immutable decoded-program execution with the unchanged interpreter.

Uses fourteen real scene shader/constant captures, exceptional input values,
invalid-program statuses and complete debug-error metadata. Also tests the
independent draw-state memory gate. Native timing is informational only.
"""
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NV2A = ROOT / "xboxrecomp/src/nv2a"
CAPTURE = ROOT / "diagnostics/codex_parity_20260925/recomp_runs/run713/pgraph_full_overlay_20261008.json"


def words(values):
    return ",".join(f"0x{value:08X}u" for value in values)


def main():
    captures = json.loads(CAPTURE.read_text(encoding="utf-8"))
    fixtures = []
    seen = set()
    for draw in captures["draws"]:
        t = draw["telemetry"]
        key = (t["texture"], t["count"])
        if t["profile"] >= 6 and not t["reason"] and t["count"] >= 100 and key not in seen:
            fixtures.append(draw)
            seen.add(key)
    assert len(fixtures) == 14
    declarations, rows = [], []
    for n, draw in enumerate(fixtures):
        p = [int(v, 16) for v in draw["program"]]
        c = [struct.unpack("<I", struct.pack("<f", v))[0] for v in draw["constants"]]
        declarations.append(f"static const uint32_t p{n}[544]={{{words(p)}}};")
        declarations.append(f"static const uint32_t c{n}[768]={{{words(c)}}};")
        regs = [int(v, 16) for v in draw["registers"]]
        rows.append(f"{{p{n},c{n},{regs[0x1EA0//4]}u,0x{regs[0x398//4]:08X}u}}")
    renderer = (NV2A / "nv2a_indexed_draw.h").read_text(encoding="utf-8")
    vertex_type = re.search(r"typedef struct \{\s*float x,y,z,rhw;uint32_t diffuse,specular;"
                            r"float u0,v0,u1,v1,u2,v2,u3,v3;\s*\} PgraphSceneVertex;", renderer)
    assert vertex_type
    pack_start = renderer.index("static int pgraph_pack_scene_vertex(")
    pack_end = renderer.index("static int pgraph_pack_vertex(", pack_start)
    state_source = (NV2A / "nv2a_pgraph_d3d11.c").read_text(encoding="utf-8")
    gate_start = state_source.index("static int pgraph_draw_state_enabled(void)")
    gate_end = state_source.index("static uint32_t pgraph_method_hist_limit", gate_start)
    gate = state_source[gate_start:gate_end]
    gates = "\n".join(gate.replace("pgraph_draw_state_enabled", f"gate{n}") for n in range(8))
    code = r'''
#include "nv2a_vertex_program.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(3);}}while(0)
typedef uint32_t DWORD;
static const char *gate_value;static unsigned gate_reads;static int history_enabled;
static DWORD GetEnvironmentVariableA(const char *name,char *out,DWORD size) {
 CHECK(!strcmp(name,"DAH2_DRAW_STATE_MEMORY"));gate_reads++;
 unsigned length=(unsigned)strlen(gate_value);
 if(length<size){memcpy(out,gate_value,length);out[length]=0;}
 return length>=size?length+1:length;
}
static int pgraph_method_hist_enabled(void){return history_enabled;}
GATES
static uint32_t clip_bits;
#define NV097_SET_CLIP_MAX 0
#define PG_REG(method) clip_bits
static float u2f(uint32_t b){float f;memcpy(&f,&b,4);return f;}
VERTEX_TYPE
static float g_pg_stage_scale[4][2]={{1,1},{1,1},{1,1},{1,1}};
static float pgraph_fog_factor(float coord){(void)coord;return 1.0f;}
PACKER
typedef struct Fixture {const uint32_t *p,*c;unsigned start;uint32_t clip;} Fixture;
DECLARATIONS
static const Fixture fixtures[]={ROWS};
static const uint32_t mov4[16]={0,0x0020001B,0x0836106C,0x2070F800,
 0,0x0020021B,0x0836106C,0x2070F848,0,0x0020041B,0x0836106C,0x2070F818,
 0,0x00376000,0x0C36106C,0x2070F829};
static const uint32_t exceptional[]={0x00000000,0x80000000,0x7F800000,0xFF800000,
 0x7FC12345,0x7F812345,0x00000001,0x80000001,0x3F800000,0xBF800000};
static unsigned cases;static volatile uint32_t sink;
static void inputs(unsigned n,float a[16][4]) {
 memset(a,0,64*sizeof(float));for(unsigned i=0;i<16;i++)a[i][3]=1;
 a[0][0]=(float)((int)(n%31)-15)/8;a[0][1]=(float)((int)(n%17)-8)/8;
 a[0][2]=u2f(exceptional[n%10]);a[1][0]=0.25f;a[1][1]=0.5f;a[1][2]=0.75f;
 a[2][0]=0.6f;a[2][1]=0.3f;a[2][2]=0.1f;a[2][3]=0;
 for(unsigned c=0;c<4;c++)a[3][c]=(float)((n+c)%8)/255;
 a[4][0]=(float)(n%9)/8;a[4][1]=(float)(n%7)/6;
}
static void errors(int value,int state[5]) {
 if(value){
  nv2a_vp_last_error_slot=91;nv2a_vp_last_error_source=92;
  nv2a_vp_last_error_constant=93;nv2a_vp_last_error_a0=94;nv2a_vp_last_error_index=95;
 } else {
  state[0]=nv2a_vp_last_error_slot;state[1]=nv2a_vp_last_error_source;
  state[2]=nv2a_vp_last_error_constant;state[3]=nv2a_vp_last_error_a0;state[4]=nv2a_vp_last_error_index;
 }
}
static void same(const uint32_t *p,unsigned slots,unsigned start,
 const NV2AVPPreparedProgram *prepared,const float a[16][4],const float c[192][4]) {
 NV2AVertexResult old,newer;memset(&old,0xCD,sizeof(old));memset(&newer,0xCD,sizeof(newer));
 int e1[5],e2[5];errors(1,NULL);
 int r1=nv2a_vp_execute_mov(p,slots,start,a,c,&old);errors(0,e1);errors(1,NULL);
 int r2=nv2a_vp_execute_prepared(prepared,a,c,&newer);errors(0,e2);
 CHECK(r1==r2&&!memcmp(&old,&newer,sizeof(old))&&!memcmp(e1,e2,sizeof(e1)));
 if(r1==NV2A_VP_OK) {
  PgraphSceneVertex v1,v2;memset(&v1,0xCD,sizeof(v1));memset(&v2,0xCD,sizeof(v2));
  int pack1=pgraph_pack_scene_vertex(&old,&v1),pack2=pgraph_pack_scene_vertex(&newer,&v2);
  CHECK(pack1==pack2&&!memcmp(&v1,&v2,sizeof(v1)));
 }
 cases++;
}
static void captured(void) {
 for(unsigned f=0;f<14;f++) {
  NV2AVPPreparedProgram prepared;unsigned length,bad1,bad2;
  float c[192][4];memcpy(c,fixtures[f].c,sizeof(c));clip_bits=fixtures[f].clip;
  CHECK(nv2a_vp_validate_mov(fixtures[f].p,136,fixtures[f].start,&length,&bad1)==NV2A_VP_OK);
  CHECK(nv2a_vp_prepare_mov(fixtures[f].p,136,fixtures[f].start,&prepared,&bad2)==NV2A_VP_OK);
  CHECK(prepared.length==length&&bad1==bad2);
  for(unsigned n=0;n<1024;n++){float a[16][4];inputs(n,a);same(fixtures[f].p,136,fixtures[f].start,&prepared,a,c);}
 }
}
static void invalid_and_snapshot(void) {
 uint32_t p[24];float a[16][4],c[192][4]={{0}};NV2AVPPreparedProgram prepared;
 inputs(8,a);for(unsigned i=0;i<4;i++)c[187][i]=1;clip_bits=0x4B7FFFFF;
 for(unsigned mutation=0;mutation<12;mutation++) {
  memset(p,0,sizeof(p));memcpy(p,mov4,sizeof(mov4));unsigned slots=4,start=0,length,bad1,bad2;
  switch(mutation) {
  case 0:p[0]=1;break;
  case 1:p[1]=(p[1]&~(15u<<21))|(14u<<21);break;
  case 2:p[1]=(p[1]&~(15u<<21))|(8u<<21);break;
  case 3:p[3]=(p[3]&~(255u<<3))|(13u<<3);break;
  case 4:p[2]&=~(3u<<26);break;
  case 5:p[15]&=~1u;break;
  case 6:slots=0;break;
  case 7:slots=137;break;
  case 8:start=4;break;
  case 9:p[3]|=4;break;
  case 10:p[3]&=~(1u<<11);break;
  case 11:memmove(p+4,p,16*sizeof(uint32_t));slots=5;start=1;break;
  }
  int r1=nv2a_vp_validate_mov(p,slots,start,&length,&bad1);
  int r2=nv2a_vp_prepare_mov(p,slots,start,&prepared,&bad2);
  CHECK(r1==r2&&length==prepared.length&&bad1==bad2);
  same(p,slots,start,&prepared,a,c);
 }
 memcpy(p,mov4,sizeof(mov4));CHECK(nv2a_vp_prepare_mov(p,4,0,&prepared,NULL)==NV2A_VP_OK);
 NV2AVertexResult before,after;CHECK(nv2a_vp_execute_prepared(&prepared,a,c,&before)==NV2A_VP_OK);
 p[0]=1;CHECK(nv2a_vp_execute_prepared(&prepared,a,c,&after)==NV2A_VP_OK);
 CHECK(!memcmp(&before,&after,sizeof(before)));cases++;
 same(NULL,4,0,NULL,a,c);
 uint32_t relative[8]={0,(13u<<21)|0x1Bu,2u<<26,0,
  0,(1u<<21)|(10u<<13)|0x1Bu,3u<<26,(15u<<12)|(1u<<11)|(9u<<3)|3u};
 CHECK(nv2a_vp_prepare_mov(relative,2,0,&prepared,NULL)==NV2A_VP_OK);
 a[0][0]=200;same(relative,2,0,&prepared,a,c);
 CHECK(nv2a_vp_last_error_slot==1&&nv2a_vp_last_error_source==0&&
       nv2a_vp_last_error_constant==10&&nv2a_vp_last_error_a0==200&&nv2a_vp_last_error_index==210);
 a[0][0]=-200;same(relative,2,0,&prepared,a,c);
 CHECK(nv2a_vp_last_error_index==-190);
 errors(1,NULL);CHECK(nv2a_vp_execute_prepared(&prepared,NULL,c,&after)==NV2A_VP_INVALID_ARGUMENT);
 CHECK(nv2a_vp_last_error_slot==91&&nv2a_vp_last_error_source==92);cases++;
}
static void gate_test(void) {
 const char *value[]={"","0","1","10","yes","11","true","123456789"};
 int (*gate[])(void)={gate0,gate1,gate2,gate3,gate4,gate5,gate6,gate7};
 for(unsigned i=0;i<8;i++) {
  gate_value=value[i];history_enabled=0;gate_reads=0;int expected=i==2;
  CHECK(gate[i]()==expected&&gate_reads==1);
  gate_value=expected?"0":"1";CHECK(gate[i]()==expected&&gate_reads==1);
  history_enabled=1;CHECK(gate[i]()==1&&gate_reads==1);
  history_enabled=0;CHECK(gate[i]()==expected&&gate_reads==1);cases++;
 }
}
static void benchmark(void) {
 const Fixture *f=&fixtures[2];float a[16][4],c[192][4];NV2AVertexResult r;NV2AVPPreparedProgram prepared;
 inputs(8,a);memcpy(c,f->c,sizeof(c));CHECK(nv2a_vp_prepare_mov(f->p,136,f->start,&prepared,NULL)==NV2A_VP_OK);
 clock_t begin=clock();
 for(unsigned n=0;n<20000;n++){CHECK(nv2a_vp_execute_mov(f->p,136,f->start,a,c,&r)==NV2A_VP_OK);uint32_t bits;memcpy(&bits,&r.output[0][0],4);sink^=bits;}
 clock_t middle=clock();
 for(unsigned n=0;n<20000;n++){CHECK(nv2a_vp_execute_prepared(&prepared,a,c,&r)==NV2A_VP_OK);uint32_t bits;memcpy(&bits,&r.output[0][0],4);sink^=bits;}
 clock_t end=clock();
 printf("Native20k shader executions: baseline=%.1fms prepared=%.1fms (informational CPU timing)\n",
  1000.0*(middle-begin)/CLOCKS_PER_SEC,1000.0*(end-middle)/CLOCKS_PER_SEC);
}
int main(void) {
 captured();invalid_and_snapshot();gate_test();benchmark();
 printf("PASS: %u prepared/gate cases; bitwise VM+packed outputs, validation statuses, error metadata, immutable words and draw-state OR/caching\n",cases);
 return 0;
}
'''
    substitutions = {
        "GATES": gates,
        "VERTEX_TYPE": vertex_type.group(0),
        "PACKER": renderer[pack_start:pack_end],
        "DECLARATIONS": "\n".join(declarations),
        "ROWS": ",".join(rows),
    }
    for key, value in substitutions.items():
        code = re.sub(r"\b" + key + r"\b", lambda _match: value, code)
    output_root = ROOT / "diagnostics/nv2a_prepared_program_test"
    output_root.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run_", dir=output_root))
    (output / "test.c").write_text(code, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /O2 /fp:precise /TC /I"{NV2A}" test.c "{NV2A / "nv2a_vertex_program.c"}" /Fe:test.exe'
    compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=output,
                              capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    result = subprocess.run([str(output / "test.exe")], capture_output=True, text=True,
                            timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    print(result.stdout, end="")
    if result.returncode:
        print(result.stderr, end="")
    result.check_returncode()
    print(f"Artifacts: {output}")


if __name__ == "__main__":
    main()
