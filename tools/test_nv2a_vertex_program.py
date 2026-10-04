"""Compile the actual bounded NV2A vertex decoder; no game/window required.

The four-instruction fixture is the selected shader captured at the first two
DAH2 run7 draws, not the earlier default SDK shader. Synthetic vertices test
decoder correctness only; they are never substituted into game rendering.
"""
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "xboxrecomp/src/nv2a"
fixture = [0,0x0020001B,0x0836106C,0x2070F800,
           0,0x0020021B,0x0836106C,0x2070F848,
           0,0x0020041B,0x0836106C,0x2070F818,
           0,0x00376000,0x0C36106C,0x2070F829]
capture = ROOT / "diagnostics/codex_parity_20260925/recomp_runs/run7/stderr.log"
if capture.exists():
    draws = []
    for line in capture.read_text(errors="replace").splitlines():
        if line.startswith("[PARITY-GPU] "):
            record = json.loads(line.split(" ", 1)[1])
            assert [int(v, 16) for v in record["program"][:16]] == fixture
            assert int(record["registers"][0x1EA0//4],16) == 0
            assert [int(v, 16) for v in record["constants"][187*4:188*4]] == [0x3F800000]*4
            draws.append(record)
    assert len(draws) == 2
    print("PASS: actual run7 selected program and c187 match both captured draws")

test = r'''
#include "nv2a_vertex_program.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(3); } } while(0)
static const uint32_t retail[16]={FIXTURE};
static unsigned cases;
static void enc(uint32_t *w,unsigned mux,unsigned index,unsigned swizzle,unsigned neg,
                unsigned temp,unsigned tmask,unsigned out,unsigned omask,unsigned final) {
    w[0]=0;
    w[1]=(1u<<21)|(swizzle&255)|(neg<<8)|(mux==2 ? index<<9 : mux==3 ? index<<13 : 0);
    w[2]=(mux<<26)|(mux==1 ? index<<28 : 0);
    w[3]=(tmask<<24)|(temp<<20)|(omask<<12)|(1<<11)|(out<<3)|final;
}
static void unchanged_error(const uint32_t *p,NV2AVPStatus wanted) {
    float a[16][4]={{0}},c[192][4]={{0}};
    NV2AVertexResult r,before;
    memset(&r,0xCD,sizeof(r));before=r;
    CHECK(nv2a_vp_execute_mov(p,4,0,a,c,&r)==wanted);
    CHECK(memcmp(&r,&before,sizeof(r))==0);
    ++cases;
}
int main(void) {
    unsigned length,bad;
    NV2AVPInstruction d;
    CHECK(nv2a_vp_validate_mov(retail,4,0,&length,&bad)==NV2A_VP_OK && length==4);
    const unsigned attrs[]={0,1,2,0},outputs[]={0,9,3,5};
    for(unsigned n=0;n<4;n++) {
        nv2a_vp_decode_instruction(retail+n*4,&d);
        CHECK(d.mac==1 && d.ilu==0 && d.attribute==attrs[n]);
        CHECK(d.source[0].mux==(n==3 ? 3 : 2));
        CHECK(d.constant==(n==3 ? 187 : 0));
        CHECK(d.output_mask==15 && d.output_address==outputs[n] && d.output_is_register);
        CHECK(!d.mac_mask && !d.ilu_mask && !d.output_is_ilu && !d.relative && d.final==(n==3));
        for(unsigned c=0;c<4;c++)CHECK(d.source[0].swizzle[c]==(n==3 ? 0 : c));
    }
    for(unsigned n=0;n<1024;n++) {
        float a[16][4]={{0}},c[192][4]={{0}};
        uint32_t bytes[7];NV2AVertexResult r;
        float vertex[6]={(float)(n%641),(float)(n%481),0,1,(float)(n%641)/640,(float)(n%481)/480};
        memcpy(bytes,vertex,sizeof(vertex));bytes[6]=n*2654435761u;
        CHECK(nv2a_vp_decode_attribute(0x1C42,bytes,16,a[0])==NV2A_VP_OK);
        CHECK(nv2a_vp_decode_attribute(0x1C22,bytes+4,8,a[1])==NV2A_VP_OK);
        CHECK(nv2a_vp_decode_attribute(0x1C40,bytes+6,4,a[2])==NV2A_VP_OK);
        CHECK(a[1][2]==0 && a[1][3]==1);
        CHECK(a[2][0]==((bytes[6]>>16)&255)/255.0f);
        CHECK(a[2][1]==((bytes[6]>>8)&255)/255.0f);
        CHECK(a[2][2]==(bytes[6]&255)/255.0f && a[2][3]==(bytes[6]>>24)/255.0f);
        c[187][0]=1;c[187][1]=2;c[187][2]=3;c[187][3]=4;
        CHECK(nv2a_vp_execute_mov(retail,4,0,a,c,&r)==NV2A_VP_OK);
        CHECK(!memcmp(r.output[0],a[0],16) && !memcmp(r.output[9],a[1],16) && !memcmp(r.output[3],a[2],16));
        for(unsigned j=0;j<4;j++)CHECK(r.output[5][j]==1);
        for(unsigned o=0;o<13;o++)CHECK(r.written_mask[o]==((o==0||o==3||o==5||o==9)?15:0));
        ++cases;
    }
    /* Every swizzle, mask and sign; temp R12 really aliases oPos. */
    for(unsigned sw=0;sw<256;sw++)for(unsigned mask=0;mask<16;mask++)for(unsigned neg=0;neg<2;neg++) {
        uint32_t p[12];float a[16][4]={{1,2,3,4}},c[192][4]={{0}};
        NV2AVertexResult r;
        enc(p,2,0,0x1B,0,12,15,0,0,0);
        enc(p+4,1,12,sw,neg,0,0,0,mask,0);
        enc(p+8,1,12,0x1B,0,0,0,3,15,1);
        CHECK(nv2a_vp_execute_mov(p,3,0,a,c,&r)==NV2A_VP_OK);
        for(unsigned j=0;j<4;j++) {
            float value=(mask&(8>>j)) ? a[0][(sw>>(6-j*2))&3]*(neg?-1:1) : a[0][j];
            CHECK(r.output[0][j]==value && r.output[3][j]==value);
        }
        ++cases;
    }
    /* Source constants must use the full eight-bit raw index, not clamp to0. */
    for(unsigned index=0;index<192;index++) {
        uint32_t p[4];float a[16][4]={{0}},c[192][4]={{0}};NV2AVertexResult r;
        for(unsigned j=0;j<4;j++)c[index][j]=(float)(index*4+j+1);
        enc(p,3,index,0x1B,0,0,0,9,15,1);
        CHECK(nv2a_vp_execute_mov(p,1,0,a,c,&r)==NV2A_VP_OK);
        CHECK(!memcmp(r.output[9],c[index],16));++cases;
    }
    uint32_t p[24];memset(p,0xFF,sizeof(p));memcpy(p+4,retail,sizeof(retail));
    CHECK(nv2a_vp_validate_mov(p,6,1,&length,&bad)==NV2A_VP_OK && length==4);
    CHECK(nv2a_vp_validate_mov(p,137,1,&length,&bad)==NV2A_VP_INVALID_ARGUMENT);
    CHECK(nv2a_vp_validate_mov(p,6,6,&length,&bad)==NV2A_VP_INVALID_ARGUMENT);
    for(unsigned mutation=0;mutation<12;mutation++) {
        memcpy(p,retail,sizeof(retail));NV2AVPStatus want=NV2A_VP_UNSUPPORTED_OPCODE;
        switch(mutation) {
        case 0:p[0]=1;break;
        case 1:p[1]=(p[1]&~(15<<21))|(2<<21);break;
        case 2:p[1]|=1<<25;break;
        case 3:p[3]|=2;break;
        case 4:p[2]&=~(3<<26);want=NV2A_VP_INVALID_SOURCE;break;
        case 5:enc(p,1,13,0x1B,0,0,0,0,15,0);want=NV2A_VP_INVALID_SOURCE;break;
        case 6:enc(p,3,192,0x1B,0,0,0,0,15,0);want=NV2A_VP_INVALID_SOURCE;break;
        case 7:p[3]&=~(1<<11);want=NV2A_VP_INVALID_DESTINATION;break;
        case 8:p[3]|=4;want=NV2A_VP_INVALID_DESTINATION;break;
        case 9:enc(p,2,0,0x1B,0,0,0,2,15,0);want=NV2A_VP_INVALID_DESTINATION;break;
        case 10:enc(p,2,0,0x1B,0,13,15,0,0,0);want=NV2A_VP_INVALID_DESTINATION;break;
        case 11:p[15]&=~1u;want=NV2A_VP_MISSING_FINAL;break;
        }
        unchanged_error(p,want);
    }
    for(unsigned type=0;type<16;type++)for(unsigned count=0;count<16;count++)for(unsigned bytes=0;bytes<=16;bytes++) {
        unsigned char data[16]={0};float value[4]={7,8,9,10},before[4];memcpy(before,value,16);
        unsigned valid=count>=1 && count<=4 && (type==2 || (type==0 && count==4));
        NV2AVPStatus want=!valid ? NV2A_VP_UNSUPPORTED_FORMAT : bytes<(type==2 ? count*4 : 4) ? NV2A_VP_INVALID_ARGUMENT : NV2A_VP_OK;
        CHECK(nv2a_vp_decode_attribute((count<<4)|type,data,bytes,value)==want);
        if(want!=NV2A_VP_OK)CHECK(!memcmp(before,value,16));
        ++cases;
    }
    printf("PASS: %u native MOV/attribute/mask/bounds/fail-closed cases\n",cases);
    return 0;
}
'''.replace("FIXTURE", ",".join(f"0x{v:08X}u" for v in fixture))

out_root = ROOT / "diagnostics/nv2a_vertex_test"
out_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="run_", dir=out_root))
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
(out / "test.c").write_text(test, encoding="utf-8")
actual = (DIRECTORY / "nv2a_vertex_program.c").read_text(encoding="utf-8")
old = actual.replace('d->mac = field(w[1],21,15); d->ilu = field(w[1],25,7);',
                     'd->mac = field(w[0],21,15); d->ilu = field(w[0],25,7);')
assert old != actual
for name, source, success in [("actual",actual,True),("wrong_opcode_word",old,False)]:
    (out / f"{name}.c").write_text(source, encoding="utf-8")
    command = f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{DIRECTORY}" test.c {name}.c /Fe:{name}.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=out, check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    result = subprocess.run([str(out / f"{name}.exe")], capture_output=True,text=True,timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if success:
        if result.returncode: print(result.stderr)
        result.check_returncode();print(result.stdout,end="")
    else:
        assert result.returncode == 3,result
        print("PASS: historical wrong-DWORD opcode decoder rejected")
print(f"Artifacts: {out}")
