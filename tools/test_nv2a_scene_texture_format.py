"""Compile the actual scene classifier against payload-proven retail headers.

This isolated native test reads saved metadata, not a running game. The dimension
and block-span expressions are also extracted from the actual upload function.
"""
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NV2A = ROOT / "xboxrecomp/src/nv2a"
TABLE = ROOT / "diagnostics/codex_parity_20260925/xemu_runs/run17/fire_texture_parity_20261008.json"


def main():
    rows = json.loads(TABLE.read_text(encoding="utf-8"))["table"]
    assert len(rows) == 16 and all(row["payloadIdentical"] for row in rows)
    source = (NV2A / "nv2a_indexed_draw.h").read_text(encoding="utf-8")
    start = source.index("static int pgraph_dah2_scene_texture_format(")
    end = source.index("static int pgraph_dah2_final_combiner(", start)
    classifier = source[start:end]
    upload = source[source.index("static int pgraph_upload_scene_texture("):]
    decode = upload[upload.index("    uint32_t address="):upload.index("    D3DFORMAT host_format;")]
    spans = upload[upload.index("    unsigned row_bytes="):upload.index("    if((uint64_t)address+size>")]
    fixtures = ",\n".join(
        "{0x%08Xu,0x%08Xu,%uu,%uu,%uu,%uu}" % (
            int(row["retailFormat"], 16), int(row["candidateAlias"], 16),
            row["width"], row["height"], row["length"],
            8 if row["format"] == "DXT1" else 16)
        for row in rows
    )
    native = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nv2a_regs.h"
static uint32_t registers[2048];
#define PG_REG(method) registers[(method)/4]
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(3);}}while(0)
CLASSIFIER
struct bounds {uint32_t address;unsigned width,height,row_bytes,rows,block_bytes;size_t size;};
static struct bounds actual_upload_bounds(unsigned stage) {
DECODE
SPANS
    struct bounds result={address,width,height,row_bytes,rows,block_bytes,size};
    return result;
}
struct fixture {uint32_t format,address;unsigned width,height,size,block_bytes;};
static const struct fixture retail[16]={FIXTURES};
static unsigned cases,old_mask_rejections;
static void setup(unsigned stage,uint32_t format,uint32_t address) {
    memset(registers,0,sizeof(registers));
    PG_REG(NV097_SET_TEXTURE_FORMAT+stage*0x40)=format;
    PG_REG(NV097_SET_TEXTURE_OFFSET+stage*0x40)=address;
    PG_REG(NV097_SET_TEXTURE_CONTROL0+stage*0x40)=0x4003FFC0u;
}
static void reject(unsigned stage,uint32_t format) {
    setup(stage,format,0x86A20800u);
    CHECK(!pgraph_dah2_scene_texture_format(stage));++cases;
}
int main(void) {
    for(unsigned i=0;i<16;i++)for(unsigned stage=0;stage<4;stage++) {
        const struct fixture *r=&retail[i];setup(stage,r->format,r->address);
        CHECK(pgraph_dah2_scene_texture_format(stage));
        struct bounds b=actual_upload_bounds(stage);
        CHECK(b.address==r->address&&b.width==r->width&&b.height==r->height);
        CHECK(b.block_bytes==r->block_bytes&&b.size==r->size);
        CHECK(b.row_bytes==((r->width+3)/4)*r->block_bytes&&b.rows==(r->height+3)/4);
        CHECK(b.width<=2048&&b.height<=2048);
        for(unsigned other=0;other<4;other++)if(other!=stage)
            CHECK(!pgraph_dah2_scene_texture_format(other));
        /* Mutation check: the removed U/V/P=1 mask rejects genuine retail. */
        if((r->format&0xFFF0FFFFu)!=(0x11100029u|(r->format&0xFF00u)))old_mask_rejections++;
        ++cases;
    }
    CHECK(old_mask_rejections==64);
    static const unsigned colors[2]={0x0C,0x0F},mips[4]={1,5,6,7};
    for(unsigned stage=0;stage<4;stage++)for(unsigned c=0;c<2;c++)
    for(unsigned m=0;m<4;m++)for(unsigned u=0;u<=11;u++)for(unsigned v=0;v<=11;v++) {
        uint32_t fmt=0x29u|(colors[c]<<8)|(mips[m]<<16)|(u<<20)|(v<<24);
        setup(stage,fmt,0x86A20800);CHECK(pgraph_dah2_scene_texture_format(stage));
        struct bounds b=actual_upload_bounds(stage);
        CHECK(b.width==(1u<<u)&&b.height==(1u<<v)&&b.width<=2048&&b.height<=2048);
        CHECK(b.size==(size_t)((b.width+3)/4)*((b.height+3)/4)*(c?16u:8u));++cases;
    }
    for(unsigned stage=0;stage<4;stage++) {
        uint32_t valid=0x06650C29u;
        for(unsigned bit=0;bit<16;bit++)reject(stage,valid^(1u<<bit));
        for(unsigned p=1;p<16;p++)reject(stage,valid|(p<<28));
        for(unsigned exp=12;exp<16;exp++) {
            reject(stage,(valid&~0x00F00000u)|(exp<<20));
            reject(stage,(valid&~0x0F000000u)|(exp<<24));
        }
        for(unsigned mip=0;mip<16;mip++)if(mip!=1&&mip!=5&&mip!=6&&mip!=7)
            reject(stage,(valid&~0x000F0000u)|(mip<<16));
        for(unsigned bit=0;bit<32;bit++) {
            setup(stage,valid,0x86A20800u);
            PG_REG(NV097_SET_TEXTURE_CONTROL0+stage*0x40)^=1u<<bit;
            CHECK(!pgraph_dah2_scene_texture_format(stage));++cases;
        }
    }
    printf("PASS: %u native cases; all16 payload-proven retail headers accepted at4 stages; actual dimension/block spans match; old mask rejects64/64; unsupported type, P, mip, control and dimensions rejected\n",cases);
    return 0;
}
'''
    for key, value in {"CLASSIFIER": classifier, "DECODE": decode, "SPANS": spans,
                       "FIXTURES": fixtures}.items():
        native = re.sub(r"\b" + key + r"\b", lambda _match: value, native)
    output_root = ROOT / "diagnostics/nv2a_scene_texture_format_test"
    output_root.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run_", dir=output_root))
    (output / "test.c").write_text(native, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /O2 /TC /I"{NV2A}" test.c /Fe:test.exe'
    compiled = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=output,
                              capture_output=True, text=True,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    result = subprocess.run([str(output / "test.exe")], capture_output=True,
                            text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    print(result.stdout, end="")
    if result.returncode:
        print(result.stderr, end="")
    result.check_returncode()
    print(f"Artifacts: {output}")


if __name__ == "__main__":
    main()