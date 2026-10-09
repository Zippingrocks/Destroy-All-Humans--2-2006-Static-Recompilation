"""Native completed-frame profile/gate/publication tests; no game process or UI."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

import read_parity_state_ring as reader

ROOT = Path(__file__).resolve().parents[1]
gpu = (ROOT / "xboxrecomp/src/nv2a/nv2a_pgraph_d3d11.c").read_text(encoding="utf-8")
indexed = (ROOT / "xboxrecomp/src/nv2a/nv2a_indexed_draw.h").read_text(encoding="utf-8")
state = (ROOT / "src/parity_state.c").read_text(encoding="utf-8")


def function(text, signature):
    match = re.search(re.escape(signature) + r".*?^\}", text, re.M | re.S)
    assert match, signature
    return match.group()


helpers = re.search(r"static PgraphD3D11FrameProfiles g_pg_frame_profiles;.*?(?=\ntypedef struct \{)",
                    gpu, re.S).group()
getter = function(gpu, "void pgraph_d3d11_get_last_frame_profiles(")
initialize = function(state, "static BOOL CALLBACK state_initialize(")
word = function(state, "static uint32_t state_word(")
present = function(state, "void dah2_parity_state_present(")
size = re.search(r"__declspec\(dllexport\) const uint32_t g_dah2_parity_state_sample_size =.*?;", state, re.S).group()

# Check the actual integration points, not only the isolated helper behavior.
flush = function(gpu, "void pgraph_d3d11_flush(")
assert flush.count("pgraph_profile_frame_end();") == 1
assert flush.index("submit_draw();") < flush.index("g_pg.stats.frames++;") < flush.index("pgraph_profile_frame_end();")
assert indexed.count("pgraph_record_profile_result(profile,g_pg.index_source,primitives,0);") == 1
assert indexed.index("PG_CALL(draw_result);PG_CALL(end_result);") < indexed.index(
    "pgraph_record_profile_result(profile,g_pg.index_source,primitives,0);")
reject = function(indexed, "static void pgraph_reject_draw(")
assert "pgraph_record_profile_result(pgraph_array_profile(),g_pg.index_source,0,1);" in reject
assert present.index("pgraph_d3d11_get_last_frame_profiles(&profiles);") < present.index("MemoryBarrier();")
assert present.index("memcpy(sample->frame_profiles, &profiles, sizeof(profiles));") < present.index("sample->sequence = present_ordinal;")
assert helpers.count("GetEnvironmentVariableA(") == 2

source = r"""
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
""" + f'#include "{(ROOT / "src/parity_state.h").as_posix()}"\n' + f'#include "{(ROOT / "xboxrecomp/src/nv2a/nv2a_pgraph_d3d11.h").as_posix()}"\n' + helpers + "\n" + getter + r"""
static unsigned char guest[0x400000];
static uintptr_t g_xbox_mem_offset;
volatile uint64_t g_dah2_parity_state_latest;
Dah2ParityStateSample g_dah2_parity_state_ring[DAH2_PARITY_STATE_CAPACITY];
static INIT_ONCE state_once = INIT_ONCE_STATIC_INIT;
static int state_enabled;
static PgraphD3D11DrawSurfaceProbe state_surface_probe[4];
static uint32_t state_surface_probe_present;
void pgraph_d3d11_get_stats(PgraphD3D11Stats *out) {
    memset(out,0,sizeof(*out));out->frames=17;out->indexed_draws=23;
}
void pgraph_d3d11_get_last_frame_methods(PgraphD3D11FrameMethods *out) {
    memset(out,0,sizeof(*out));
}
void pgraph_d3d11_get_recent_draws(PgraphD3D11RecentDraw out[4]) {
    memset(out,0,sizeof(*out)*4u);
}
int pgraph_d3d11_get_draw_surface_probe(PgraphD3D11DrawSurfaceProbe out[4]) {
    (void)out;return 0;
}
""" + size + "\n" + initialize + "\n" + word + "\n" + present + r"""
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;} } while(0)
static int empty(const PgraphD3D11FrameProfiles *p) {
    PgraphD3D11FrameProfiles zero={0};return !memcmp(p,&zero,sizeof(zero));
}
int main(int argc,char **argv) {
    CHECK(argc==2);int wanted=atoi(argv[1]);
    CHECK(sizeof(Dah2ParityStateSample)==560 && g_dah2_parity_state_sample_size==560);
    CHECK(sizeof(PgraphD3D11FrameProfiles)==160);
    CHECK(offsetof(Dah2ParityStateSample,frame_profiles)==396);
    CHECK(pgraph_profile_counters_enabled()==wanted);
    PgraphD3D11FrameProfiles out;
    memset(&g_pg_last_frame_profiles,0xA5,sizeof(g_pg_last_frame_profiles));
    pgraph_d3d11_get_last_frame_profiles(&out);
    CHECK(wanted ? !memcmp(&out,&g_pg_last_frame_profiles,sizeof(out)) : empty(&out));
    memset(&g_pg_last_frame_profiles,0,sizeof(g_pg_last_frame_profiles));
    for(unsigned p=0;p<PGRAPH_D3D11_PROFILE_COUNT;p++) {
        pgraph_record_profile_result(p,1,3,0);
        pgraph_record_profile_result(p,3,2,0);
        pgraph_record_profile_result(p,3,0,0);
        pgraph_record_profile_result(p,1,8,1);
    }
    PgraphD3D11FrameProfiles before=g_pg_frame_profiles;
    pgraph_record_profile_result(10,3,1,0);pgraph_record_profile_result(UINT32_MAX,3,1,1);
    CHECK(!memcmp(&before,&g_pg_frame_profiles,sizeof(before)));
    pgraph_d3d11_get_last_frame_profiles(&out);CHECK(empty(&out));
    pgraph_d3d11_get_last_frame_profiles(NULL);
    pgraph_profile_frame_end();
    pgraph_d3d11_get_last_frame_profiles(&out);
    for(unsigned p=0;p<PGRAPH_D3D11_PROFILE_COUNT;p++) {
        CHECK(out.accepted[p]==(wanted ? 2u : 0u));
        CHECK(out.rejected[p]==(wanted ? 1u : 0u));
        CHECK(out.accepted_inline[p]==(wanted ? 1u : 0u));
        CHECK(out.clipped[p]==(wanted ? 1u : 0u));
    }
    CHECK(empty(&g_pg_frame_profiles));
    g_xbox_mem_offset=(uintptr_t)guest;
    *(uint32_t *)(guest+0x31D9BC)=7;
    dah2_parity_state_present(1);
    CHECK(g_dah2_parity_state_latest==(uint64_t)wanted);
    if(wanted) {
        Dah2ParityStateSample *s=&g_dah2_parity_state_ring[0];
        CHECK(s->sequence==1 && s->wall_ms>0 && s->title_state==7);
        CHECK(s->gpu_stats[0]==17 && s->gpu_stats[6]==23);
        CHECK(!memcmp(s->frame_profiles,&out,sizeof(out)));
    }
    PgraphD3D11FrameProfiles saved=out;
    pgraph_d3d11_get_last_frame_profiles(&out);CHECK(!memcmp(&saved,&out,sizeof(out)));
    pgraph_profile_frame_end();pgraph_d3d11_get_last_frame_profiles(&out);CHECK(empty(&out));
    dah2_parity_state_present(2);
    if(wanted) CHECK(!memcmp(g_dah2_parity_state_ring[1].frame_profiles,&out,sizeof(out)));
    pgraph_record_profile_result(6,3,1,0);
    pgraph_d3d11_get_last_frame_profiles(&out);CHECK(empty(&out));
    pgraph_profile_frame_end();pgraph_d3d11_get_last_frame_profiles(&out);
    CHECK(out.accepted[6]==(unsigned)wanted && out.accepted_inline[6]==(unsigned)wanted);
    CHECK(out.accepted[7]==0 && out.rejected[6]==0 && out.clipped[6]==0);
    dah2_parity_state_present(4097);
    if(wanted) {
        CHECK(g_dah2_parity_state_ring[0].sequence==4097 && g_dah2_parity_state_latest==4097);
        CHECK(!memcmp(g_dah2_parity_state_ring[0].frame_profiles,&out,sizeof(out)));
    }
    SetEnvironmentVariableA("DAH2_PARITY_TIMING_MEMORY",wanted ? "0" : "1");
    SetEnvironmentVariableA("DAH2_PARITY_STATE_MEMORY",wanted ? "0" : "1");
    CHECK(pgraph_profile_counters_enabled()==wanted);
    puts("PASS");return 0;
}
"""

flags = ("DAH2_PARITY_TIMING_MEMORY", "DAH2_PARITY_STATE_MEMORY", "DAH2_METHOD_HIST", "DAH2_DRAW_STATE_MEMORY")
cases = [({}, 0), ({flags[0]: "1"}, 1), ({flags[1]: "1"}, 1),
         ({flags[0]: "0", flags[1]: "1"}, 1), ({flags[0]: "1", flags[1]: "0"}, 1),
         ({flags[0]: "1", flags[1]: "1"}, 1), ({flags[2]: "1"}, 0), ({flags[3]: "1"}, 0)]
for flag in flags[:2]:
    for invalid in ("", "0", "01", "11", "true", "123456789"):
        cases.append(({flag: invalid}, 0))
        cases.append(({flag: invalid, flags[1 if flag == flags[0] else 0]: "1"}, 1))

with tempfile.TemporaryDirectory(prefix="dah2_profile_counters_") as temporary:
    directory = Path(temporary)
    (directory / "test.c").write_text(source, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /W4 /TC /O2 /Gy /Gw test.c /Fe:test.exe /link /OPT:REF /MAP:test.map'
    built = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=directory,
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if built.returncode:
        raise AssertionError(built.stdout + built.stderr)
    assert reader.symbol_rva(directory / "test.map", "g_dah2_parity_state_sample_size") >= 0
    for changes, wanted in cases:
        environment = os.environ.copy()
        for flag in flags:
            environment.pop(flag, None)
        environment.update(changes)
        completed = subprocess.run([str(directory / "test.exe"), str(wanted)], cwd=directory,
            env=environment, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert completed.returncode == 0, (changes, wanted, completed.stdout, completed.stderr)
print(f"PASS: {len(cases)} native gate/accepted/rejected/inline/clipped/completed-frame/reset/publication cases; v2=560 and size export retained")
