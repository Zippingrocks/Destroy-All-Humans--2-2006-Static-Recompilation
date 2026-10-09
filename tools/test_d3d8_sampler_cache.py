"""Native real-source sampler cache equivalence; no game, driver, or GUI."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
states = (ROOT / "xboxrecomp/src/d3d/d3d8_states.c").read_text(encoding="utf-8")
# Exact pre-cache function retained as an independent normalized-TSS reference.
BASELINE = r"""void d3d8_states_apply_sampler(DWORD stage)
{
    const DWORD *tss;
    D3D11_SAMPLER_DESC sd;
    HRESULT hr;
    ID3D11DeviceContext *ctx = d3d8_GetD3D11Context();

    if (stage >= 4) return;
    tss = d3d8_GetTSS(stage);
    if (!tss) return;

    /* Release old sampler */
    if (g_sampler_states[stage]) {
        ID3D11SamplerState_Release(g_sampler_states[stage]);
        g_sampler_states[stage] = NULL;
    }

    memset(&sd, 0, sizeof(sd));
    sd.Filter = d3d8_to_d3d11_filter(
        tss[D3DTSS_MAGFILTER],
        tss[D3DTSS_MINFILTER],
        tss[D3DTSS_MIPFILTER]);
    sd.AddressU = d3d8_to_d3d11_address(tss[D3DTSS_ADDRESSU] ? tss[D3DTSS_ADDRESSU] : D3DTADDRESS_WRAP);
    sd.AddressV = d3d8_to_d3d11_address(tss[D3DTSS_ADDRESSV] ? tss[D3DTSS_ADDRESSV] : D3DTADDRESS_WRAP);
    sd.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
    sd.MaxAnisotropy = tss[D3DTSS_MAXANISOTROPY] ? tss[D3DTSS_MAXANISOTROPY] : 1;
    sd.ComparisonFunc = D3D11_COMPARISON_NEVER;
    sd.MaxLOD = D3D11_FLOAT32_MAX;

    hr = ID3D11Device_CreateSamplerState(d3d8_GetD3D11Device(), &sd, &g_sampler_states[stage]);
    if (SUCCEEDED(hr)) {
        ID3D11DeviceContext_PSSetSamplers(ctx, stage, 1, &g_sampler_states[stage]);
    }
}"""


def function(signature):
    found = re.search(re.escape(signature) + r".*?^\}", states, re.M | re.S)
    assert found, signature
    return found.group()


globals_block = re.search(r"static ID3D11BlendState.*?(?=/\* =)", states, re.S).group()
address = function("static D3D11_TEXTURE_ADDRESS_MODE d3d8_to_d3d11_address(")
filter_code = function("static D3D11_FILTER d3d8_to_d3d11_filter(")
bind = function("static void d3d8_states_bind_sampler(")
apply = function("void d3d8_states_apply_sampler(")
shutdown = function("void d3d8_states_shutdown(")
baseline = BASELINE.replace("void d3d8_states_apply_sampler", "static void baseline_apply_sampler").replace("g_sampler_states", "old_sampler_states")
assert "memcmp(&g_sampler_descs[stage],desc,sizeof(*desc))" in bind
assert "g_sampler_devices[stage]==device" in bind
assert shutdown.count("g_sampler_desc_valid[i]=FALSE;") == 1

source = f'#include "{(ROOT / "xboxrecomp/src/d3d/d3d8_internal.h").as_posix()}"\n' + r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
typedef struct {D3D11_SAMPLER_DESC desc;ID3D11Device *device;unsigned world,refs,alive;} MockSampler;
static MockSampler objects[50000];
static unsigned objects_used,current_world,cases,dedup;
static ID3D11Device *current_device=(ID3D11Device *)(uintptr_t)0x1000;
static DWORD tss[4][64];
static int missing_tss,behavior[2];
static unsigned creates[2],binds[2],owned_releases[2];
static D3D11_SAMPLER_DESC last_created[2];
static ID3D11SamplerState *bound[2][4],*old_sampler_states[4];
static void drop(ID3D11SamplerState *state) {
    if(!state)return;MockSampler *m=(MockSampler *)state;
    CHECK(m->alive && m->refs);if(!--m->refs)m->alive=0;
}
static ULONG mock_release(ID3D11SamplerState *state) {
    MockSampler *m=(MockSampler *)state;CHECK(m->world==current_world);
    owned_releases[current_world]++;drop(state);return m->refs;
}
static HRESULT mock_create(ID3D11Device *device,const D3D11_SAMPLER_DESC *desc,ID3D11SamplerState **out) {
    creates[current_world]++;last_created[current_world]=*desc;*out=NULL;
    if(!device || behavior[current_world]==1)return E_FAIL;
    if(behavior[current_world]==2)return S_OK;
    MockSampler *m=NULL;
    if(dedup)for(unsigned i=0;i<objects_used;i++) {
        MockSampler *candidate=&objects[i];
        if(candidate->alive && candidate->world==current_world &&
           candidate->device==device && !memcmp(&candidate->desc,desc,sizeof(*desc))) {
            m=candidate;break;
        }
    }
    if(m)m->refs++;
    else {CHECK(objects_used<50000);m=&objects[objects_used++];m->desc=*desc;m->device=device;
          m->world=current_world;m->refs=1;m->alive=1;}
    *out=(ID3D11SamplerState *)m;
    return behavior[current_world]==3 ? E_FAIL : behavior[current_world]==4 ? S_FALSE : S_OK;
}
static void mock_bind(ID3D11DeviceContext *ctx,UINT stage,UINT count,ID3D11SamplerState *const *states) {
    CHECK(ctx==(ID3D11DeviceContext *)(uintptr_t)(0x2000+current_world));
    CHECK(stage<4 && count==1);ID3D11SamplerState *next=*states;
    if(next) {MockSampler *m=(MockSampler *)next;CHECK(m->alive && m->world==current_world);m->refs++;}
    drop(bound[current_world][stage]);bound[current_world][stage]=next;binds[current_world]++;
}
#undef ID3D11Device_CreateSamplerState
#undef ID3D11DeviceContext_PSSetSamplers
#undef ID3D11SamplerState_Release
#define ID3D11Device_CreateSamplerState mock_create
#define ID3D11DeviceContext_PSSetSamplers mock_bind
#define ID3D11SamplerState_Release mock_release
ID3D11Device *d3d8_GetD3D11Device(void) {return current_device;}
ID3D11DeviceContext *d3d8_GetD3D11Context(void) {return (ID3D11DeviceContext *)(uintptr_t)(0x2000+current_world);}
const DWORD *d3d8_GetTSS(DWORD stage) {return missing_tss ? NULL : tss[stage];}
""" + globals_block + "\n" + address + "\n" + filter_code + "\n" + bind + "\n" + apply + "\n" + shutdown + "\n" + baseline + r"""
/* Lower-level pre-cache release/create/bind sequence for arbitrary descriptor
 * bit patterns. The actual original TSS constructor above is also tested. */
static void baseline_bind_desc(UINT stage,const D3D11_SAMPLER_DESC *desc) {
    if(stage>=4)return;
    if(old_sampler_states[stage]) {mock_release(old_sampler_states[stage]);old_sampler_states[stage]=NULL;}
    HRESULT hr=mock_create(current_device,desc,&old_sampler_states[stage]);
    if(SUCCEEDED(hr))mock_bind(d3d8_GetD3D11Context(),stage,1,&old_sampler_states[stage]);
}
static void same_bound(void) {
    for(unsigned stage=0;stage<4;stage++) {
        CHECK(!!bound[0][stage]==!!bound[1][stage]);
        if(bound[0][stage]) {
            MockSampler *a=(MockSampler *)bound[0][stage],*b=(MockSampler *)bound[1][stage];
            CHECK(a->alive && b->alive && a->device==b->device && !memcmp(&a->desc,&b->desc,sizeof(a->desc)));
        }
        if(g_sampler_desc_valid[stage]) {
            CHECK(g_sampler_states[stage]);MockSampler *m=(MockSampler *)g_sampler_states[stage];
            CHECK(m->alive && m->refs && g_sampler_devices[stage]==m->device &&
                  !memcmp(&g_sampler_descs[stage],&m->desc,sizeof(m->desc)));
        }
    }
}
static void pair(UINT stage,const D3D11_SAMPLER_DESC *desc) {
    unsigned b0=binds[0],b1=binds[1],c1=creates[1];
    current_world=0;if(desc)baseline_bind_desc(stage,desc);else baseline_apply_sampler(stage);
    current_world=1;if(desc)d3d8_states_bind_sampler(stage,current_device,d3d8_GetD3D11Context(),desc);else d3d8_states_apply_sampler(stage);
    CHECK(binds[0]-b0==binds[1]-b1);
    if(stage<4 && creates[1]!=c1)CHECK(!memcmp(&last_created[0],&last_created[1],sizeof(D3D11_SAMPLER_DESC)));
    same_bound();cases++;
}
static void cleanup(void) {
    current_world=0;
    for(unsigned s=0;s<4;s++)if(old_sampler_states[s]) {mock_release(old_sampler_states[s]);old_sampler_states[s]=NULL;}
    current_world=1;d3d8_states_shutdown();
    for(unsigned s=0;s<4;s++) {
        CHECK(!g_sampler_states[s] && !g_sampler_desc_valid[s] && !g_sampler_devices[s]);
        D3D11_SAMPLER_DESC zero={0};CHECK(!memcmp(&zero,&g_sampler_descs[s],sizeof(zero)));
    }
    unsigned release=owned_releases[1];d3d8_states_shutdown();CHECK(owned_releases[1]==release);
    for(unsigned w=0;w<2;w++)for(unsigned s=0;s<4;s++) {drop(bound[w][s]);bound[w][s]=NULL;}
    for(unsigned i=0;i<objects_used;i++)CHECK(!objects[i].alive && objects[i].refs==0);
}
static D3D11_SAMPLER_DESC descriptor(void) {
    D3D11_SAMPLER_DESC d={0};d.Filter=D3D11_FILTER_MIN_MAG_MIP_POINT;
    d.AddressU=d.AddressV=d.AddressW=D3D11_TEXTURE_ADDRESS_WRAP;
    d.MaxAnisotropy=1;d.ComparisonFunc=D3D11_COMPARISON_NEVER;d.MaxLOD=D3D11_FLOAT32_MAX;return d;
}
static void descriptor_tests(void) {
    D3D11_SAMPLER_DESC base=descriptor();
    for(unsigned s=0;s<4;s++)pair(s,&base);
    unsigned start=creates[1],start_bind=binds[1];
    for(unsigned n=0;n<100;n++)for(unsigned s=0;s<4;s++)pair(s,&base);
    CHECK(creates[1]==start && binds[1]-start_bind==400);
    for(unsigned word=0;word<sizeof(base)/4;word++) {
        D3D11_SAMPLER_DESC changed=base;uint32_t bits;
        memcpy(&bits,(char *)&changed+word*4,4);bits^=1;memcpy((char *)&changed+word*4,&bits,4);
        pair(0,&base);start=creates[1];pair(0,&changed);CHECK(creates[1]==start+1);
        pair(0,&changed);CHECK(creates[1]==start+1);
    }
    const unsigned floats[]={4,7,8,9,10,11,12};
    const uint32_t patterns[]={0,0x80000000u,0x7FC00001u,0x7FC00002u,0x7FA00001u,0x7F800000u,0xFF800000u,1};
    for(unsigned f=0;f<7;f++)for(unsigned p=0;p<8;p++) {
        D3D11_SAMPLER_DESC changed=base;memcpy((char *)&changed+floats[f]*4,&patterns[p],4);
        pair(1,&changed);start=creates[1];pair(1,&changed);CHECK(creates[1]==start);
    }
    start=creates[1];pair(4,&base);pair(UINT32_MAX,&base);CHECK(creates[1]==start);
    cleanup();
}
static void failure_tests(void) {
    D3D11_SAMPLER_DESC d=descriptor();pair(0,&d);
    for(int mode=1;mode<=4;mode++) {
        d.MaxAnisotropy++;behavior[0]=behavior[1]=mode;
        unsigned start=creates[1];pair(0,&d);CHECK(creates[1]==start+1);
        if(mode!=4) {
            CHECK(!g_sampler_desc_valid[0]);pair(0,&d);CHECK(creates[1]==start+2);
        } else {CHECK(g_sampler_desc_valid[0]);pair(0,&d);CHECK(creates[1]==start+1);}
        behavior[0]=behavior[1]=0;pair(0,&d);CHECK(g_sampler_desc_valid[0]);
    }
    unsigned start=creates[1];current_device=(ID3D11Device *)(uintptr_t)0x3000;
    pair(0,&d);CHECK(creates[1]==start+1 && g_sampler_devices[0]==current_device);
    current_device=NULL;pair(0,&d);CHECK(!g_sampler_desc_valid[0]);pair(0,&d);
    current_device=(ID3D11Device *)(uintptr_t)0x1000;pair(0,&d);
    cleanup();pair(0,&d);CHECK(g_sampler_desc_valid[0]);cleanup();
}
static uint32_t random_bits=123456789;
static uint32_t next(void) {random_bits=random_bits*1664525u+1013904223u;return random_bits;}
static void normalized_tests(void) {
    memset(tss,0,sizeof(tss));
    for(unsigned s=0;s<4;s++)pair(s,NULL);
    unsigned start=creates[1];for(unsigned s=0;s<4;s++)pair(s,NULL);CHECK(creates[1]==start);
    /* Explicit wrap/point/aniso defaults normalize to the same bytes. */
    for(unsigned s=0;s<4;s++) {tss[s][D3DTSS_ADDRESSU]=D3DTADDRESS_WRAP;tss[s][D3DTSS_ADDRESSV]=D3DTADDRESS_WRAP;
        tss[s][D3DTSS_MAXANISOTROPY]=1;tss[s][D3DTSS_MAGFILTER]=D3DTEXF_POINT;
        tss[s][D3DTSS_MINFILTER]=D3DTEXF_POINT;tss[s][D3DTSS_MIPFILTER]=D3DTEXF_POINT;pair(s,NULL);}
    CHECK(creates[1]==start);
    for(unsigned i=0;i<2000;i++) {
        unsigned s=next()%4;
        tss[s][D3DTSS_ADDRESSU]=next()%7;tss[s][D3DTSS_ADDRESSV]=next()%7;
        tss[s][D3DTSS_MAGFILTER]=next()%6;tss[s][D3DTSS_MINFILTER]=next()%6;
        tss[s][D3DTSS_MIPFILTER]=next()%6;tss[s][D3DTSS_MAXANISOTROPY]=next()%17;
        tss[s][D3DTSS_BORDERCOLOR]=next();tss[s][D3DTSS_MIPMAPLODBIAS]=next();
        pair(s,NULL);start=creates[1];pair(s,NULL);CHECK(creates[1]==start);
    }
    missing_tss=1;start=creates[1];pair(0,NULL);CHECK(creates[1]==start);missing_tss=0;
    pair(4,NULL);pair(UINT32_MAX,NULL);cleanup();
}
int main(void) {
    CHECK(sizeof(D3D11_SAMPLER_DESC)==52);
    for(dedup=0;dedup<=1;dedup++) {descriptor_tests();failure_tests();normalized_tests();}
    printf("PASS: %u native sampler cases; baseline bindings/descriptors, all52 bytes, NaN/zero bits, stages, device changes, failure retry, shutdown and COM ownership; creates %u -> %u\n",
           cases,creates[0],creates[1]);return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="dah2_sampler_cache_") as temporary:
    directory = Path(temporary)
    (directory / "test.c").write_text(source, encoding="utf-8")
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /W4 /TC /O2 /I"{ROOT / "xboxrecomp/src"}" test.c /Fe:test.exe'
    built = subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=directory,
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if built.returncode:
        raise AssertionError(built.stdout + built.stderr)
    completed = subprocess.run([str(directory / "test.exe")], cwd=directory,
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    print(completed.stdout.strip())
