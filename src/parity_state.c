#include "parity_state.h"

#include "nv2a_pgraph_d3d11.h"
#include "recomp/recomp_types.h"

#include <string.h>
#include <windows.h>

volatile uint64_t g_dah2_parity_state_latest;
/* Retain the optional discovery symbol even with linker dead-data removal. */
__declspec(dllexport) const uint32_t g_dah2_parity_state_sample_size =
    (uint32_t)sizeof(Dah2ParityStateSample);
typedef char Dah2ParityStateSampleSizeV2[sizeof(Dah2ParityStateSample)==560u ? 1 : -1];
typedef char Dah2ParityProfileSize[sizeof(PgraphD3D11FrameProfiles)==160u ? 1 : -1];
Dah2ParityStateSample g_dah2_parity_state_ring[DAH2_PARITY_STATE_CAPACITY];

static INIT_ONCE state_once = INIT_ONCE_STATIC_INIT;
static int state_enabled;
static PgraphD3D11DrawSurfaceProbe state_surface_probe[4];
static uint32_t state_surface_probe_present;

static BOOL CALLBACK state_initialize(PINIT_ONCE once, PVOID parameter,
                                      PVOID *context)
{
    char flag[8];
    DWORD length;
    (void)once; (void)parameter; (void)context;
    length = GetEnvironmentVariableA("DAH2_PARITY_STATE_MEMORY", flag,
                                     sizeof(flag));
    state_enabled = length == 1 && flag[0] == '1';
    /* Timing-only samples avoid the per-method history and full shader
     * snapshots implied by DAH2_PARITY_STATE_MEMORY. */
    if (!state_enabled) {
        length = GetEnvironmentVariableA("DAH2_PARITY_TIMING_MEMORY", flag,
                                         sizeof(flag));
        state_enabled = length == 1 && flag[0] == '1';
    }

    return TRUE;
}

static uint32_t state_word(uint32_t address)
{
    uint32_t value = 0;
    __try {
        value = *(volatile uint32_t *)((uintptr_t)g_xbox_mem_offset + address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
    }
    return value;
}

void dah2_parity_state_present(uint64_t present_ordinal)
{
    Dah2ParityStateSample *sample;
    uint32_t movie;
    unsigned i;
    PgraphD3D11Stats stats;
    PgraphD3D11FrameMethods methods;
    PgraphD3D11FrameProfiles profiles;
    PgraphD3D11RecentDraw draws[4];
    InitOnceExecuteOnce(&state_once, state_initialize, NULL, NULL);
    if (!state_enabled) return;

    sample = &g_dah2_parity_state_ring[
        (unsigned)((present_ordinal - 1u) % DAH2_PARITY_STATE_CAPACITY)];
    sample->sequence = 0;
    sample->wall_ms = GetTickCount64();
    sample->title_state = state_word(0x31D9BCu);
    sample->title_count = state_word(0x31D9D0u);
    sample->title_field_b8 = state_word(0x31DA74u);
    sample->title_field_c0 = state_word(0x31DA7Cu);
    sample->title_field_cc = state_word(0x31DA88u);
    movie = state_word(0x31DA8Cu);
    sample->movie = movie;
    sample->title_field_d4 = state_word(0x31DA90u);
    sample->gate = (int16_t)(state_word(0x2EC0B8u) & 0xFFFFu);
    for (i = 0; i < 6; ++i)
        sample->movie_header[i] = movie && movie != UINT32_MAX
            ? state_word(movie + i * 4u) : 0;
    pgraph_d3d11_get_stats(&stats);
    pgraph_d3d11_get_last_frame_methods(&methods);
    pgraph_d3d11_get_last_frame_profiles(&profiles);
    pgraph_d3d11_get_recent_draws(draws);
    memcpy(sample->gpu_stats, &stats, sizeof(stats));
    memcpy(sample->frame_methods, &methods, sizeof(methods));
    memcpy(sample->frame_profiles, &profiles, sizeof(profiles));
    memcpy(sample->recent_draws, draws, sizeof(draws));
    if (!state_surface_probe_present &&
        pgraph_d3d11_get_draw_surface_probe(state_surface_probe)) {
        state_surface_probe_present = (uint32_t)present_ordinal;
    }
    sample->surface_probe_present = state_surface_probe_present;
    memcpy(sample->surface_probe, state_surface_probe,
           sizeof(state_surface_probe));
    MemoryBarrier();
    sample->sequence = present_ordinal;
    g_dah2_parity_state_latest = present_ordinal;
}