#ifndef DAH2_PARITY_STATE_H
#define DAH2_PARITY_STATE_H

#include <stdint.h>

#define DAH2_PARITY_STATE_CAPACITY 4096u

typedef struct Dah2ParityStateSample {
    volatile uint64_t sequence;
    uint64_t wall_ms;
    uint32_t title_state;
    uint32_t title_count;
    uint32_t title_field_b8;
    uint32_t title_field_c0;
    uint32_t title_field_cc;
    uint32_t movie;
    uint32_t title_field_d4;
    int32_t gate;
    uint32_t movie_header[6];
    uint32_t gpu_stats[8];
    uint32_t frame_methods[20];
    uint32_t recent_draws[4][9];
    uint32_t surface_probe_present;
    uint32_t surface_probe[4][4];
    /* v2 appends accepted/rejected/accepted_inline/clipped, ten profiles each. */
    uint32_t frame_profiles[40];
} Dah2ParityStateSample;

/* Exported through the linker map for external ReadProcessMemory snapshots.
 * A slot is complete only when sequence is nonzero and stable across a read. */
extern volatile uint64_t g_dah2_parity_state_latest;
extern __declspec(dllexport) const uint32_t g_dah2_parity_state_sample_size;
extern Dah2ParityStateSample
    g_dah2_parity_state_ring[DAH2_PARITY_STATE_CAPACITY];

/* Read-only semantic state sampled after a native present. Enabled only by
 * DAH2_PARITY_STATE_MEMORY=1 or DAH2_PARITY_TIMING_MEMORY=1; no file/console I/O. */
void dah2_parity_state_present(uint64_t present_ordinal);

#endif