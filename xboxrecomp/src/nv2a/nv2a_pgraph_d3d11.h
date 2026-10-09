/*
 * NV2A PGRAPH → D3D11 Translator
 *
 * Intercepts NV2A push buffer method calls and translates them into
 * D3D8→D3D11 rendering commands. This is the core of the GPU translation
 * layer for Xbox static recompilation.
 *
 * The push buffer contains NV2A Kelvin (NV097) methods:
 *   - Surface/viewport setup → D3D11 render target + viewport
 *   - Render state (blend, depth, cull) → D3D11 state objects
 *   - Begin/End draw + Inline vertex data → D3D11 DrawPrimitiveUP
 *   - Texture binding → D3D11 shader resource views
 *   - Clear commands → D3D11 ClearRenderTargetView
 *
 * Vertex formats observed in menus:
 *   5 dwords per vertex: float X, float Y, float U, float V, D3DCOLOR
 *   Drawn as TRIANGLE_STRIP (mode 6)
 *
 * This module is designed to be reusable across Xbox recompilation projects.
 * See: https://github.com/sp00nznet/xboxrecomp
 */

#ifndef NV2A_PGRAPH_D3D11_H
#define NV2A_PGRAPH_D3D11_H

#include <stdint.h>

/* Initialize the PGRAPH→D3D11 translator. Call after D3D11 device is created. */
void pgraph_d3d11_init(void);

/* Physical-memory reader supplied by the title bridge. Returning zero denotes
 * an unavailable range; the backend must not dereference host/guest pointers. */
typedef int (*PgraphGuestReader)(uint32_t physical, void *output, uint32_t bytes);
void pgraph_d3d11_set_guest_reader(PgraphGuestReader reader);

/* Shut down and release resources. */
void pgraph_d3d11_shutdown(void);

/* Process an NV2A PGRAPH method call. Called from push buffer parser.
 * Returns 1 if handled, 0 if unhandled (caller should log/ignore). */
int pgraph_d3d11_method(int subchannel, uint32_t method, uint32_t param);

/* Flush any pending draw commands (call at end of frame). */
void pgraph_d3d11_flush(void);

/* Set chyron scroll: pass frame counter to animate, 0 to disable.
 * Applies horizontal scroll offset to vertices in the chyron Y band. */
void pgraph_d3d11_set_chyron_scroll(uint32_t frame);

/* Statistics */
typedef struct {
    uint32_t frames;
    uint32_t draw_calls;
    uint32_t vertices_submitted;
    uint32_t methods_handled;
    uint32_t methods_ignored;
    uint32_t clears;
    uint32_t indexed_draws; /* Successful checked guest-array submissions. */
    uint32_t rejected_draws; /* Unsupported/invalid draws, never synthetic fallback. */
} PgraphD3D11Stats;

void pgraph_d3d11_get_stats(PgraphD3D11Stats *out);

typedef struct {
    uint32_t methods, begins, ends;
    uint32_t begin_modes[11];
    uint32_t element16_words, element32_words;
    uint32_t draw_arrays_words, draw_arrays_vertices;
    uint32_t inline_words, clears;
} PgraphD3D11FrameMethods;

void pgraph_d3d11_get_last_frame_methods(PgraphD3D11FrameMethods *out);

#define PGRAPH_D3D11_PROFILE_COUNT 10u
typedef struct {
    uint32_t accepted[PGRAPH_D3D11_PROFILE_COUNT];
    uint32_t rejected[PGRAPH_D3D11_PROFILE_COUNT];
    uint32_t accepted_inline[PGRAPH_D3D11_PROFILE_COUNT];
    uint32_t clipped[PGRAPH_D3D11_PROFILE_COUNT];
} PgraphD3D11FrameProfiles;

/* Completed-frame checked submissions; zero when state/timing memory is off.
 * Accepted means a nonzero-primitives host draw succeeded, not visible pixels.
 * accepted_inline is a subset for programmable INLINE_ARRAY (source 3). */
void pgraph_d3d11_get_last_frame_profiles(PgraphD3D11FrameProfiles *out);

typedef struct {
    uint32_t kind, profile, count, mode;
    uint32_t target, texture, clip_h, clip_v, combiner;
} PgraphD3D11RecentDraw;

void pgraph_d3d11_get_recent_draws(PgraphD3D11RecentDraw out[4]);

typedef struct {
    uint32_t target, texture;
    uint32_t source_before_nonblack, target_after_nonblack;
} PgraphD3D11DrawSurfaceProbe;

int pgraph_d3d11_get_draw_surface_probe(PgraphD3D11DrawSurfaceProbe out[4]);

#endif /* NV2A_PGRAPH_D3D11_H */
