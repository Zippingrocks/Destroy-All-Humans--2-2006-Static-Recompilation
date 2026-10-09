#ifndef NV2A_DRAW_VERTEX_CACHE_H
#define NV2A_DRAW_VERTEX_CACHE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* One synchronous indexed draw only. Shader state, packing state and source
 * arrays must remain unchanged until the draw has finished expanding. The
 * cache maps source indices to the first successfully packed output position;
 * it never owns vertex bytes and must not survive a draw boundary.
 */
typedef struct NV2ADrawVertexCache {
    uint32_t first, span;
    uint32_t *positions; /* output position + 1; zero means unseen */
    uint32_t hits, misses;
} NV2ADrawVertexCache;

static void nv2a_draw_vertex_cache_init(NV2ADrawVertexCache *cache,
    const uint32_t *indices, uint32_t count) {
    uint32_t first=UINT32_MAX, last=0;
    memset(cache,0,sizeof(*cache));
    if(!indices || count<64u) return;
    for(uint32_t i=0;i<count;i++) {
        if(indices[i]<first) first=indices[i];
        if(indices[i]>last) last=indices[i];
    }
    uint64_t span=(uint64_t)last-first+1u;
    /* Same conservative eligibility as DAH1. Sparse/full-width indices keep
     * the uncached path, and allocation failure is only a performance fallback.
     */
    if(span>4096u || (uint64_t)count<=span+16u) return;
    cache->positions=(uint32_t *)calloc((size_t)span,sizeof(*cache->positions));
    if(!cache->positions) return;
    cache->first=first;cache->span=(uint32_t)span;
}

static int nv2a_draw_vertex_cache_find(NV2ADrawVertexCache *cache,
    uint32_t index, uint32_t *position) {
    uint32_t relative=index-cache->first;
    if(!cache->positions || relative>=cache->span || !position) return 0;
    uint32_t stored=cache->positions[relative];
    if(!stored) { cache->misses++;return 0; }
    *position=stored-1u;cache->hits++;return 1;
}

/* Call only after the complete output vertex has been packed successfully. */
static void nv2a_draw_vertex_cache_store(NV2ADrawVertexCache *cache,
    uint32_t index, uint32_t position) {
    uint32_t relative=index-cache->first;
    if(cache->positions && relative<cache->span && position<UINT32_MAX &&
       !cache->positions[relative]) cache->positions[relative]=position+1u;
}

static void nv2a_draw_vertex_cache_destroy(NV2ADrawVertexCache *cache) {
    free(cache->positions);memset(cache,0,sizeof(*cache));
}

#endif
