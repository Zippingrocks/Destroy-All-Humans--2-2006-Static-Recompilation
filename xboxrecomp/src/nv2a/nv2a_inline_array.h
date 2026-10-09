#ifndef NV2A_INLINE_ARRAY_H
#define NV2A_INLINE_ARRAY_H

#include "nv2a_vertex_program.h"
#include <limits.h>
#include <string.h>

/* Bounded programmable INLINE_ARRAY input, independent of guest array offsets
 * and their stride fields. xemu GL/Vulkan consume every enabled attribute in
 * ascending order and align it to its element size: F=4, S1=2, UB_D3D=1.
 * The supported formats are exactly the shared attribute decoder's subset.
 */
typedef struct NV2AInlineArrayLayout {
    uint32_t formats[NV2A_VP_ATTRIBUTES];
    uint16_t offsets[NV2A_VP_ATTRIBUTES];
    uint8_t bytes[NV2A_VP_ATTRIBUTES];
    uint32_t enabled_mask, stride_bytes;
} NV2AInlineArrayLayout;

static NV2AVPStatus nv2a_inline_array_layout(
    const uint32_t formats[NV2A_VP_ATTRIBUTES], NV2AInlineArrayLayout *out,
    unsigned *bad_attribute) {
    NV2AInlineArrayLayout layout;
    if(bad_attribute) *bad_attribute=UINT_MAX;
    if(!formats || !out) return NV2A_VP_INVALID_ARGUMENT;
    memset(&layout,0,sizeof(layout));
    for(unsigned a=0;a<NV2A_VP_ATTRIBUTES;a++) {
        uint32_t format=formats[a];
        unsigned count=(format>>4)&15u, type=format&15u;
        layout.formats[a]=format;
        if(!count) continue;
        if(count>4u || (type!=2u && type!=1u && !(type==0u && count==4u))) {
            if(bad_attribute) *bad_attribute=a;
            return NV2A_VP_UNSUPPORTED_FORMAT;
        }
        unsigned size=type==2u ? 4u : type==1u ? 2u : 1u;
        unsigned offset=(layout.stride_bytes+size-1u)&~(size-1u);
        layout.offsets[a]=(uint16_t)offset;
        layout.bytes[a]=(uint8_t)(size*count);
        layout.enabled_mask|=1u<<a;
        layout.stride_bytes=offset+size*count;
    }
    if(!layout.stride_bytes) return NV2A_VP_INVALID_ARGUMENT;
    *out=layout;
    return NV2A_VP_OK;
}

static NV2AVPStatus nv2a_inline_array_count(const NV2AInlineArrayLayout *layout,
    uint32_t word_count, uint32_t vertex_limit, uint32_t *count) {
    if(!layout || !count || !layout->stride_bytes) return NV2A_VP_INVALID_ARGUMENT;
    uint64_t bytes=(uint64_t)word_count*4u;
    /* A partial final vertex is outside this bounded path. Do not silently
     * render a truncated draw after a malformed packet or accumulator overflow.
     */
    if(bytes%layout->stride_bytes || bytes/layout->stride_bytes>vertex_limit)
        return NV2A_VP_INVALID_ARGUMENT;
    *count=(uint32_t)(bytes/layout->stride_bytes);
    return NV2A_VP_OK;
}

static NV2AVPStatus nv2a_inline_array_read(const NV2AInlineArrayLayout *layout,
    const uint32_t *words, uint32_t word_count, uint32_t index,
    float out[NV2A_VP_ATTRIBUTES][4], unsigned *bad_attribute) {
    if(bad_attribute) *bad_attribute=UINT_MAX;
    if(!layout || !words || !out || !layout->stride_bytes)
        return NV2A_VP_INVALID_ARGUMENT;
    uint64_t begin=(uint64_t)index*layout->stride_bytes;
    uint64_t available=(uint64_t)word_count*4u;
    if(begin+layout->stride_bytes>available) return NV2A_VP_INVALID_ARGUMENT;
    float input[NV2A_VP_ATTRIBUTES][4]={{0}};
    for(unsigned a=0;a<NV2A_VP_ATTRIBUTES;a++) {
        input[a][3]=1.0f;
        if(!(layout->enabled_mask&(1u<<a))) continue;
        if((unsigned)layout->offsets[a]+layout->bytes[a]>layout->stride_bytes) {
            if(bad_attribute) *bad_attribute=a;
            return NV2A_VP_INVALID_ARGUMENT;
        }
        NV2AVPStatus status=nv2a_vp_decode_attribute(layout->formats[a],
            (const unsigned char *)words+(size_t)begin+layout->offsets[a],
            layout->bytes[a],input[a]);
        if(status!=NV2A_VP_OK) {
            if(bad_attribute) *bad_attribute=a;
            return status;
        }
    }
    memcpy(out,input,sizeof(input));
    return NV2A_VP_OK;
}

#endif
