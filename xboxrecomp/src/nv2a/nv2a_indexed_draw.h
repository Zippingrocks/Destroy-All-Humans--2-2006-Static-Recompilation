#ifndef NV2A_INDEXED_DRAW_IMPLEMENTATION_H
#define NV2A_INDEXED_DRAW_IMPLEMENTATION_H

/* Private implementation included after the PGRAPH state declaration.
 * Only the captured DAH2 MOV-program / linear-texture combiner subset is
 * admitted. Unsupported state is observable and never falls back to a quad,
 * a guessed shader, or the unrelated legacy Burnout inline rendering path.
 */
enum {
    PGRAPH_REJECT_STATE=1, PGRAPH_REJECT_SHADER, PGRAPH_REJECT_MEMORY,
    PGRAPH_REJECT_OUTPUT, PGRAPH_REJECT_DEVICE, PGRAPH_REJECT_LIMIT,
    PGRAPH_REJECT_TOPOLOGY, PGRAPH_REJECT_INLINE
};
#define PG_REG(method) g_pg.registers[(method)/4]

static void pgraph_reject_draw(unsigned reason, uint32_t detail) {
    static const char *names[]={"none","state","shader","guest-memory",
        "vertex-output","device","limit","topology","legacy-inline"};
    g_pg.stats.rejected_draws++;
    if (reason<9 && !(g_pg.reject_reported&(1u<<reason))) {
        g_pg.reject_reported|=1u<<reason;
        fprintf(stderr,"[PGRAPH-REJECT] reason=%s detail=%08X value=%08X mode=%u indices=%u\n",
            names[reason],detail,
            (reason==PGRAPH_REJECT_STATE && detail<sizeof(g_pg.registers)) ? PG_REG(detail) : 0,
            g_pg.draw_mode,g_pg.index_count);
        if (reason==PGRAPH_REJECT_STATE && detail==NV097_SET_BLEND_FUNC_SFACTOR)
            fprintf(stderr,"[PGRAPH-BLEND] enable=%d sfactor=%08X dfactor=%08X equation=%08X\n",
                g_pg.blend_enable,g_pg.blend_sfactor,g_pg.blend_dfactor,
                PG_REG(NV097_SET_BLEND_EQUATION));
        if (reason==PGRAPH_REJECT_STATE) fprintf(stderr,
            "[PGRAPH-STATE] combiner=%08X shader_stage=%08X color_icw=%08X/%08X color_ocw=%08X/%08X alpha_icw=%08X/%08X alpha_ocw=%08X/%08X final=%08X/%08X texfmt=%08X texctl0=%08X texaddr=%08X texfilter=%08X\n",
            PG_REG(NV097_SET_COMBINER_CONTROL),PG_REG(NV097_SET_SHADER_STAGE_PROGRAM),
            PG_REG(NV097_SET_COMBINER_COLOR_ICW),PG_REG(NV097_SET_COMBINER_COLOR_ICW+4),
            PG_REG(NV097_SET_COMBINER_COLOR_OCW),PG_REG(NV097_SET_COMBINER_COLOR_OCW+4),
            PG_REG(NV097_SET_COMBINER_ALPHA_ICW),PG_REG(NV097_SET_COMBINER_ALPHA_ICW+4),
            PG_REG(NV097_SET_COMBINER_ALPHA_OCW),PG_REG(NV097_SET_COMBINER_ALPHA_OCW+4),
            PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0),PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1),
            PG_REG(NV097_SET_TEXTURE_FORMAT),PG_REG(NV097_SET_TEXTURE_CONTROL0),
            PG_REG(NV097_SET_TEXTURE_ADDRESS),PG_REG(NV097_SET_TEXTURE_FILTER));
        if (reason==PGRAPH_REJECT_STATE) fprintf(stderr,
            "[PGRAPH-STATE-FULL] color_icw2=%08X/%08X color_ocw2=%08X/%08X "
            "alpha_icw2=%08X/%08X alpha_ocw2=%08X/%08X factor0=%08X factor1=%08X "
            "surf=%08X/%08X window=%08X/%08X "
            "tex0=%08X,%08X,%08X,%08X tex1=%08X,%08X,%08X,%08X "
            "tex2=%08X,%08X,%08X,%08X tex3=%08X,%08X,%08X,%08X\n",
            PG_REG(NV097_SET_COMBINER_COLOR_ICW+8),PG_REG(NV097_SET_COMBINER_COLOR_ICW+12),
            PG_REG(NV097_SET_COMBINER_COLOR_OCW+8),PG_REG(NV097_SET_COMBINER_COLOR_OCW+12),
            PG_REG(NV097_SET_COMBINER_ALPHA_ICW+8),PG_REG(NV097_SET_COMBINER_ALPHA_ICW+12),
            PG_REG(NV097_SET_COMBINER_ALPHA_OCW+8),PG_REG(NV097_SET_COMBINER_ALPHA_OCW+12),
            PG_REG(NV097_SET_COMBINER_FACTOR0),PG_REG(NV097_SET_COMBINER_FACTOR0+4),
            g_pg.surface_clip_h,g_pg.surface_clip_v,
            PG_REG(NV097_SET_WINDOW_CLIP_HORIZONTAL),PG_REG(NV097_SET_WINDOW_CLIP_VERTICAL),
            PG_REG(NV097_SET_TEXTURE_OFFSET),PG_REG(NV097_SET_TEXTURE_FORMAT),PG_REG(NV097_SET_TEXTURE_CONTROL1),PG_REG(NV097_SET_TEXTURE_IMAGE_RECT),
            PG_REG(NV097_SET_TEXTURE_OFFSET+0x40),PG_REG(NV097_SET_TEXTURE_FORMAT+0x40),PG_REG(NV097_SET_TEXTURE_CONTROL1+0x40),PG_REG(NV097_SET_TEXTURE_IMAGE_RECT+0x40),
            PG_REG(NV097_SET_TEXTURE_OFFSET+0x80),PG_REG(NV097_SET_TEXTURE_FORMAT+0x80),PG_REG(NV097_SET_TEXTURE_CONTROL1+0x80),PG_REG(NV097_SET_TEXTURE_IMAGE_RECT+0x80),
            PG_REG(NV097_SET_TEXTURE_OFFSET+0xC0),PG_REG(NV097_SET_TEXTURE_FORMAT+0xC0),PG_REG(NV097_SET_TEXTURE_CONTROL1+0xC0),PG_REG(NV097_SET_TEXTURE_IMAGE_RECT+0xC0));
        if (reason==PGRAPH_REJECT_STATE) fprintf(stderr,
            "[PGRAPH-STATE-TEX4] ctl0=%08X/%08X/%08X/%08X addr=%08X/%08X/%08X/%08X filter=%08X/%08X/%08X/%08X\n",
            PG_REG(NV097_SET_TEXTURE_CONTROL0),PG_REG(NV097_SET_TEXTURE_CONTROL0+0x40),
            PG_REG(NV097_SET_TEXTURE_CONTROL0+0x80),PG_REG(NV097_SET_TEXTURE_CONTROL0+0xC0),
            PG_REG(NV097_SET_TEXTURE_ADDRESS),PG_REG(NV097_SET_TEXTURE_ADDRESS+0x40),
            PG_REG(NV097_SET_TEXTURE_ADDRESS+0x80),PG_REG(NV097_SET_TEXTURE_ADDRESS+0xC0),
            PG_REG(NV097_SET_TEXTURE_FILTER),PG_REG(NV097_SET_TEXTURE_FILTER+0x40),
            PG_REG(NV097_SET_TEXTURE_FILTER+0x80),PG_REG(NV097_SET_TEXTURE_FILTER+0xC0));
    }
}

static int pgraph_track_array_state(uint32_t method,uint32_t value) {
    if (method==NV097_SET_TRANSFORM_PROGRAM_LOAD) {
        g_pg.program_word=value<NV2A_VP_SLOTS ? value*4 : NV2A_VP_SLOTS*4;
        return 1;
    }
    if (method==NV097_SET_TRANSFORM_CONSTANT_LOAD) {
        g_pg.constant_word=value<NV2A_VP_CONSTANTS ? value*4 : NV2A_VP_CONSTANTS*4;
        return 1;
    }
    if (method>=NV097_SET_TRANSFORM_PROGRAM && method<NV097_SET_TRANSFORM_PROGRAM+0x80 && !(method&3)) {
        if (g_pg.program_word<NV2A_VP_SLOTS*4) {
            g_pg.program[g_pg.program_word]=value;
            g_pg.program_valid[g_pg.program_word++]=1;
        }
        return 1;
    }
    if (method>=NV097_SET_TRANSFORM_CONSTANT && method<NV097_SET_TRANSFORM_CONSTANT+0x80 && !(method&3)) {
        if (g_pg.constant_word<NV2A_VP_CONSTANTS*4) {
            memcpy((unsigned char *)g_pg.constants+g_pg.constant_word*4,&value,4);
            g_pg.constant_valid[g_pg.constant_word++]=1;
        }
        return 1;
    }
    if ((method>=NV097_SET_VERTEX_DATA_ARRAY_OFFSET && method<NV097_SET_VERTEX_DATA_ARRAY_OFFSET+0x40) ||
        (method>=NV097_SET_VERTEX_DATA_ARRAY_FORMAT && method<NV097_SET_VERTEX_DATA_ARRAY_FORMAT+0x40) ||
        method==NV097_SET_TRANSFORM_EXECUTION_MODE || method==NV097_SET_TRANSFORM_PROGRAM_START ||
        method==NV097_SET_TRANSFORM_PROGRAM_CXT_WRITE_EN) return 1;
    if (method==NV097_ARRAY_ELEMENT16 || method==NV097_ARRAY_ELEMENT32 || method==NV097_DRAW_ARRAYS) {
        if (!g_pg.in_draw) return 0;
        unsigned count=method==NV097_ARRAY_ELEMENT16 ? 2 : method==NV097_ARRAY_ELEMENT32 ? 1 : (value>>24)+1;
        unsigned kind=method==NV097_DRAW_ARRAYS ? 2 : 1;
        if (g_pg.inline_count || (g_pg.index_source && (g_pg.index_source!=kind || kind==2)))
            g_pg.draw_error=PGRAPH_REJECT_STATE; /* Multiple DRAW_ARRAYS ranges need restart semantics. */
        g_pg.index_source=kind;
        if (count>MAX_INLINE_VERTS-g_pg.index_count) {
            g_pg.draw_error=PGRAPH_REJECT_LIMIT;
            return 1;
        }
        for (unsigned i=0;i<count;i++) {
            uint32_t index=method==NV097_ARRAY_ELEMENT16 ? ((value>>(i*16))&0xFFFF) :
                method==NV097_ARRAY_ELEMENT32 ? value : (value&0xFFFFFF)+i;
            g_pg.indices[g_pg.index_count++]=index;
        }
        return 1;
    }
    return 0;
}

/* Verify exact raw combiner state before using a fixed-function equivalent.
 * NV2A ICW A occupies the high byte; OCW AB destination is bits4..7.
 * Captured RGB: r0=clamp(2*v0*t0); alpha: r0.a=v0.a*t0.a.
 * Final RGB is clamp(v1+r0), final alpha r0.a. The vertex check below requires
 * v1.rgb=0. Facts verified against xemu pgraph/glsl/psh.c and psh_regs.h.
 */
enum {
    PGRAPH_ARRAY_PROFILE_NONE,
    PGRAPH_ARRAY_PROFILE_TEXTURED_ARGB,
    PGRAPH_ARRAY_PROFILE_MOVIE,
    PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB,
    PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB,
    PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB
};

static unsigned pgraph_array_profile(void) {
    if (PG_REG(NV097_SET_COMBINER_CONTROL)==0x11101 &&
        PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==1 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC4C80000 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x100C0 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD4D81010 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0xC0 &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0xE &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1)==0x1C80 &&
        PG_REG(NV097_SET_TEXTURE_FORMAT)==0x11229 &&
        PG_REG(NV097_SET_TEXTURE_CONTROL0)==0x4003FFC0 &&
        PG_REG(NV097_SET_TEXTURE_ADDRESS)==0x10303 &&
        PG_REG(NV097_SET_TEXTURE_FILTER)==0x02023F01)
        return PGRAPH_ARRAY_PROFILE_TEXTURED_ARGB;
    if (PG_REG(NV097_SET_COMBINER_CONTROL)==0x11101 &&
        PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==1 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC4C80000 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x100C0 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD4D81010 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0xC0 &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0xE &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1)==0x1C80 &&
        PG_REG(NV097_SET_TEXTURE_FORMAT)==0x11E29 &&
        PG_REG(NV097_SET_TEXTURE_CONTROL0)==0x4003FFC0 &&
        PG_REG(NV097_SET_TEXTURE_ADDRESS)==0x10303 &&
        PG_REG(NV097_SET_TEXTURE_FILTER)==0x02023F01)
        return PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB;
    /* DAH2 title/menu pass.  Decoding the raw NV2A inputs with xemu's
     * psh_regs rules gives:
     *   stage 0 RGB: r0 = t0 * 1 + v0 * -1 = t0 - v0
     *   stage 0 A:   r0.a = t0.a - v0.a
     *   stage 1 A:   r0.a = t0.a
     *   final:       clamp(r0.rgb), r0.a
     * The texture is linear X8R8G8B8, so its sampled alpha is one. */
    if (PG_REG(NV097_SET_COMBINER_CONTROL)==0x11102 &&
        PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==1 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC820C440 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW+4)==0 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x00000C00 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW+4)==0 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD830D450 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW+4)==0xD8301010 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0x00000C00 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW+4)==0x000000C0 &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0xE &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1)==0x1C80 &&
        PG_REG(NV097_SET_TEXTURE_FORMAT)==0x11E29 &&
        PG_REG(NV097_SET_TEXTURE_CONTROL0)==0x4003FFC0 &&
        PG_REG(NV097_SET_TEXTURE_ADDRESS)==0x10303 &&
        PG_REG(NV097_SET_TEXTURE_FILTER)==0x02023F01)
        return PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB;
    /* Four jittered samples of the current 320x240 title surface.  The first
     * two combiner stages form half-weighted pairs with factor0=0x404040;
     * stage two adds those pair results.  Sequential saturated multiply-add
     * is equivalent for these non-negative XRGB samples. */
    if (PG_REG(NV097_SET_COMBINER_CONTROL)==0x11104 &&
        PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==0x8421 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC1C8C1C9 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW+4)==0xC1CAC1CB &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW+8)==0xCC20CD20 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW+12)==0 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x00010C00 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW+4)==0x00010D00 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW+8)==0x00030C00 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW+12)==0 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD1D8D1D9 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW+4)==0xD1DAD1DB &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW+8)==0xDC30DD30 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW+12)==0xD1301010 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0x00010C00 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW+4)==0x00010D00 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW+8)==0x00030C00 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW+12)==0x000000C0 &&
        PG_REG(NV097_SET_COMBINER_FACTOR0)==0xFF404040 &&
        PG_REG(NV097_SET_COMBINER_FACTOR0+4)==0xFF404040 &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0xE &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1)==0x1C80) {
        uint32_t offset=PG_REG(NV097_SET_TEXTURE_OFFSET);
        for (unsigned stage=0;stage<4;stage++) {
            unsigned d=stage*0x40;
            if (PG_REG(NV097_SET_TEXTURE_OFFSET+d)!=offset ||
                PG_REG(NV097_SET_TEXTURE_FORMAT+d)!=0x11E29 ||
                PG_REG(NV097_SET_TEXTURE_CONTROL0+d)!=0x4003FFC0 ||
                PG_REG(NV097_SET_TEXTURE_ADDRESS+d)!=0x10303 ||
                PG_REG(NV097_SET_TEXTURE_FILTER+d)!=(stage ? 0x02022000u : 0x02023F01u) ||
                PG_REG(NV097_SET_TEXTURE_CONTROL1+d)!=0x05000000 ||
                PG_REG(NV097_SET_TEXTURE_IMAGE_RECT+d)!=0x014000F0)
                return PGRAPH_ARRAY_PROFILE_NONE;
        }
        return PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB;
    }
    /* Two-stage Bink presentation pass.  Stage 0 writes
     * r0.rgb=clamp(2*v0.rgb), stage 1 writes r0.a=v0.b, and the final
     * combiner emits v1+r0/r0.a.  Texture mode zero means no sampling. */
    if (PG_REG(NV097_SET_COMBINER_CONTROL)==0x11102 &&
        PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==0 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC420C020 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW+4)==0 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x00010C00 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW+4)==0 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD430D030 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW+4)==0xD430D030 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0x00010C00 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW+4)==0x00000C00 &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0xE &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1)==0x1C80 &&
        (PG_REG(NV097_SET_TEXTURE_FORMAT)==0x11229 ||
         PG_REG(NV097_SET_TEXTURE_FORMAT)==0x11E29) &&
        PG_REG(NV097_SET_TEXTURE_CONTROL0)==0x0003FFC0 &&
        PG_REG(NV097_SET_TEXTURE_ADDRESS)==0x10101 &&
        PG_REG(NV097_SET_TEXTURE_FILTER)==0x02023F01)
        return PGRAPH_ARRAY_PROFILE_MOVIE;
    return PGRAPH_ARRAY_PROFILE_NONE;
}

static uint32_t pgraph_supported_array_state(unsigned profile) {
    const uint32_t pairs[][2]={
        {NV097_SET_TRANSFORM_EXECUTION_MODE,6}, {NV097_SET_TRANSFORM_PROGRAM_CXT_WRITE_EN,0},
        {NV097_SET_CONTEXT_DMA_A,3}, {NV097_SET_CONTEXT_DMA_VERTEX_A,3},
        {NV097_SET_CONTEXT_DMA_VERTEX_B,3},
        {NV097_SET_FOG_ENABLE,0}, {NV097_SET_STENCIL_TEST_ENABLE,0},
        {NV097_SET_POLY_OFFSET_FILL_ENABLE,0}, {NV097_SET_SHADE_MODE,0x1D01},
        {NV097_SET_FRONT_POLYGON_MODE,0x1B02}, {NV097_SET_BACK_POLYGON_MODE,0x1B02},
        {NV097_SET_SURFACE_FORMAT,0x124}, {NV097_SET_CLIP_MIN,0},
        {NV097_SET_CLIP_MAX,0x4B7FFFFF}, {NV097_SET_BLEND_EQUATION,0x8006}
    };
    for (unsigned i=0;i<sizeof(pairs)/sizeof(pairs[0]);i++)
        if (PG_REG(pairs[i][0])!=pairs[i][1]) return pairs[i][0];
    if (!profile) return NV097_SET_COMBINER_CONTROL;
    if (profile!=PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB)
        for (unsigned stage=1;stage<4;stage++)
            if (PG_REG(NV097_SET_TEXTURE_CONTROL0+stage*0x40)&(1u<<30)) return NV097_SET_TEXTURE_CONTROL0+stage*0x40;
    if (PG_REG(NV097_SET_ANTI_ALIASING_CONTROL)&1) return NV097_SET_ANTI_ALIASING_CONTROL;
    if (PG_REG(NV097_SET_DEPTH_FUNC)<0x200 || PG_REG(NV097_SET_DEPTH_FUNC)>0x207) return NV097_SET_DEPTH_FUNC;
    if (PG_REG(NV097_SET_ALPHA_FUNC)<0x200 || PG_REG(NV097_SET_ALPHA_FUNC)>0x207) return NV097_SET_ALPHA_FUNC;
    if (g_pg.blend_enable &&
        !((g_pg.blend_sfactor==0x302 && g_pg.blend_dfactor==0x303) ||
          (g_pg.blend_sfactor==1 && (g_pg.blend_dfactor==0 || g_pg.blend_dfactor==1))))
        return NV097_SET_BLEND_FUNC_SFACTOR;
    if (g_pg.cull_enable && (PG_REG(NV097_SET_CULL_FACE)!=0x405 || PG_REG(NV097_SET_FRONT_FACE)!=0x900))
        return NV097_SET_CULL_FACE;
    if (profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB ||
        profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) {
        /* The title scene is deliberately rendered through the game's
         * 320x240 UI surface before its presentation pass. */
        if (g_pg.surface_clip_h!=0x01400000u || g_pg.surface_clip_v!=0x00F00000u)
            return NV097_SET_SURFACE_CLIP_HORIZONTAL;
    } else if ((g_pg.surface_clip_h&0xFFFF) || (g_pg.surface_clip_v&0xFFFF) ||
               (g_pg.surface_clip_h>>16)!=d3d8_GetBackbufferWidth() ||
               (g_pg.surface_clip_v>>16)!=d3d8_GetBackbufferHeight()) {
        return NV097_SET_SURFACE_CLIP_HORIZONTAL;
    }
    if (PG_REG(NV097_SET_WINDOW_CLIP_HORIZONTAL)!=g_pg.surface_clip_h ||
        PG_REG(NV097_SET_WINDOW_CLIP_VERTICAL)!=g_pg.surface_clip_v || PG_REG(NV097_SET_WINDOW_CLIP_TYPE))
        return NV097_SET_WINDOW_CLIP_HORIZONTAL;
    return 0;
}

static int pgraph_read_vertex(uint32_t index,unsigned attributes,NV2AVertexResult *result) {
    float input[NV2A_VP_ATTRIBUTES][4]={{0}};
    for (unsigned a=0;a<NV2A_VP_ATTRIBUTES;a++) {
        input[a][3]=1;
        if (!(attributes&(1u<<a))) continue;
        uint32_t format=PG_REG(NV097_SET_VERTEX_DATA_ARRAY_FORMAT+a*4);
        unsigned count=(format>>4)&15,type=format&15,stride=(format>>8)&255;
        unsigned bytes=type==2 ? count*4 : 4;
        if (!count || count>4 || (type!=2 && !(type==0 && count==4))) return 0;
        uint32_t base=PG_REG(NV097_SET_VERTEX_DATA_ARRAY_OFFSET+a*4)&0x7FFFFFFF;
        uint64_t address=(uint64_t)base+(uint64_t)index*stride;
        unsigned char data[16];
        if (address+bytes>0x100000000ULL || !g_pg_guest_reader ||
            !g_pg_guest_reader((uint32_t)address,data,bytes) ||
            nv2a_vp_decode_attribute(format,data,bytes,input[a])!=NV2A_VP_OK) return 0;
    }
    return nv2a_vp_execute_mov(g_pg.program,NV2A_VP_SLOTS,
        PG_REG(NV097_SET_TRANSFORM_PROGRAM_START),input,g_pg.constants,result)==NV2A_VP_OK;
}

static int pgraph_pack_vertex(const NV2AVertexResult *r,OutputVertex *v,unsigned tw,unsigned th,int texel_coords) {
    if (r->written_mask[0]!=15 || r->written_mask[3]!=15 || r->written_mask[9]!=15) return 0;
    for (unsigned o=0;o<NV2A_VP_OUTPUTS;o++)for(unsigned c=0;c<4;c++)
        if (!isfinite(r->output[o][c])) return 0;
    /* Host XYZRHW currently ignores W. Admit only the exact affine 2D subset.
     * Nonzero guest depth needs NV2A depth quantization, not a guessed z copy. */
    if (r->output[0][3]!=1 || r->output[0][2]!=0 ||
        r->output[4][0]!=0 || r->output[4][1]!=0 || r->output[4][2]!=0) return 0;
    v->x=truncf(r->output[0][0]*16.0f)/16.0f;
    v->y=truncf(r->output[0][1]*16.0f)/16.0f;
    v->z=0;v->rhw=1;
    v->u=texel_coords ? r->output[9][0] : r->output[9][0]/tw;
    v->v=texel_coords ? r->output[9][1] : r->output[9][1]/th;
    if (!isfinite(v->x) || !isfinite(v->y) || !isfinite(v->u) || !isfinite(v->v)) return 0;
    uint32_t color[4];
    for(unsigned c=0;c<4;c++) {
        float f=fminf(1,fmaxf(0,r->output[3][c]))*255.0f;
        float integral=floorf(f+0.5f);
        if (fabsf(f-integral)>0.00003f) return 0; /* Do not invent lossy float-color quantization. */
        color[c]=(uint32_t)integral;
    }
    v->color=(color[3]<<24)|(color[0]<<16)|(color[1]<<8)|color[2];
    return 1;
}

static void pgraph_movie_vertex_alpha(OutputVertex *v) {
    /* The movie profile's second alpha combiner selects interpolated v0.b. */
    v->color=(v->color&0x00FFFFFFu)|((v->color&0xFFu)<<24);
}

typedef struct {
    float x,y,z,rhw;
    uint32_t color;
    float uv[8];
} PgraphOutputVertex4;

static int pgraph_pack_vertex4(const NV2AVertexResult *r,PgraphOutputVertex4 *v,
    unsigned tw,unsigned th,unsigned texel_coord_mask) {
    if (!pgraph_pack_vertex(r,(OutputVertex *)v,tw,th,texel_coord_mask&1u)) return 0;
    for (unsigned stage=0;stage<4;stage++) {
        unsigned output=9+stage;
        /* PROJECT2D consumes XY; the title shader deliberately writes zero
         * Z/W after scaling each coordinate by its jitter constant.  Linear
         * NV2A textures retain texel coordinates through interpolation and
         * normalize them in the fragment stage, matching xemu. */
        if (r->written_mask[output]!=15) return 0;
        if (texel_coord_mask&(1u<<stage)) {
            v->uv[stage*2]=r->output[output][0];
            v->uv[stage*2+1]=r->output[output][1];
        } else {
            v->uv[stage*2]=r->output[output][0]/tw;
            v->uv[stage*2+1]=r->output[output][1]/th;
        }
        if (!isfinite(v->uv[stage*2]) || !isfinite(v->uv[stage*2+1])) return 0;
    }
    return 1;
}

static int pgraph_surface_index(uint32_t guest_offset) {
    for (unsigned i=0;i<4;i++)
        if (g_pg.array_surfaces[i].texture && g_pg.array_surfaces[i].guest_offset==guest_offset)
            return (int)i;
    return -1;
}

static int pgraph_ensure_surface(IDirect3DDevice8 *dev,uint32_t guest_offset,
    unsigned width,unsigned height,unsigned guest_pitch) {
    int existing=pgraph_surface_index(guest_offset);
    if (existing>=0) {
        return g_pg.array_surfaces[existing].width==width &&
            g_pg.array_surfaces[existing].height==height ? existing : -1;
    }
    unsigned slot;
    for (slot=0;slot<4;slot++) if (!g_pg.array_surfaces[slot].texture) break;
    if (slot==4 || !width || !height) return -1;
    IDirect3DTexture8 *texture=NULL;
    if (FAILED(dev->lpVtbl->CreateTexture(dev,width,height,1,D3DUSAGE_RENDERTARGET,
        D3DFMT_LIN_A8R8G8B8,0,&texture)) || !texture) return -1;
    D3D8Texture *host=(D3D8Texture *)texture;
    /* The swap chain is RGBA8 while Xbox linear XRGB bytes are uploaded as
     * BGRA elsewhere.  Surface-to-surface rendering stays entirely on the
     * host, so replace the wrapper resource with RGBA8 for lossless copies to
     * the swap-chain backbuffer. */
    if (host->srv) { ID3D11ShaderResourceView_Release(host->srv);host->srv=NULL; }
    if (host->d3d11_texture) { ID3D11Texture2D_Release(host->d3d11_texture);host->d3d11_texture=NULL; }
    D3D11_TEXTURE2D_DESC color_desc={0};
    color_desc.Width=width;color_desc.Height=height;color_desc.MipLevels=1;
    color_desc.ArraySize=1;color_desc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
    color_desc.SampleDesc.Count=1;color_desc.Usage=D3D11_USAGE_DEFAULT;
    color_desc.BindFlags=D3D11_BIND_SHADER_RESOURCE|D3D11_BIND_RENDER_TARGET;
    if (FAILED(ID3D11Device_CreateTexture2D(d3d8_GetD3D11Device(),&color_desc,NULL,
        &host->d3d11_texture)) || !host->d3d11_texture ||
        FAILED(ID3D11Device_CreateShaderResourceView(d3d8_GetD3D11Device(),
        (ID3D11Resource *)host->d3d11_texture,NULL,&host->srv)) || !host->srv) {
        texture->lpVtbl->Release(texture);return -1;
    }
    host->dxgi_format=DXGI_FORMAT_R8G8B8A8_UNORM;
    ID3D11RenderTargetView *rtv=NULL;
    if (FAILED(ID3D11Device_CreateRenderTargetView(d3d8_GetD3D11Device(),
        (ID3D11Resource *)host->d3d11_texture,NULL,&rtv)) || !rtv) {
        texture->lpVtbl->Release(texture);return -1;
    }
    D3D11_TEXTURE2D_DESC depth_desc={0};
    depth_desc.Width=width;depth_desc.Height=height;depth_desc.MipLevels=1;
    depth_desc.ArraySize=1;depth_desc.Format=DXGI_FORMAT_D24_UNORM_S8_UINT;
    depth_desc.SampleDesc.Count=1;depth_desc.Usage=D3D11_USAGE_DEFAULT;
    depth_desc.BindFlags=D3D11_BIND_DEPTH_STENCIL;
    ID3D11Texture2D *depth=NULL;ID3D11DepthStencilView *dsv=NULL;
    if (FAILED(ID3D11Device_CreateTexture2D(d3d8_GetD3D11Device(),&depth_desc,NULL,&depth)) ||
        !depth || FAILED(ID3D11Device_CreateDepthStencilView(d3d8_GetD3D11Device(),
        (ID3D11Resource *)depth,NULL,&dsv)) || !dsv) {
        if (dsv) ID3D11DepthStencilView_Release(dsv);
        if (depth) ID3D11Texture2D_Release(depth);
        ID3D11RenderTargetView_Release(rtv);texture->lpVtbl->Release(texture);return -1;
    }
    /* Seed the host surface from guest VRAM.  This preserves CPU-authored
     * pixels before the surface's first GPU clear/draw and is bounds checked
     * by the registered guest reader. */
    if (g_pg_guest_reader && guest_pitch>=width*4) {
        D3DLOCKED_RECT lock={0};
        unsigned long long seeded_nonblack=0;
        if (SUCCEEDED(texture->lpVtbl->LockRect(texture,0,&lock,NULL,0)) && lock.pBits) {
            for (unsigned y=0;y<height;y++) {
                if (!g_pg_guest_reader(guest_offset+y*guest_pitch,
                    (unsigned char *)lock.pBits+(size_t)y*lock.Pitch,width*4)) break;
                const uint32_t *row=(const uint32_t *)((const unsigned char *)lock.pBits+(size_t)y*lock.Pitch);
                for (unsigned x=0;x<width;x++) seeded_nonblack+=(row[x]&0x00FFFFFFu)!=0;
            }
            texture->lpVtbl->UnlockRect(texture,0);
            fprintf(stderr,"[PGRAPH-SURFACE-SEED] guest=%08X size=%ux%u nonblack=%llu\n",
                guest_offset,width,height,seeded_nonblack);
        }
    }
    g_pg.array_surfaces[slot].guest_offset=guest_offset;
    g_pg.array_surfaces[slot].width=width;
    g_pg.array_surfaces[slot].height=height;
    g_pg.array_surfaces[slot].texture=texture;
    g_pg.array_surfaces[slot].rtv=rtv;
    g_pg.array_surfaces[slot].depth=depth;
    g_pg.array_surfaces[slot].dsv=dsv;
    fprintf(stderr,"[PGRAPH-SURFACE] create slot=%u guest=%08X size=%ux%u pitch=%u\n",
        slot,guest_offset,width,height,guest_pitch);
    return (int)slot;
}

static int pgraph_bind_array_target(IDirect3DDevice8 *dev) {
    unsigned width=g_pg.surface_clip_h>>16,height=g_pg.surface_clip_v>>16;
    unsigned pitch=PG_REG(NV097_SET_SURFACE_PITCH)&0xFFFF;
    uint32_t offset=PG_REG(NV097_SET_SURFACE_COLOR_OFFSET);
    int slot=pgraph_ensure_surface(dev,offset,width,height,pitch);
    if (slot<0) return PGRAPH_REJECT_DEVICE;
    for (unsigned stage=0;stage<4;stage++)
        if (FAILED(dev->lpVtbl->SetTexture(dev,stage,NULL))) return PGRAPH_REJECT_DEVICE;
    ID3D11DeviceContext_OMSetRenderTargets(d3d8_GetD3D11Context(),1,
        &g_pg.array_surfaces[slot].rtv,g_pg.array_surfaces[slot].dsv);
    return 0;
}

static IDirect3DTexture8 *pgraph_surface_texture(uint32_t guest_offset) {
    int slot=pgraph_surface_index(guest_offset);
    return slot>=0 ? g_pg.array_surfaces[slot].texture : NULL;
}

static void pgraph_clear_array_target(uint32_t flags,uint32_t color) {
    int slot=pgraph_surface_index(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
    if (slot<0) return;
    ID3D11DeviceContext *context=d3d8_GetD3D11Context();
    if (flags&0xF0) {
        float rgba[4]={((color>>16)&255)/255.0f,((color>>8)&255)/255.0f,
            (color&255)/255.0f,((color>>24)&255)/255.0f};
        ID3D11DeviceContext_ClearRenderTargetView(context,g_pg.array_surfaces[slot].rtv,rgba);
    }
    if (flags&3) {
        UINT clear_flags=0;
        if (flags&1) clear_flags|=D3D11_CLEAR_DEPTH;
        if (flags&2) clear_flags|=D3D11_CLEAR_STENCIL;
        ID3D11DeviceContext_ClearDepthStencilView(context,g_pg.array_surfaces[slot].dsv,
            clear_flags,1.0f,0);
    }
}

static void pgraph_copy_primary_to_backbuffer(uint32_t guest_offset) {
    int slot=pgraph_surface_index(guest_offset);
    if (slot<0 || g_pg.array_surfaces[slot].width!=d3d8_GetBackbufferWidth() ||
        g_pg.array_surfaces[slot].height!=d3d8_GetBackbufferHeight()) return;
    ID3D11Texture2D *backbuffer=NULL;
    if (SUCCEEDED(IDXGISwapChain_GetBuffer(d3d8_GetSwapChain(),0,
        &IID_ID3D11Texture2D,(void **)&backbuffer)) && backbuffer) {
        D3D8Texture *source=(D3D8Texture *)g_pg.array_surfaces[slot].texture;
        ID3D11DeviceContext_CopyResource(d3d8_GetD3D11Context(),
            (ID3D11Resource *)backbuffer,(ID3D11Resource *)source->d3d11_texture);
        ID3D11Texture2D_Release(backbuffer);
    }
}

static void pgraph_report_surface(uint32_t guest_offset,const char *label) {
    static unsigned reports;
    int slot=pgraph_surface_index(guest_offset);
    if (reports>=20 || slot<0) return;
    D3D8Texture *source=(D3D8Texture *)g_pg.array_surfaces[slot].texture;
    D3D11_TEXTURE2D_DESC desc={0};
    ID3D11Texture2D_GetDesc(source->d3d11_texture,&desc);
    D3D11_TEXTURE2D_DESC staging_desc=desc;
    staging_desc.Usage=D3D11_USAGE_STAGING;staging_desc.BindFlags=0;
    staging_desc.CPUAccessFlags=D3D11_CPU_ACCESS_READ;staging_desc.MiscFlags=0;
    ID3D11Texture2D *staging=NULL;
    if (FAILED(ID3D11Device_CreateTexture2D(d3d8_GetD3D11Device(),&staging_desc,NULL,&staging))) return;
    ID3D11DeviceContext_CopyResource(d3d8_GetD3D11Context(),(ID3D11Resource *)staging,
        (ID3D11Resource *)source->d3d11_texture);
    D3D11_MAPPED_SUBRESOURCE mapped={0};
    if (SUCCEEDED(ID3D11DeviceContext_Map(d3d8_GetD3D11Context(),
        (ID3D11Resource *)staging,0,D3D11_MAP_READ,0,&mapped))) {
        unsigned long long nonblack=0;
        for (unsigned y=0;y<desc.Height;y++) {
            const uint32_t *row=(const uint32_t *)((const unsigned char *)mapped.pData+(size_t)y*mapped.RowPitch);
            for (unsigned x=0;x<desc.Width;x++) nonblack+=(row[x]&0x00FFFFFFu)!=0;
        }
        fprintf(stderr,"[PGRAPH-SURFACE-CONTENT] %s guest=%08X size=%ux%u nonblack=%llu\n",
            label,guest_offset,desc.Width,desc.Height,nonblack);
        ID3D11DeviceContext_Unmap(d3d8_GetD3D11Context(),(ID3D11Resource *)staging,0);
        reports++;
    }
    ID3D11Texture2D_Release(staging);
}

static void pgraph_record_recent_draw(unsigned kind,unsigned profile,unsigned count) {
    static int dumped;
    if (!dumped && profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB &&
        PG_REG(NV097_SET_SURFACE_COLOR_OFFSET)==0x07743000u) {
        unsigned available=g_pg.recent_draw_total<64 ? g_pg.recent_draw_total : 64;
        fprintf(stderr,"[PGRAPH-PRE-TITLE] draws=%u\n",available);
        for (unsigned n=available;n;n--) {
            unsigned index=(g_pg.recent_draw_cursor+64-n)%64;
            fprintf(stderr,"[PGRAPH-PRE-TITLE-DRAW] kind=%u profile=%u target=%08X tex=%08X clip=%08X/%08X combiner=%08X mode=%u count=%u\n",
                g_pg.recent_draws[index].kind,g_pg.recent_draws[index].profile,
                g_pg.recent_draws[index].target,g_pg.recent_draws[index].texture,
                g_pg.recent_draws[index].clip_h,g_pg.recent_draws[index].clip_v,
                g_pg.recent_draws[index].combiner,g_pg.recent_draws[index].mode,
                g_pg.recent_draws[index].count);
        }
        dumped=1;
    }
    unsigned index=g_pg.recent_draw_cursor++%64;
    g_pg.recent_draws[index].kind=kind;g_pg.recent_draws[index].profile=profile;
    g_pg.recent_draws[index].count=count;g_pg.recent_draws[index].mode=g_pg.draw_mode;
    g_pg.recent_draws[index].target=PG_REG(NV097_SET_SURFACE_COLOR_OFFSET);
    g_pg.recent_draws[index].texture=PG_REG(NV097_SET_TEXTURE_OFFSET);
    g_pg.recent_draws[index].clip_h=g_pg.surface_clip_h;g_pg.recent_draws[index].clip_v=g_pg.surface_clip_v;
    g_pg.recent_draws[index].combiner=PG_REG(NV097_SET_COMBINER_CONTROL);
    g_pg.recent_draw_total++;
}

static int pgraph_upload_array_texture(IDirect3DDevice8 *dev,unsigned width,unsigned height,unsigned pitch,int force_opaque) {
    uint32_t address=PG_REG(NV097_SET_TEXTURE_OFFSET);
    uint64_t span=(uint64_t)(height-1)*pitch+width*4;
    size_t size=(size_t)width*height*4;
    if (!g_pg_guest_reader || (uint64_t)address+span>0x100000000ULL) return PGRAPH_REJECT_MEMORY;
    unsigned char *data=(unsigned char *)malloc(size);
    if (!data) return PGRAPH_REJECT_LIMIT;
    for (unsigned y=0;y<height;y++) {
        if (!g_pg_guest_reader(address+y*pitch,data+(size_t)y*width*4,width*4)) {
            free(data);return PGRAPH_REJECT_MEMORY;
        }
    }
    if (force_opaque) {
        uint32_t *pixels=(uint32_t *)data;
        static unsigned reports;
        if (reports<8) {
            size_t nonzero=0;
            uint32_t hash=2166136261u;
            for (size_t i=0;i<(size_t)width*height;i++) {
                uint32_t rgb=pixels[i]&0x00FFFFFFu;
                nonzero+=rgb!=0;
                hash=(hash^rgb)*16777619u;
            }
            fprintf(stderr,"[PGRAPH-XRGB] offset=%08X size=%ux%u pitch=%u nonzero_rgb=%llu hash=%08X first=%08X/%08X/%08X/%08X\n",
                address,width,height,pitch,(unsigned long long)nonzero,hash,
                pixels[0],pixels[1],pixels[2],pixels[3]);
            reports++;
        }
        for (size_t i=0;i<(size_t)width*height;i++) pixels[i]|=0xFF000000u;
    }
    if (g_pg.array_texture && (width!=g_pg.array_texture_width || height!=g_pg.array_texture_height)) {
        if (FAILED(dev->lpVtbl->SetTexture(dev,0,NULL))) { free(data);return PGRAPH_REJECT_DEVICE; }
        g_pg.array_texture->lpVtbl->Release(g_pg.array_texture);g_pg.array_texture=NULL;
    }
    if (!g_pg.array_texture) {
        HRESULT hr=dev->lpVtbl->CreateTexture(dev,width,height,1,D3DUSAGE_DYNAMIC,D3DFMT_LIN_A8R8G8B8,0,&g_pg.array_texture);
        if (FAILED(hr) || !g_pg.array_texture) { free(data);return PGRAPH_REJECT_DEVICE; }
        g_pg.array_texture_width=width;g_pg.array_texture_height=height;
    }
    D3DLOCKED_RECT lock={0};
    if (FAILED(g_pg.array_texture->lpVtbl->LockRect(g_pg.array_texture,0,&lock,NULL,0))) {
        free(data);return PGRAPH_REJECT_DEVICE;
    }
    int valid=lock.pBits && lock.Pitch>0 && (unsigned)lock.Pitch>=width*4;
    if (valid) for(unsigned y=0;y<height;y++)
        memcpy((unsigned char *)lock.pBits+(size_t)y*lock.Pitch,data+(size_t)y*width*4,width*4);
    HRESULT hr=g_pg.array_texture->lpVtbl->UnlockRect(g_pg.array_texture,0);
    free(data);
    return valid && SUCCEEDED(hr) ? 0 : PGRAPH_REJECT_DEVICE;
}

static void submit_indexed_draw(void) {
    OutputVertex *vertices=NULL;
    size_t vertex_stride=sizeof(OutputVertex);
    unsigned reason=g_pg.draw_error,detail=0,length=0,attributes=0;
    unsigned profile=pgraph_array_profile();
    unsigned texel_coord_mask=profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB ? 15u :
        (profile==PGRAPH_ARRAY_PROFILE_TEXTURED_ARGB ||
         profile==PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB ||
         profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB) ? 1u : 0u;
    pgraph_record_recent_draw(1,profile,g_pg.index_count);
    { static unsigned title_trace;
      if (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) title_trace=32;
      if (title_trace) {
          fprintf(stderr,"[PGRAPH-TITLE-DRAW] profile=%u target=%08X pitch=%08X clip=%08X/%08X tex=%08X mode=%u indices=%u\n",
              profile,PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),PG_REG(NV097_SET_SURFACE_PITCH),
              g_pg.surface_clip_h,g_pg.surface_clip_v,PG_REG(NV097_SET_TEXTURE_OFFSET),
              g_pg.draw_mode,g_pg.index_count);
          title_trace--;
      }
    }
    if (reason) goto rejected;
    if (g_pg.draw_mode!=5 && g_pg.draw_mode!=6) { reason=PGRAPH_REJECT_TOPOLOGY;goto rejected; }
    if (g_pg.index_count<3 || (g_pg.draw_mode==5 && g_pg.index_count%3)) { reason=PGRAPH_REJECT_TOPOLOGY;goto rejected; }
    detail=pgraph_supported_array_state(profile);
    if (detail) { reason=PGRAPH_REJECT_STATE;goto rejected; }
    unsigned start=PG_REG(NV097_SET_TRANSFORM_PROGRAM_START);
    if (nv2a_vp_validate_mov(g_pg.program,NV2A_VP_SLOTS,start,&length,&detail)!=NV2A_VP_OK) {
        reason=PGRAPH_REJECT_SHADER;goto rejected;
    }
    for (unsigned i=start;i<start+length;i++) {
        for(unsigned w=0;w<4;w++)if(!g_pg.program_valid[i*4+w]) { reason=PGRAPH_REJECT_SHADER;detail=i;goto rejected; }
        NV2AVPInstruction inst;nv2a_vp_decode_instruction(g_pg.program+i*4,&inst);
        if (inst.mac) for (unsigned source=0;source<3;source++) {
            if (source==1 || (inst.mac!=3 && source==2)) continue;
            if (inst.source[source].mux==2) attributes|=1u<<inst.attribute;
            if (inst.source[source].mux==3)for(unsigned c=0;c<4;c++)
                if(!g_pg.constant_valid[inst.constant*4+c]) { reason=PGRAPH_REJECT_SHADER;detail=inst.constant;goto rejected; }
        }
    }
    unsigned width=PG_REG(NV097_SET_TEXTURE_IMAGE_RECT)>>16;
    unsigned height=PG_REG(NV097_SET_TEXTURE_IMAGE_RECT)&0xFFFF;
    unsigned pitch=PG_REG(NV097_SET_TEXTURE_CONTROL1)>>16;
    if (!width || !height || width>2048 || height>2048 || pitch<width*4 || (uint64_t)width*height*4>16*1024*1024) {
        reason=PGRAPH_REJECT_LIMIT;detail=NV097_SET_TEXTURE_IMAGE_RECT;goto rejected;
    }
    if (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB)
        vertex_stride=sizeof(PgraphOutputVertex4);
    vertices=(OutputVertex *)malloc(g_pg.index_count*vertex_stride);
    if (!vertices) { reason=PGRAPH_REJECT_LIMIT;goto rejected; }
    for(unsigned i=0;i<g_pg.index_count;i++) {
        NV2AVertexResult result;
        detail=g_pg.indices[i];
        if (!pgraph_read_vertex(detail,attributes,&result)) { reason=PGRAPH_REJECT_MEMORY;goto rejected; }
        OutputVertex *vertex=(OutputVertex *)((unsigned char *)vertices+i*vertex_stride);
        if (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) {
            if (!pgraph_pack_vertex4(&result,(PgraphOutputVertex4 *)vertex,width,height,texel_coord_mask)) {
                static int output_dumped;
                if (!output_dumped) {
                    fprintf(stderr,"[PGRAPH-OUTPUT4] index=%u",detail);
                    for (unsigned o=0;o<NV2A_VP_OUTPUTS;o++) if (result.written_mask[o])
                        fprintf(stderr," o%u[%X]=%.7g,%.7g,%.7g,%.7g",o,result.written_mask[o],
                            result.output[o][0],result.output[o][1],result.output[o][2],result.output[o][3]);
                    fprintf(stderr,"\n");
                    output_dumped=1;
                }
                reason=PGRAPH_REJECT_OUTPUT;goto rejected;
            }
        } else if (!pgraph_pack_vertex(&result,vertex,width,height,texel_coord_mask&1u)) {
            reason=PGRAPH_REJECT_OUTPUT;goto rejected;
        }
        if (profile==PGRAPH_ARRAY_PROFILE_MOVIE) pgraph_movie_vertex_alpha(vertex);
    }
    if (profile==PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB ||
        profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB ||
        profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) {
        static unsigned vertex_reports;
        if (vertex_reports<4) {
            fprintf(stderr,"[PGRAPH-XRGB-VERTICES]");
            for(unsigned i=0;i<g_pg.index_count;i++) {
                OutputVertex *vertex=(OutputVertex *)((unsigned char *)vertices+i*vertex_stride);
                fprintf(stderr," %u:(%.3f,%.3f %.5f,%.5f %08X)",
                    i,vertex->x,vertex->y,vertex->u,vertex->v,vertex->color);
            }
            fprintf(stderr,"\n");
            vertex_reports++;
        }
    }
    IDirect3DDevice8 *dev=xbox_GetD3DDevice();
    if (!dev) { reason=PGRAPH_REJECT_DEVICE;goto rejected; }
    IDirect3DTexture8 *surface_texture=pgraph_surface_texture(PG_REG(NV097_SET_TEXTURE_OFFSET));

    static int title_content_trace;
    if (profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB &&
        PG_REG(NV097_SET_SURFACE_COLOR_OFFSET)==0x07743000u) title_content_trace=1;
    if (title_content_trace && surface_texture)
        pgraph_report_surface(PG_REG(NV097_SET_TEXTURE_OFFSET),"source");
    if (profile==PGRAPH_ARRAY_PROFILE_TEXTURED_ARGB ||
        profile==PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB ||
        profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB ||
        profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) {
        if (!surface_texture) {
        reason=pgraph_upload_array_texture(dev,width,height,pitch,
            profile==PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB ||
            profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB ||
            profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB);
        if (reason) goto rejected;
        }
    }
    reason=pgraph_bind_array_target(dev);
    if (reason) goto rejected;
    reason=PGRAPH_REJECT_DEVICE;
#define PG_CALL(call) do { if (FAILED(call)) goto rejected; } while(0)
#define PG_RS(state,value) PG_CALL(dev->lpVtbl->SetRenderState(dev,state,value))
#define PG_TSS(state,value) PG_CALL(dev->lpVtbl->SetTextureStageState(dev,0,state,value))
#define PG_TSS_STAGE(stage,state,value) PG_CALL(dev->lpVtbl->SetTextureStageState(dev,stage,state,value))
    D3DVIEWPORT8 viewport={0,0,g_pg.surface_clip_h>>16,g_pg.surface_clip_v>>16,0,1};
    PG_CALL(dev->lpVtbl->SetViewport(dev,&viewport));
    PG_CALL(dev->lpVtbl->SetPixelShader(dev,0));
    PG_CALL(dev->lpVtbl->SetVertexShader(dev,D3DFVF_XYZRHW|D3DFVF_DIFFUSE|
        (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB ? D3DFVF_TEX4 : D3DFVF_TEX1)));
    PG_RS(D3DRS_LIGHTING,FALSE);PG_RS(D3DRS_FOGENABLE,FALSE);PG_RS(D3DRS_SPECULARENABLE,FALSE);
    PG_RS(D3DRS_FILLMODE,D3DFILL_SOLID);PG_RS(D3DRS_SHADEMODE,2 /* D3DSHADE_GOURAUD */);
    PG_RS(D3DRS_ZENABLE,g_pg.depth_test);PG_RS(D3DRS_ZWRITEENABLE,PG_REG(NV097_SET_DEPTH_MASK)!=0);
    PG_RS(D3DRS_ZFUNC,PG_REG(NV097_SET_DEPTH_FUNC)-0x1FF);PG_RS(D3DRS_STENCILENABLE,FALSE);
    PG_RS(D3DRS_CULLMODE,g_pg.cull_enable ? D3DCULL_CCW : D3DCULL_NONE);
    PG_RS(D3DRS_ALPHATESTENABLE,g_pg.alpha_test);PG_RS(D3DRS_ALPHAFUNC,PG_REG(NV097_SET_ALPHA_FUNC)-0x1FF);
    PG_RS(D3DRS_ALPHAREF,PG_REG(NV097_SET_ALPHA_REF)&255);
    PG_RS(D3DRS_ALPHABLENDENABLE,g_pg.blend_enable);
    PG_RS(D3DRS_SRCBLEND,g_pg.blend_sfactor==1 ? D3DBLEND_ONE : D3DBLEND_SRCALPHA);
    PG_RS(D3DRS_DESTBLEND,g_pg.blend_dfactor==0 ? D3DBLEND_ZERO :
        g_pg.blend_dfactor==1 ? D3DBLEND_ONE : D3DBLEND_INVSRCALPHA);
    PG_RS(D3DRS_BLENDOP,1);
    uint32_t mask=g_pg.color_mask;
    PG_RS(D3DRS_COLORWRITEENABLE,((mask>>16)&1)|(((mask>>8)&1)<<1)|((mask&1)<<2)|(((mask>>24)&1)<<3));
    for(unsigned s=0;s<4;s++) PG_CALL(dev->lpVtbl->SetTexture(dev,s,
        profile!=PGRAPH_ARRAY_PROFILE_MOVIE &&
        (s==0 || profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) ?
        (IDirect3DBaseTexture8 *)(surface_texture ? surface_texture : g_pg.array_texture) : NULL));
    if (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) {
        PG_RS(D3DRS_TEXTUREFACTOR,0xFF808080u);
        for (unsigned s=0;s<4;s++) {
            PG_TSS_STAGE(s,D3DTSS_COLOROP,s ? D3DTOP_MULTIPLYADD : D3DTOP_MODULATE);
            PG_TSS_STAGE(s,D3DTSS_COLORARG1,D3DTA_TEXTURE);
            PG_TSS_STAGE(s,D3DTSS_COLORARG2,D3DTA_TFACTOR);
            PG_TSS_STAGE(s,D3DTSS_COLORARG0,D3DTA_CURRENT);
            PG_TSS_STAGE(s,D3DTSS_ALPHAOP,s ? D3DTOP_MULTIPLYADD : D3DTOP_MODULATE);
            PG_TSS_STAGE(s,D3DTSS_ALPHAARG1,D3DTA_TEXTURE);
            PG_TSS_STAGE(s,D3DTSS_ALPHAARG2,D3DTA_TFACTOR);
            PG_TSS_STAGE(s,D3DTSS_ALPHAARG0,D3DTA_CURRENT);
            PG_TSS_STAGE(s,D3DTSS_TEXCOORDINDEX,s);
        }
    } else if (profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB) {
        PG_TSS(D3DTSS_COLOROP,D3DTOP_SUBTRACT);PG_TSS(D3DTSS_COLORARG1,2);PG_TSS(D3DTSS_COLORARG2,0);
        PG_TSS(D3DTSS_ALPHAOP,D3DTOP_SELECTARG1);PG_TSS(D3DTSS_ALPHAARG1,2);PG_TSS(D3DTSS_ALPHAARG2,0);
    } else if (profile==PGRAPH_ARRAY_PROFILE_TEXTURED_ARGB || profile==PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB) {
        PG_TSS(D3DTSS_COLOROP,D3DTOP_MODULATE2X);PG_TSS(D3DTSS_COLORARG1,2);PG_TSS(D3DTSS_COLORARG2,0);
        PG_TSS(D3DTSS_ALPHAOP,D3DTOP_MODULATE);PG_TSS(D3DTSS_ALPHAARG1,2);PG_TSS(D3DTSS_ALPHAARG2,0);
    } else {
        PG_RS(D3DRS_TEXTUREFACTOR,0xFFFFFFFFu);
        PG_TSS(D3DTSS_COLOROP,D3DTOP_MODULATE2X);PG_TSS(D3DTSS_COLORARG1,0);PG_TSS(D3DTSS_COLORARG2,3);
        PG_TSS(D3DTSS_ALPHAOP,D3DTOP_SELECTARG1);PG_TSS(D3DTSS_ALPHAARG1,0);PG_TSS(D3DTSS_ALPHAARG2,0);
    }
    for (unsigned s=0;s<(profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB ? 4u : 1u);s++) {
        PG_TSS_STAGE(s,D3DTSS_ADDRESSU,D3DTADDRESS_CLAMP);PG_TSS_STAGE(s,D3DTSS_ADDRESSV,D3DTADDRESS_CLAMP);
        PG_TSS_STAGE(s,D3DTSS_MINFILTER,D3DTEXF_LINEAR);PG_TSS_STAGE(s,D3DTSS_MAGFILTER,D3DTEXF_LINEAR);
        PG_TSS_STAGE(s,D3DTSS_MIPFILTER,D3DTEXF_NONE);PG_TSS_STAGE(s,D3DTSS_MAXMIPLEVEL,0);
        PG_TSS_STAGE(s,D3DTSS_MIPMAPLODBIAS,0);
    }
    PG_CALL(dev->lpVtbl->BeginScene(dev));
    d3d8_shaders_set_texel_coord_mask(texel_coord_mask);
    unsigned primitives=g_pg.draw_mode==5 ? g_pg.index_count/3 : g_pg.index_count-2;
    HRESULT draw_result=dev->lpVtbl->DrawPrimitiveUP(dev,
        g_pg.draw_mode==5 ? D3DPT_TRIANGLELIST : D3DPT_TRIANGLESTRIP,
        primitives,vertices,(UINT)vertex_stride);
    HRESULT end_result=dev->lpVtbl->EndScene(dev);
    d3d8_shaders_set_texel_coord_mask(0);
    PG_CALL(draw_result);PG_CALL(end_result);
    if (g_pg.stats.indexed_draws<8)
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"early-target");
    if (title_content_trace)
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"target");
    pgraph_copy_primary_to_backbuffer(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
    g_pg.stats.draw_calls++;g_pg.stats.indexed_draws++;g_pg.stats.vertices_submitted+=g_pg.index_count;
    { static unsigned profile_reports[6];
      if (g_pg.stats.indexed_draws<=2 || (profile<6 && profile_reports[profile]<8)) {
        fprintf(stderr,"[PGRAPH-ARRAY] submitted profile=%u mode=%u indices=%u shader=%u texture=%ux%u pitch=%u\n",
            profile,g_pg.draw_mode,g_pg.index_count,length,width,height,pitch);
        if (profile<6) profile_reports[profile]++;
      }
    }
    free(vertices);
    return;
rejected:
    free(vertices);
    if (reason==PGRAPH_REJECT_SHADER) {
        static int shader_dumped;
        if (!shader_dumped) {
            unsigned shader_start=PG_REG(NV097_SET_TRANSFORM_PROGRAM_START);
            fprintf(stderr,"[PGRAPH-SHADER-DUMP] start=%u detail=%u\n",shader_start,detail);
            for (unsigned i=shader_start;i<shader_start+16 && i<NV2A_VP_SLOTS;i++)
                fprintf(stderr,"[PGRAPH-SHADER-INST] %u %08X %08X %08X %08X valid=%u%u%u%u\n",i,
                    g_pg.program[i*4],g_pg.program[i*4+1],g_pg.program[i*4+2],g_pg.program[i*4+3],
                    g_pg.program_valid[i*4],g_pg.program_valid[i*4+1],
                    g_pg.program_valid[i*4+2],g_pg.program_valid[i*4+3]);
            shader_dumped=1;
        }
    }
    pgraph_reject_draw(reason,detail);
#undef PG_CALL
#undef PG_RS
#undef PG_TSS
#undef PG_TSS_STAGE
}
#undef PG_REG
#endif
