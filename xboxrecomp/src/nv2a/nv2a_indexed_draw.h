#ifndef NV2A_INDEXED_DRAW_IMPLEMENTATION_H
#define NV2A_INDEXED_DRAW_IMPLEMENTATION_H

#include "nv2a_draw_vertex_cache.h"
#include "nv2a_inline_array.h"

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

typedef struct {
    uint32_t profile,count,mode,target,texture,clip_h,clip_v,combiner,reason,detail;
    uint32_t source_object,source_node;
} Dah2PgraphDrawTelemetry;
extern volatile uint32_t g_dah2_menu_active_node;
extern volatile uint32_t g_dah2_menu_active_object;
volatile uint32_t g_dah2_pgraph_draw_telemetry_cursor;
volatile Dah2PgraphDrawTelemetry g_dah2_pgraph_draw_telemetry[64];
volatile uint32_t g_dah2_pgraph_draw_registers[64][0x2000/4];
volatile uint32_t g_dah2_pgraph_draw_programs[64][NV2A_VP_SLOTS*4];
volatile uint8_t g_dah2_pgraph_draw_program_valid[64][NV2A_VP_SLOTS*4];
volatile float g_dah2_pgraph_draw_constants[64][NV2A_VP_CONSTANTS][4];
volatile uint8_t g_dah2_pgraph_draw_constant_valid[64][NV2A_VP_CONSTANTS*4];
volatile float g_dah2_pgraph_draw_outputs[64][NV2A_VP_OUTPUTS][4];
volatile uint8_t g_dah2_pgraph_draw_output_masks[64][NV2A_VP_OUTPUTS];
volatile uint32_t g_dah2_pgraph_draw_memory_failures[64][11];
volatile uint32_t g_dah2_pg_generic_draws,g_dah2_pg_generic_prims; /* generic scene profile submissions (the per-profile ring arrays are fixed at 10 entries) */
static NV2AInlineArrayLayout g_pg_inline_layout;

static unsigned pgraph_array_profile(void);

static void pgraph_reject_draw(unsigned reason, uint32_t detail) {
    if(pgraph_profile_counters_enabled())
        pgraph_record_profile_result(pgraph_array_profile(),g_pg.index_source,0,1);
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
    PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB,
    PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2,
    PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT4,
    PGRAPH_ARRAY_PROFILE_DAH2_SCENE_TEXTURED,
    PGRAPH_ARRAY_PROFILE_DAH2_SCENE_UNTEXTURED,
    PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC /* any register-combiner program, up to four 2D textures */
};

#include "../d3d/d3d8_swizzle.h"
static int pgraph_dah2_scene_texture_format(unsigned stage) {
    unsigned d=stage*0x40;uint32_t format=PG_REG(NV097_SET_TEXTURE_FORMAT+d);
    unsigned color=(format>>8)&0xFF,varying=(format>>16)&15;
    return (color==0x0C || color==0x0F) && (varying==1 || varying==5 || varying==6 || varying==7) &&
        /* Exponents are texture dimensions, not pipeline identity. The
         * repaired XG header now emits the retail U/V values and P=0. */
        (format&0xF000FFFFu)==(0x00000029u|(color<<8)) &&
        ((format>>20)&15u)<=11u && ((format>>24)&15u)<=11u &&
        PG_REG(NV097_SET_TEXTURE_CONTROL0+d)==0x4003FFC0u;
}
static int pgraph_dah2_final_combiner(void) {
    /* 0x130E0300: spare0 blended toward the fog register (A=fog.a, B=spare0, C=fog.rgb) -- the fog variant of the plain 0xE. */
    return (PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0xEu || PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0x130E0300u) &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1)==0x1C80u;
}
static int pgraph_dah2_scene_lit2(void) {
    static const uint32_t rgb_icw[6]={0,0xC4C80000,0xC9D10000,0xCDDD0000,0xCD20CC20,0};
    static const uint32_t rgb_ocw[6]={0,0x000100C0,0x000000D0,0x000100D0,0x00000C00,0};
    static const uint32_t alpha_icw[6]={0xD1D81010,0,0,0,0,0xD4301010};
    static const uint32_t alpha_ocw[6]={0x000000D0,0,0,0,0,0x000000C0};
    if(PG_REG(NV097_SET_COMBINER_CONTROL)!=0x11106 ||
       (PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)!=1 && PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)!=0x21) ||
       !pgraph_dah2_scene_texture_format(0) || !pgraph_dah2_final_combiner()) return 0;
    if(PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==0x21 && !pgraph_dah2_scene_texture_format(1)) return 0;
    for(unsigned i=0;i<6;i++) if(PG_REG(NV097_SET_COMBINER_COLOR_ICW+i*4)!=rgb_icw[i] ||
        PG_REG(NV097_SET_COMBINER_COLOR_OCW+i*4)!=rgb_ocw[i] ||
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW+i*4)!=alpha_icw[i] ||
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW+i*4)!=alpha_ocw[i]) return 0;
    return 1;
}
static int pgraph_dah2_scene_lit4(void) {
    static const uint32_t rgb_icw[4]={0xC4C80000,0xC9D10000,0xCDD10000,0xCD20CC20};
    static const uint32_t rgb_ocw[4]={0x000100C0,0x000000D0,0x000100D0,0x00000C00};
    static const uint32_t alpha_icw[4]={0,0,0,0xD4D81010};
    static const uint32_t alpha_ocw[4]={0,0,0,0x000000C0};
    if(PG_REG(NV097_SET_COMBINER_CONTROL)!=0x11104 ||
       PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)!=0x21 ||
       !pgraph_dah2_scene_texture_format(0) || !pgraph_dah2_scene_texture_format(1) ||
       !pgraph_dah2_final_combiner()) return 0;
    for(unsigned i=0;i<4;i++) if(PG_REG(NV097_SET_COMBINER_COLOR_ICW+i*4)!=rgb_icw[i] ||
        PG_REG(NV097_SET_COMBINER_COLOR_OCW+i*4)!=rgb_ocw[i] ||
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW+i*4)!=alpha_icw[i] ||
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW+i*4)!=alpha_ocw[i]) return 0;
    return 1;
}
static int pgraph_dah2_scene_textured(void) {
    return PG_REG(NV097_SET_COMBINER_CONTROL)==0x11101 && PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==1 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC4C80000 && PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x000100C0 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD4D81010 && PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0x000000C0 &&
        pgraph_dah2_scene_texture_format(0) && pgraph_dah2_final_combiner();
}
static int pgraph_dah2_scene_untextured(void) {
    return PG_REG(NV097_SET_COMBINER_CONTROL)==0x11102 && PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==0 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC420C020 && PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x00010C00 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD430D030 && PG_REG(NV097_SET_COMBINER_ALPHA_ICW+4)==0xD430D030 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0x00010C00 && PG_REG(NV097_SET_COMBINER_ALPHA_OCW+4)==0x00000C00 &&
        pgraph_dah2_final_combiner();
}

static int pgraph_dah2_scene_generic(void) {
    /* Bisecting switches: DAH2_GENERIC_OFF=1 disables the generic profile; DAH2_GENERIC_NO_OFFSCREEN=1 limits it to full-size targets;
     * DAH2_GENERIC_MIN_VERTS / DAH2_GENERIC_MAX_VERTS bound the draw size (the 4-vertex quads are the post-process passes). */
    static int off=-1,no_offscreen=-1;static unsigned min_verts,max_verts;
    if(off<0) {
        off=getenv("DAH2_GENERIC_OFF")!=NULL;no_offscreen=getenv("DAH2_GENERIC_NO_OFFSCREEN")!=NULL;
        min_verts=getenv("DAH2_GENERIC_MIN_VERTS") ? (unsigned)atoi(getenv("DAH2_GENERIC_MIN_VERTS")) : 0u;
        max_verts=getenv("DAH2_GENERIC_MAX_VERTS") ? (unsigned)atoi(getenv("DAH2_GENERIC_MAX_VERTS")) : 0xFFFFFFFFu;
    }
    if(off || g_pg.index_count<min_verts || g_pg.index_count>max_verts) return 0;
    if(no_offscreen && ((g_pg.surface_clip_h>>16)!=640u || (g_pg.surface_clip_v>>16)!=480u)) return 0;
    unsigned stages=PG_REG(NV097_SET_COMBINER_CONTROL)&15u;
    if(stages<1 || stages>8) return 0;
    uint32_t program=PG_REG(NV097_SET_SHADER_STAGE_PROGRAM);
    for(unsigned s=0;s<4;s++) {
        unsigned mode=(program>>(s*5))&31u;
        if(mode!=0 && mode!=1) return 0; /* 2D only for now (no cube/3D/bump/pass-through stages) */
        if(mode==1 && !(PG_REG(NV097_SET_TEXTURE_CONTROL0+s*0x40)&NV097_SET_TEXTURE_CONTROL0_ENABLE)) return 0;
    }
    return 1;
}

/* The hand-made title bloom profiles (SUBTRACT / ACCUMULATE4) ignored the combiners' "shift right 1" output mapping and therefore
 * blurred twice as bright as retail.  They now run through the generic combiner path; DAH2_LEGACY_POSTPROCESS=1 restores them. */
static int pgraph_legacy_post(void) {
    static int legacy=-1;
    if(legacy<0) legacy=getenv("DAH2_LEGACY_POSTPROCESS")!=NULL;
    return legacy;
}
static int pgraph_dah2_scene_generic(void);

static unsigned pgraph_array_profile(void) {
    if(pgraph_dah2_scene_lit4()) return PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT4;
    if(pgraph_dah2_scene_lit2()) return PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2;
    if(pgraph_dah2_scene_textured()) return PGRAPH_ARRAY_PROFILE_DAH2_SCENE_TEXTURED;
    if(pgraph_dah2_scene_untextured()) return PGRAPH_ARRAY_PROFILE_DAH2_SCENE_UNTEXTURED;
    if (PG_REG(NV097_SET_COMBINER_CONTROL)==0x11101 &&
        PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)==1 &&
        PG_REG(NV097_SET_COMBINER_COLOR_ICW)==0xC4C80000 &&
        PG_REG(NV097_SET_COMBINER_COLOR_OCW)==0x100C0 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_ICW)==0xD4D81010 &&
        PG_REG(NV097_SET_COMBINER_ALPHA_OCW)==0xC0 &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0)==0xE &&
        PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1)==0x1C80 &&
        (PG_REG(NV097_SET_TEXTURE_FORMAT)==0x11229 ||
         PG_REG(NV097_SET_TEXTURE_FORMAT)==0x11D29) &&
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
        return pgraph_legacy_post() ? PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB :
            (pgraph_dah2_scene_generic() ? PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC : PGRAPH_ARRAY_PROFILE_NONE);
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
                PG_REG(NV097_SET_TEXTURE_FILTER+d)!=(stage<=1 ? 0x02023F01u : 0x02022000u) ||
                PG_REG(NV097_SET_TEXTURE_CONTROL1+d)!=0x05000000 ||
                PG_REG(NV097_SET_TEXTURE_IMAGE_RECT+d)!=0x014000F0)
                return PGRAPH_ARRAY_PROFILE_NONE;
        }
        return pgraph_legacy_post() ? PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB :
            (pgraph_dah2_scene_generic() ? PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC : PGRAPH_ARRAY_PROFILE_NONE);
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
    return pgraph_dah2_scene_generic() ? PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC : PGRAPH_ARRAY_PROFILE_NONE;
}

static uint32_t pgraph_supported_array_state(unsigned profile) {
    const uint32_t pairs[][2]={
        {NV097_SET_TRANSFORM_EXECUTION_MODE,6}, {NV097_SET_TRANSFORM_PROGRAM_CXT_WRITE_EN,0},
        {NV097_SET_CONTEXT_DMA_A,3}, {NV097_SET_CONTEXT_DMA_VERTEX_A,3},
        {NV097_SET_CONTEXT_DMA_VERTEX_B,3},
        {NV097_SET_POLY_OFFSET_FILL_ENABLE,0}, {NV097_SET_SHADE_MODE,0x1D01},
        {NV097_SET_FRONT_POLYGON_MODE,0x1B02}, {NV097_SET_BACK_POLYGON_MODE,0x1B02},
        {NV097_SET_CLIP_MIN,0},
        {NV097_SET_CLIP_MAX,0x4B7FFFFF}
    };
    for (unsigned i=0;i<sizeof(pairs)/sizeof(pairs[0]);i++)
        if (PG_REG(pairs[i][0])!=pairs[i][1]) return pairs[i][0];
    if (PG_REG(NV097_SET_SURFACE_FORMAT)!=0x124u &&
        !(profile==PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC && PG_REG(NV097_SET_SURFACE_FORMAT)==0x128u) &&
        !(g_pg.index_source==3u && !g_pg.depth_test &&
          PG_REG(NV097_SET_SURFACE_FORMAT)==0x128u))
        return NV097_SET_SURFACE_FORMAT;
    if (profile<PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 && PG_REG(NV097_SET_STENCIL_TEST_ENABLE)) return NV097_SET_STENCIL_TEST_ENABLE;
    if (g_pg.blend_enable) { uint32_t equation=PG_REG(NV097_SET_BLEND_EQUATION);
      if(equation!=0x8006 && equation!=0x8007 && equation!=0x8008 && equation!=0x800A && equation!=0x800B)
          return NV097_SET_BLEND_EQUATION; }
    if (PG_REG(NV097_SET_FOG_ENABLE)>1 || (PG_REG(NV097_SET_FOG_ENABLE) &&
        PG_REG(NV097_SET_FOG_MODE)!=NV097_SET_FOG_MODE_V_LINEAR && PG_REG(NV097_SET_FOG_MODE)!=NV097_SET_FOG_MODE_V_LINEAR_ABS &&
        PG_REG(NV097_SET_FOG_MODE)!=NV097_SET_FOG_MODE_V_EXP && PG_REG(NV097_SET_FOG_MODE)!=NV097_SET_FOG_MODE_V_EXP2 &&
        PG_REG(NV097_SET_FOG_MODE)!=NV097_SET_FOG_MODE_V_EXP_ABS && PG_REG(NV097_SET_FOG_MODE)!=NV097_SET_FOG_MODE_V_EXP2_ABS))
        return NV097_SET_FOG_MODE;
    if (!profile) return NV097_SET_COMBINER_CONTROL;
    if (profile!=PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB && profile!=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC)
        for (unsigned stage=((profile==PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 ||
            profile==PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT4) ? 2u : 1u);stage<4;stage++)
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
    if (profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        unsigned gw=g_pg.surface_clip_h>>16,gh=g_pg.surface_clip_v>>16;
        if ((g_pg.surface_clip_h&0xFFFF) || (g_pg.surface_clip_v&0xFFFF) || !gw || !gh || gw>2048 || gh>2048)
            return NV097_SET_SURFACE_CLIP_HORIZONTAL;
    } else if (profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB ||
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
    if (profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        /* A window clip narrower than the surface becomes a host scissor rectangle (set around the draw). */
        if (PG_REG(NV097_SET_WINDOW_CLIP_TYPE)) return NV097_SET_WINDOW_CLIP_TYPE;
        /* Only window-clip rectangle 0 is programmed by the title; rectangles 1..7 stay at their reset value. */
        return 0;
    }
    if (PG_REG(NV097_SET_WINDOW_CLIP_HORIZONTAL)!=g_pg.surface_clip_h ||
        PG_REG(NV097_SET_WINDOW_CLIP_VERTICAL)!=g_pg.surface_clip_v || PG_REG(NV097_SET_WINDOW_CLIP_TYPE))
        return NV097_SET_WINDOW_CLIP_HORIZONTAL;
    return 0;
}

static int pgraph_read_vertex(uint32_t index,unsigned attributes,NV2AVertexResult *result,
    unsigned telemetry_slot,const NV2AVPPreparedProgram *prepared) {
    volatile uint32_t *failure=g_dah2_pgraph_draw_memory_failures[telemetry_slot];
    failure[0]=index;failure[1]=0xFFFFFFFFu;failure[2]=0;failure[3]=0;failure[4]=0;failure[5]=0;
    float input[NV2A_VP_ATTRIBUTES][4]={{0}};
    if(g_pg.index_source==3u) {
        /* Disabled inline attributes are persistent NV2A current values. That
         * state is not tracked yet, so admit only shaders whose inputs are all
         * supplied by this inline payload. Never substitute an invented value. */
        unsigned missing=attributes&~g_pg_inline_layout.enabled_mask;
        if(missing) {
            unsigned a=0;while(!(missing&(1u<<a)))a++;
            failure[1]=a;failure[2]=g_pg_inline_layout.formats[a];failure[5]=1;return 0;
        }
        unsigned bad;
        NV2AVPStatus decode_status=nv2a_inline_array_read(&g_pg_inline_layout,
            g_pg.inline_data,g_pg.inline_count,index,input,&bad);
        if(decode_status!=NV2A_VP_OK) {
            failure[1]=bad;
            if(bad<NV2A_VP_ATTRIBUTES) {
                failure[2]=g_pg_inline_layout.formats[bad];
                failure[3]=index*g_pg_inline_layout.stride_bytes+g_pg_inline_layout.offsets[bad];
                failure[4]=(g_pg_inline_layout.stride_bytes<<16)|g_pg_inline_layout.bytes[bad];
            }
            failure[5]=0x10u+(uint32_t)decode_status;return 0;
        }
    } else {
        for (unsigned a=0;a<NV2A_VP_ATTRIBUTES;a++) {
            input[a][3]=1;
            if (!(attributes&(1u<<a))) continue;
            uint32_t format=PG_REG(NV097_SET_VERTEX_DATA_ARRAY_FORMAT+a*4);failure[1]=a;failure[2]=format;
            unsigned count=(format>>4)&15,type=format&15,stride=(format>>8)&255;
            if (type==6) count=3;
            unsigned bytes=type==2 ? count*4 : (type==1 || type==5) ? count*2 : type==4 ? count : 4;
            if (!count || count>4 || (type!=2 && type!=1 && type!=4 && type!=5 && type!=6 && !(type==0 && count==4))) { failure[5]=1;return 0; }
            uint32_t base=PG_REG(NV097_SET_VERTEX_DATA_ARRAY_OFFSET+a*4)&0x7FFFFFFF;
            uint64_t address=(uint64_t)base+(uint64_t)index*stride;
            failure[3]=(uint32_t)address;failure[4]=(stride<<16)|bytes;
            unsigned char data[16];
            if (address+bytes>0x100000000ULL) { failure[5]=2;return 0; }
            if (!g_pg_guest_reader || !g_pg_guest_reader((uint32_t)address,data,bytes)) { failure[5]=3;return 0; }
            NV2AVPStatus decode_status=nv2a_vp_decode_attribute(format,data,bytes,input[a]);
            if (decode_status!=NV2A_VP_OK) { failure[5]=0x10u+(uint32_t)decode_status;return 0; }
        }
    }
    NV2AVPStatus execute_status=nv2a_vp_execute_prepared(prepared,input,g_pg.constants,result);
    if(execute_status!=NV2A_VP_OK){
        failure[5]=0x20u+(uint32_t)execute_status;
        failure[6]=(uint32_t)nv2a_vp_last_error_slot;
        failure[7]=(uint32_t)nv2a_vp_last_error_source;
        failure[8]=(uint32_t)nv2a_vp_last_error_constant;
        failure[9]=(uint32_t)nv2a_vp_last_error_a0;
        failure[10]=(uint32_t)nv2a_vp_last_error_index;
        return 0;
    }
    if (getenv("DAH2_VP_VERTEX_DIAGNOSTIC") && g_pg.stats.frames>=1350) {
        static unsigned reports;
        if (reports<2) {
            fprintf(stderr,"[PGRAPH-VP-VERTEX] index=%u attributes=%08X",index,attributes);
            for(unsigned a=0;a<NV2A_VP_ATTRIBUTES;a++) if(attributes&(1u<<a))
                fprintf(stderr," v%u=%.9g,%.9g,%.9g,%.9g",a,input[a][0],input[a][1],input[a][2],input[a][3]);
            fprintf(stderr," oPos=%.9g,%.9g,%.9g,%.9g\n",result->output[0][0],result->output[0][1],result->output[0][2],result->output[0][3]);
            reports++;
        }
    }
    failure[5]=0;return 1;
}

typedef struct {
    float x,y,z,rhw;uint32_t diffuse,specular;float u0,v0,u1,v1,u2,v2,u3,v3;
} PgraphSceneVertex;

/* Linear (unnormalised) NV2A textures carry texel coordinates; D3D samples with 0..1.  Set per draw before vertices are packed. */
static float g_pg_stage_scale[4][2]={{1,1},{1,1},{1,1},{1,1}}; /* specular.a carries the NV2A fog factor (oFog through the fog mode; 255 = unfogged) */

/* Fog factor from the vertex program's oFog.x, after xemu's glsl/vsh.c: the programmable pipeline feeds oFog.x through the
 * fog mode and FOG_PARAMS; the pixel side clamps it to 0..1 and uses it as the FOG register alpha of the final combiner. */
static float pgraph_fog_factor(float coord) {
    if(!PG_REG(NV097_SET_FOG_ENABLE)) return 1.0f;
    float p0=u2f(PG_REG(NV097_SET_FOG_PARAMS)),p1=u2f(PG_REG(NV097_SET_FOG_PARAMS+4));
    float f;
    switch(PG_REG(NV097_SET_FOG_MODE)) {
    case NV097_SET_FOG_MODE_V_LINEAR: case NV097_SET_FOG_MODE_V_LINEAR_ABS:
        f=p0+coord*p1-1.0f;break;
    case NV097_SET_FOG_MODE_V_EXP: case NV097_SET_FOG_MODE_V_EXP_ABS:
        f=p0+exp2f(coord*p1*16.0f)-1.5f;break;
    case NV097_SET_FOG_MODE_V_EXP2: case NV097_SET_FOG_MODE_V_EXP2_ABS:
        f=p0+exp2f(-coord*coord*p1*p1*32.0f)-1.5f;break;
    default: f=1.0f;
    }
    uint32_t m=PG_REG(NV097_SET_FOG_MODE);
    if(m==NV097_SET_FOG_MODE_V_LINEAR_ABS || m==NV097_SET_FOG_MODE_V_EXP_ABS || m==NV097_SET_FOG_MODE_V_EXP2_ABS) f=fabsf(f);
    if(!(f==f)) f=1.0f;
    return fminf(1.0f,fmaxf(0.0f,f));
}

static int pgraph_pack_scene_vertex(const NV2AVertexResult *r,PgraphSceneVertex *v) {
    if(r->written_mask[0]!=15) return 0;
    float w=r->output[0][3];
    if(!isfinite(r->output[0][0]) || !isfinite(r->output[0][1]) ||
       !isfinite(r->output[0][2]) || !isfinite(w) || w==0) {
        /* NV2A carries exceptional vertex results through clipping.  Keep the
         * strip alive with an off-screen sentinel instead of rejecting the
         * complete draw and losing later valid triangles. */
        v->x=-1000000.0f;v->y=-1000000.0f;v->z=1.0f;v->rhw=1.0f;
        v->diffuse=0;v->specular=0;v->u0=0;v->v0=0;v->u1=0;v->v1=0;v->u2=0;v->v2=0;v->u3=0;v->v3=0;
        return 1;
    }
    float inv=1.0f/w;
    /* xemu's programmable path treats guest oPos as post-viewport screen
     * coordinates, truncates XY to 1/16 pixel, and normalizes guest Z by the
     * active clip range. W remains reciprocal-W for interpolation. */
    v->x=truncf(r->output[0][0]*16.0f)/16.0f;
    v->y=truncf(r->output[0][1]*16.0f)/16.0f;
    v->z=r->output[0][2]/u2f(PG_REG(NV097_SET_CLIP_MAX));
    v->rhw=inv;uint32_t color[4];
    for(unsigned c=0;c<4;c++) {
        float component=isnan(r->output[3][c]) || !(r->written_mask[3]&(8u>>c)) ? 1.0f : r->output[3][c];
        color[c]=(uint32_t)floorf(fminf(1,fmaxf(0,component))*255.0f+0.5f);
    }
    v->diffuse=(color[3]<<24)|(color[0]<<16)|(color[1]<<8)|color[2];
    { uint32_t spec[3]={0,0,0};
      if(r->written_mask[4]) for(unsigned c=0;c<3;c++) {
          float component=isfinite(r->output[4][c]) ? r->output[4][c] : 0.0f;
          spec[c]=(uint32_t)floorf(fminf(1,fmaxf(0,component))*255.0f+0.5f);
      }
      float fog=(r->written_mask[5]&8) && isfinite(r->output[5][0]) ? pgraph_fog_factor(r->output[5][0]) : 1.0f;
      v->specular=((uint32_t)floorf(fog*255.0f+0.5f)<<24)|(spec[0]<<16)|(spec[1]<<8)|spec[2]; }
    { float *uv[4]={&v->u0,&v->u1,&v->u2,&v->u3};
      float *vv[4]={&v->v0,&v->v1,&v->v2,&v->v3};
      for(unsigned s=0;s<4;s++) {
          unsigned o=9+s;
          *uv[s]=(r->written_mask[o]&8) && isfinite(r->output[o][0]) ? r->output[o][0]*g_pg_stage_scale[s][0] : 0;
          *vv[s]=(r->written_mask[o]&4) && isfinite(r->output[o][1]) ? r->output[o][1]*g_pg_stage_scale[s][1] : 0;
      } }
    return isfinite(v->x)&&isfinite(v->y)&&isfinite(v->z)&&isfinite(v->rhw);
}

static int pgraph_pack_vertex(const NV2AVertexResult *r,OutputVertex *v,unsigned tw,unsigned th,int texel_coords) {
    if (r->written_mask[0]!=15 || r->written_mask[3]!=15 || r->written_mask[9]!=15) return 0;
    for (unsigned o=0;o<NV2A_VP_OUTPUTS;o++)for(unsigned c=0;c<4;c++)
        if (!isfinite(r->output[o][c])) return 0;
    /* Indexed 2D draws retain the verified affine restriction. Programmable
     * inline vertices use the captured post-viewport Z and reciprocal W. */
    int inline_position=g_pg.index_source==3u;
    if ((!inline_position && (r->output[0][3]!=1 || r->output[0][2]!=0)) ||
        (inline_position && !(r->output[0][3]>0)) ||
        r->output[4][0]!=0 || r->output[4][1]!=0 || r->output[4][2]!=0) return 0;
    v->x=truncf(r->output[0][0]*16.0f)/16.0f;
    v->y=truncf(r->output[0][1]*16.0f)/16.0f;
    /* xemu's programmable output is post-viewport: undoing perspective
     * before GL restores the same XY/Z after division. D3D XYZRHW consumes
     * that screen-space Z and reciprocal W directly. */
    v->z=inline_position ? r->output[0][2]/u2f(PG_REG(NV097_SET_CLIP_MAX)) : 0;
    v->rhw=inline_position ? 1.0f/r->output[0][3] : 1;
    if(!isfinite(v->z) || !isfinite(v->rhw)) return 0;
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
    for (unsigned i=0;i<PGRAPH_SURFACE_SLOTS;i++)
        if (g_pg.array_surfaces[i].texture && g_pg.array_surfaces[i].guest_offset==guest_offset)
            return (int)i;
    return -1;
}

static int pgraph_depth_index(uint32_t guest_offset,unsigned width,unsigned height) {
    for (unsigned i=0;i<PGRAPH_SURFACE_SLOTS;i++)
        if (g_pg.array_depths[i].dsv &&
            g_pg.array_depths[i].guest_offset==guest_offset &&
            g_pg.array_depths[i].width==width &&
            g_pg.array_depths[i].height==height)
            return (int)i;
    return -1;
}

static int pgraph_ensure_depth(uint32_t guest_offset,unsigned width,unsigned height) {
    int existing=pgraph_depth_index(guest_offset,width,height);
    if (existing>=0) return existing;
    unsigned slot;
    for (slot=0;slot<PGRAPH_SURFACE_SLOTS;slot++) if (!g_pg.array_depths[slot].dsv) break;
    if (slot==PGRAPH_SURFACE_SLOTS || !width || !height) return -1;
    D3D11_TEXTURE2D_DESC desc={0};
    desc.Width=width;desc.Height=height;desc.MipLevels=1;desc.ArraySize=1;
    desc.Format=DXGI_FORMAT_D24_UNORM_S8_UINT;desc.SampleDesc.Count=1;
    desc.Usage=D3D11_USAGE_DEFAULT;desc.BindFlags=D3D11_BIND_DEPTH_STENCIL;
    ID3D11Texture2D *depth=NULL;ID3D11DepthStencilView *dsv=NULL;
    if (FAILED(ID3D11Device_CreateTexture2D(d3d8_GetD3D11Device(),&desc,NULL,&depth)) ||
        !depth || FAILED(ID3D11Device_CreateDepthStencilView(d3d8_GetD3D11Device(),
        (ID3D11Resource *)depth,NULL,&dsv)) || !dsv) {
        if (dsv) ID3D11DepthStencilView_Release(dsv);
        if (depth) ID3D11Texture2D_Release(depth);
        return -1;
    }
    ID3D11DeviceContext_ClearDepthStencilView(d3d8_GetD3D11Context(),dsv,
        D3D11_CLEAR_DEPTH|D3D11_CLEAR_STENCIL,1.0f,0);
    g_pg.array_depths[slot].guest_offset=guest_offset;
    g_pg.array_depths[slot].width=width;g_pg.array_depths[slot].height=height;
    g_pg.array_depths[slot].depth=depth;g_pg.array_depths[slot].dsv=dsv;
    fprintf(stderr,"[PGRAPH-ZETA] create slot=%u guest=%08X size=%ux%u\n",
        slot,guest_offset,width,height);
    return (int)slot;
}

static int pgraph_bind_surface_depth(unsigned surface_slot,uint32_t guest_offset,
    unsigned width,unsigned height) {
    if (g_pg.array_surfaces[surface_slot].dsv &&
        g_pg.array_surfaces[surface_slot].zeta_offset==guest_offset) return 0;
    int depth_slot=pgraph_ensure_depth(guest_offset,width,height);
    if (depth_slot<0) return PGRAPH_REJECT_DEVICE;
    ID3D11Texture2D *depth=g_pg.array_depths[depth_slot].depth;
    ID3D11DepthStencilView *dsv=g_pg.array_depths[depth_slot].dsv;
    ID3D11Texture2D_AddRef(depth);ID3D11DepthStencilView_AddRef(dsv);
    if (g_pg.array_surfaces[surface_slot].dsv)
        ID3D11DepthStencilView_Release(g_pg.array_surfaces[surface_slot].dsv);
    if (g_pg.array_surfaces[surface_slot].depth)
        ID3D11Texture2D_Release(g_pg.array_surfaces[surface_slot].depth);
    g_pg.array_surfaces[surface_slot].zeta_offset=guest_offset;
    g_pg.array_surfaces[surface_slot].depth=depth;
    g_pg.array_surfaces[surface_slot].dsv=dsv;
    return 0;
}

static void pgraph_release_surface(unsigned slot) {
    if (g_pg.array_surfaces[slot].dsv) ID3D11DepthStencilView_Release(g_pg.array_surfaces[slot].dsv);
    if (g_pg.array_surfaces[slot].depth) ID3D11Texture2D_Release(g_pg.array_surfaces[slot].depth);
    if (g_pg.array_surfaces[slot].rtv) ID3D11RenderTargetView_Release(g_pg.array_surfaces[slot].rtv);
    if (g_pg.array_surfaces[slot].texture) g_pg.array_surfaces[slot].texture->lpVtbl->Release(g_pg.array_surfaces[slot].texture);
    memset(&g_pg.array_surfaces[slot],0,sizeof(g_pg.array_surfaces[slot]));
}

static int pgraph_ensure_surface(IDirect3DDevice8 *dev,uint32_t guest_offset,
    unsigned width,unsigned height,unsigned guest_pitch) {
    int existing=pgraph_surface_index(guest_offset);
    if (existing>=0) {
        /* A smaller surface clip is only a draw rectangle inside the same target; the target is re-created only when the guest
         * needs more room than it has (the offset was reused for a larger render target). */
        if (width>g_pg.array_surfaces[existing].width || height>g_pg.array_surfaces[existing].height) {
            pgraph_release_surface((unsigned)existing);
            existing=-1;
        } else
        return pgraph_bind_surface_depth((unsigned)existing,
            PG_REG(NV097_SET_SURFACE_ZETA_OFFSET),g_pg.array_surfaces[existing].width,
            g_pg.array_surfaces[existing].height) ? -1 : existing;
    }
    if (guest_pitch/4u>width && guest_pitch/4u<=2048u) width=guest_pitch/4u;
    unsigned slot;
    for (slot=0;slot<PGRAPH_SURFACE_SLOTS;slot++) if (!g_pg.array_surfaces[slot].texture) break;
    if (slot==PGRAPH_SURFACE_SLOTS || !width || !height) return -1;
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
    uint32_t zeta_offset=PG_REG(NV097_SET_SURFACE_ZETA_OFFSET);
    int depth_slot=pgraph_ensure_depth(zeta_offset,width,height);
    if (depth_slot<0) {
        ID3D11RenderTargetView_Release(rtv);texture->lpVtbl->Release(texture);return -1;
    }
    ID3D11Texture2D *depth=g_pg.array_depths[depth_slot].depth;
    ID3D11DepthStencilView *dsv=g_pg.array_depths[depth_slot].dsv;
    ID3D11Texture2D_AddRef(depth);ID3D11DepthStencilView_AddRef(dsv);
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
    g_pg.array_surfaces[slot].zeta_offset=zeta_offset;
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

static void pgraph_report_surface(uint32_t guest_offset,const char *label);

/* The guest clears depth/stencil inside a rectangle (the radar disc, HUD panels) while the rest of the world depth must survive.
 * D3D11 cannot clear a sub-rect of a DSV, so draw a depth-writing (and stencil-replacing) quad under a scissor instead.
 * Returns 1 if handled; 0 means the clear covers the whole target (or the device refused) and the full clear applies. */
static int pgraph_clear_depth_rect(uint32_t flags,float depth,unsigned stencil) {
    unsigned xmin=g_pg.clear_rect_h&0xFFFFu,xmax=g_pg.clear_rect_h>>16;
    unsigned ymin=g_pg.clear_rect_v&0xFFFFu,ymax=g_pg.clear_rect_v>>16;
    int slot=pgraph_surface_index(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
    IDirect3DDevice8 *dev=xbox_GetD3DDevice();
    if(slot<0 || !dev || getenv("DAH2_NO_RECT_CLEAR")) return 0;
    unsigned sw=g_pg.array_surfaces[slot].width,sh=g_pg.array_surfaces[slot].height;
    if(xmax<xmin || ymax<ymin) return 1;
    if(xmin==0 && ymin==0 && xmax+1>=sw && ymax+1>=sh) return 0;
    if(xmax+1>sw) xmax=sw-1;
    if(ymax+1>sh) ymax=sh-1;
    if(pgraph_bind_array_target(dev)) return 0;
    D3DVIEWPORT8 viewport={0,0,sw,sh,0,1};
    struct { float x,y,z,rhw; DWORD color; } quad[4]={
        {(float)xmin,(float)ymin,depth,1.0f,0},{(float)(xmax+1),(float)ymin,depth,1.0f,0},
        {(float)xmin,(float)(ymax+1),depth,1.0f,0},{(float)(xmax+1),(float)(ymax+1),depth,1.0f,0}};
    dev->lpVtbl->SetViewport(dev,&viewport);
    dev->lpVtbl->SetPixelShader(dev,0);
    dev->lpVtbl->SetVertexShader(dev,D3DFVF_XYZRHW|D3DFVF_DIFFUSE);
    for(unsigned s=0;s<4;s++) dev->lpVtbl->SetTexture(dev,s,NULL);
    dev->lpVtbl->SetRenderState(dev,D3DRS_LIGHTING,FALSE);
    dev->lpVtbl->SetRenderState(dev,D3DRS_FOGENABLE,FALSE);
    dev->lpVtbl->SetRenderState(dev,D3DRS_CULLMODE,D3DCULL_NONE);
    dev->lpVtbl->SetRenderState(dev,D3DRS_ALPHATESTENABLE,FALSE);
    dev->lpVtbl->SetRenderState(dev,D3DRS_ALPHABLENDENABLE,FALSE);
    dev->lpVtbl->SetRenderState(dev,D3DRS_COLORWRITEENABLE,0);
    dev->lpVtbl->SetRenderState(dev,D3DRS_ZENABLE,TRUE);
    dev->lpVtbl->SetRenderState(dev,D3DRS_ZFUNC,8 /* D3DCMP_ALWAYS */);
    dev->lpVtbl->SetRenderState(dev,D3DRS_ZWRITEENABLE,(flags&1)!=0);
    dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILENABLE,(flags&2)!=0);
    if(flags&2) {
        dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILFUNC,8);
        dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILREF,stencil&255u);
        dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILMASK,255u);
        dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILWRITEMASK,255u);
        dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILFAIL,3);
        dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILZFAIL,3);
        dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILPASS,3 /* D3DSTENCILOP_REPLACE */);
    }
    d3d8_states_set_scissor(1,(int)xmin,(int)ymin,(int)xmax+1,(int)ymax+1);
    if(SUCCEEDED(dev->lpVtbl->BeginScene(dev))) {
        dev->lpVtbl->DrawPrimitiveUP(dev,D3DPT_TRIANGLESTRIP,2,quad,(UINT)sizeof(quad[0]));
        dev->lpVtbl->EndScene(dev);
    }
    d3d8_states_set_scissor(0,0,0,0,0);
    dev->lpVtbl->SetRenderState(dev,D3DRS_STENCILENABLE,FALSE);
    return 1;
}

static void pgraph_clear_array_target(uint32_t flags,uint32_t color) {
    if(flags&1) g_pg.pending_scene_depth_replay=1;
    int slot=pgraph_surface_index(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
    if (slot<0) return;
    if(getenv("DAH2_DEPTH_CLEAR_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN")) {
        fprintf(stdout,
            "[PGRAPH-CLEAR] frame=%u target=%08X boundZeta=%08X guestZeta=%08X "
            "flags=%08X packed=%08X format=%08X rectH=%08X rectV=%08X\n",
            g_pg.stats.frames,PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),
            g_pg.array_surfaces[slot].zeta_offset,PG_REG(NV097_SET_SURFACE_ZETA_OFFSET),
            flags,PG_REG(NV097_SET_ZSTENCIL_CLEAR_VALUE),
            PG_REG(NV097_SET_SURFACE_FORMAT),g_pg.clear_rect_h,g_pg.clear_rect_v);
        fflush(stdout);
    }    if(getenv("DAH2_DEPTH_CLEAR_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN")) {
        fprintf(stdout,"[PGRAPH-CLEAR-DSV] frame=%u dsv=%p depth=%p size=%ux%u\n",
            g_pg.stats.frames,(void *)g_pg.array_surfaces[slot].dsv,
            (void *)g_pg.array_surfaces[slot].depth,
            g_pg.array_surfaces[slot].width,g_pg.array_surfaces[slot].height);
        fflush(stdout);
    }    if(getenv("DAH2_SURFACE_TIMELINE_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN") &&
       g_pg.stats.frames>=1348u && g_pg.stats.frames<=1350u) {
        fprintf(stdout,"[PGRAPH-CLEAR-TIMELINE] frame=%u target=%08X zeta=%08X flags=%08X color=%08X\n",
            g_pg.stats.frames,PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),
            PG_REG(NV097_SET_SURFACE_ZETA_OFFSET),flags,color);
        fflush(stdout);
    }
    if(getenv("DAH2_SURFACE_TIMELINE_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN"))
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"clear-before");
    { static int dump_lo=-2,dump_hi=-2;
      if(dump_lo==-2) { const char *e=getenv("DAH2_DRAW_DUMP"); dump_lo=dump_hi=-1; if(e) sscanf(e,"%d,%d",&dump_lo,&dump_hi); }
      if(dump_lo>=0 && (int)g_pg.stats.frames>=dump_lo && (int)g_pg.stats.frames<=dump_hi) {
          fprintf(stdout,"[PGRAPH-CLR] f=%u flags=%02X packed=%08X rectH=%08X rectV=%08X tgt=%08X" "\n",g_pg.stats.frames,flags,
              PG_REG(NV097_SET_ZSTENCIL_CLEAR_VALUE),g_pg.clear_rect_h,g_pg.clear_rect_v,PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
          fflush(stdout); } }
    ID3D11DeviceContext *context=d3d8_GetD3D11Context();
    if (flags&0xF0) {
        float rgba[4]={((color>>16)&255)/255.0f,((color>>8)&255)/255.0f,
            (color&255)/255.0f,((color>>24)&255)/255.0f};
        ID3D11DeviceContext_ClearRenderTargetView(context,g_pg.array_surfaces[slot].rtv,rgba);
    }
    if (flags&3) {
        UINT clear_flags=0;
        uint32_t packed=PG_REG(NV097_SET_ZSTENCIL_CLEAR_VALUE);
        unsigned zeta=(PG_REG(NV097_SET_SURFACE_FORMAT)&NV097_SET_SURFACE_FORMAT_ZETA)>>4;
        float clear_depth=1.0f;
        UINT8 clear_stencil=0;
        if (zeta==NV097_SET_SURFACE_FORMAT_ZETA_Z24S8) {
            clear_depth=(packed>>8)/(float)0xFFFFFFu;
            clear_stencil=(UINT8)(packed&0xFFu);
        } else if (zeta==NV097_SET_SURFACE_FORMAT_ZETA_Z16) {
            clear_depth=(packed&0xFFFFu)/(float)0xFFFFu;
        }
        if (flags&1) clear_flags|=D3D11_CLEAR_DEPTH;
        if (flags&2) clear_flags|=D3D11_CLEAR_STENCIL;
        if (pgraph_clear_depth_rect(flags&3u,clear_depth,clear_stencil)) {
            if(getenv("DAH2_SURFACE_TIMELINE_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN"))
                pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"clear-after");
            return;
        }
        ID3D11DeviceContext_ClearDepthStencilView(context,g_pg.array_surfaces[slot].dsv,
            clear_flags,clear_depth,clear_stencil);
        int depth_slot=pgraph_depth_index(PG_REG(NV097_SET_SURFACE_ZETA_OFFSET),
            g_pg.array_surfaces[slot].width,g_pg.array_surfaces[slot].height);
        if(depth_slot>=0) {
            /* Replay the combined D24S8 transition at first draw bind.  The
             * guest stencil clear already ran at command time and supported
             * DAH2 scene profiles keep stencil testing disabled, so a neutral
             * stencil payload is sufficient for the host transition. */
            g_pg.array_depths[depth_slot].pending_clear_flags=clear_flags;
            g_pg.array_depths[depth_slot].pending_clear_depth=clear_depth;
            g_pg.array_depths[depth_slot].pending_clear_stencil=0;
            if(getenv("DAH2_DEPTH_CLEAR_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN")) {
                fprintf(stdout,"[PGRAPH-PENDING-SET] frame=%u slot=%d flags=%08X depth=%.9g\n",
                    g_pg.stats.frames,depth_slot,
                    g_pg.array_depths[depth_slot].pending_clear_flags,
                    g_pg.array_depths[depth_slot].pending_clear_depth);
                fflush(stdout);
            }
        }
        if(getenv("DAH2_GUEST_CLEAR_REPLAY_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN"))
            ID3D11DeviceContext_ClearDepthStencilView(context,g_pg.array_surfaces[slot].dsv,
                D3D11_CLEAR_DEPTH|D3D11_CLEAR_STENCIL,1.0f,0);
    }
    if(getenv("DAH2_SURFACE_TIMELINE_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN"))
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"clear-after");
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
    static unsigned reports,isolated_reports,timeline_reports,postprocess_reports;
    int isolated=label && !strcmp(label,"isolated-scene");
    int timeline=label && (!strcmp(label,"draw-after") ||
        !strcmp(label,"clear-before") || !strcmp(label,"clear-after"));
    int postprocess=label && !strncmp(label,"post-",5);
    if(isolated && g_pg.stats.frames<1350u) return;
    if(timeline && g_pg.stats.frames!=1350u) return;
    int slot=pgraph_surface_index(guest_offset);
    if ((!isolated && !timeline && !postprocess && reports>=20) ||
        (isolated && isolated_reports>=8) || (timeline && timeline_reports>=128) ||
        (postprocess && postprocess_reports>=64) || slot<0) return;
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
        unsigned long long nonblack=0,not_red=0,above_threshold=0;
        unsigned max_r=0,max_g=0,max_b=0,max_a=0;
        for (unsigned y=0;y<desc.Height;y++) {
            const uint32_t *row=(const uint32_t *)((const unsigned char *)mapped.pData+(size_t)y*mapped.RowPitch);
            for (unsigned x=0;x<desc.Width;x++) {
                uint32_t rgb=row[x]&0x00FFFFFFu;
                nonblack+=rgb!=0;not_red+=rgb!=0x000000FFu;
                unsigned b=rgb&255u,g=(rgb>>8)&255u,r=(rgb>>16)&255u,a=row[x]>>24;
                if(r>max_r) max_r=r;if(g>max_g) max_g=g;
                if(b>max_b) max_b=b;if(a>max_a) max_a=a;
                above_threshold+=(r>127u || g>127u || b>127u);
            }
        }
        unsigned bound_cull=UINT_MAX,bound_depth_clip=UINT_MAX;
        if(isolated) {
            ID3D11RasterizerState *bound_raster=NULL;
            ID3D11DeviceContext_RSGetState(d3d8_GetD3D11Context(),&bound_raster);
            if(bound_raster) {
                D3D11_RASTERIZER_DESC bound_desc;
                ID3D11RasterizerState_GetDesc(bound_raster,&bound_desc);
                bound_cull=(unsigned)bound_desc.CullMode;
                bound_depth_clip=(unsigned)bound_desc.DepthClipEnable;
                ID3D11RasterizerState_Release(bound_raster);
            }
        }
        FILE *report_stream=(isolated || timeline || postprocess) ? stdout : stderr;
        if(postprocess)
            fprintf(report_stream,"[PGRAPH-POST-SURFACE] frame=%u event=%s guest=%08X source=%08X size=%ux%u nonblack=%llu above127=%llu max=%u,%u,%u,%u\n",
                g_pg.stats.frames,label,guest_offset,PG_REG(NV097_SET_TEXTURE_OFFSET),
                desc.Width,desc.Height,nonblack,above_threshold,max_r,max_g,max_b,max_a);
        else if(timeline)
            fprintf(report_stream,"[PGRAPH-SURFACE-TIMELINE] frame=%u event=%s guest=%08X source=%08X mode=%u count=%u size=%ux%u nonblack=%llu notRed=%llu\n",
                g_pg.stats.frames,label,guest_offset,PG_REG(NV097_SET_TEXTURE_OFFSET),
                g_pg.draw_mode,g_pg.index_count,desc.Width,desc.Height,nonblack,not_red);
        else
            fprintf(report_stream,"[PGRAPH-SURFACE-CONTENT] %s guest=%08X size=%ux%u nonblack=%llu notRed=%llu cull=%u depthClip=%u\n",
                label,guest_offset,desc.Width,desc.Height,nonblack,not_red,bound_cull,bound_depth_clip);
        fflush(report_stream);
        ID3D11DeviceContext_Unmap(d3d8_GetD3D11Context(),(ID3D11Resource *)staging,0);
        if(isolated) isolated_reports++; else if(timeline) timeline_reports++;
        else if(postprocess) postprocess_reports++; else reports++;
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
    unsigned color=(PG_REG(NV097_SET_TEXTURE_FORMAT)>>8)&0xFFu;
    unsigned source_bpp=color==NV097_SET_TEXTURE_FORMAT_COLOR_LU_IMAGE_A4R4G4B4 ? 2u : 4u;
    uint64_t span=(uint64_t)(height-1)*pitch+width*source_bpp;
    size_t size=(size_t)width*height*4;
    if (!g_pg_guest_reader || (uint64_t)address+span>0x100000000ULL) return PGRAPH_REJECT_MEMORY;
    unsigned char *data=(unsigned char *)malloc(size);
    if (!data) return PGRAPH_REJECT_LIMIT;
    if(source_bpp==2u) {
        uint16_t *row=(uint16_t *)malloc((size_t)width*2u);
        if(!row){free(data);return PGRAPH_REJECT_LIMIT;}
        uint32_t *pixels=(uint32_t *)data;
        for(unsigned y=0;y<height;y++) {
            if(!g_pg_guest_reader(address+y*pitch,row,width*2u)) {
                free(row);free(data);return PGRAPH_REJECT_MEMORY;
            }
            for(unsigned x=0;x<width;x++) {
                uint32_t value=row[x];
                uint32_t a=((value>>12)&15u)*17u,r=((value>>8)&15u)*17u;
                uint32_t g=((value>>4)&15u)*17u,b=(value&15u)*17u;
                pixels[(size_t)y*width+x]=(a<<24)|(r<<16)|(g<<8)|b;
            }
        }
        free(row);
    } else for (unsigned y=0;y<height;y++) {
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

/* Textures that must survive eviction while a draw's other stages are being uploaded. */
static IDirect3DTexture8 *g_pg_scene_protect[4];

/* Decode an uncompressed NV2A texture (swizzled or linear) to host A8R8G8B8.  Returns 0 or a PGRAPH_REJECT_* code. */
static int pgraph_decode_uncompressed_texture(unsigned stage,uint32_t **out,unsigned *ow,unsigned *oh) {
    unsigned d=stage*0x40;
    uint32_t address=PG_REG(NV097_SET_TEXTURE_OFFSET+d),format=PG_REG(NV097_SET_TEXTURE_FORMAT+d);
    unsigned color=(format>>8)&0xFF;
    unsigned bpp=0,kind=0;int swizzled=0;
    enum {K_Y8=1,K_AY8,K_A1R5G5B5,K_X1R5G5B5,K_A4R4G4B4,K_R5G6B5,K_A8R8G8B8,K_X8R8G8B8,K_A8,K_A8Y8};
    switch(color) {
    case 0x00: bpp=1;kind=K_Y8;swizzled=1;break;      case 0x13: bpp=1;kind=K_Y8;break;
    case 0x01: bpp=1;kind=K_AY8;swizzled=1;break;     case 0x1B: bpp=1;kind=K_AY8;break;
    case 0x02: bpp=2;kind=K_A1R5G5B5;swizzled=1;break;case 0x10: bpp=2;kind=K_A1R5G5B5;break;
    case 0x03: bpp=2;kind=K_X1R5G5B5;swizzled=1;break;case 0x1C: bpp=2;kind=K_X1R5G5B5;break;
    case 0x04: bpp=2;kind=K_A4R4G4B4;swizzled=1;break;case 0x1D: bpp=2;kind=K_A4R4G4B4;break;
    case 0x05: bpp=2;kind=K_R5G6B5;swizzled=1;break;  case 0x11: bpp=2;kind=K_R5G6B5;break;
    case 0x06: bpp=4;kind=K_A8R8G8B8;swizzled=1;break;case 0x12: bpp=4;kind=K_A8R8G8B8;break;
    case 0x07: bpp=4;kind=K_X8R8G8B8;swizzled=1;break;case 0x1E: bpp=4;kind=K_X8R8G8B8;break;
    case 0x19: bpp=1;kind=K_A8;swizzled=1;break;      case 0x1F: bpp=1;kind=K_A8;break;
    case 0x1A: bpp=2;kind=K_A8Y8;swizzled=1;break;    case 0x20: bpp=2;kind=K_A8Y8;break;
    default: return PGRAPH_REJECT_STATE;
    }
    if((format&NV097_SET_TEXTURE_FORMAT_CUBEMAP_ENABLE) || ((format>>4)&15u)!=2u) return PGRAPH_REJECT_STATE;
    unsigned width,height,pitch;
    if(swizzled) {
        width=1u<<((format>>20)&15u);height=1u<<((format>>24)&15u);pitch=width*bpp;
    } else {
        uint32_t rect=PG_REG(NV097_SET_TEXTURE_IMAGE_RECT+d);
        width=rect>>16;height=rect&0xFFFFu;pitch=PG_REG(NV097_SET_TEXTURE_CONTROL1+d)>>16;
        if(pitch<width*bpp) return PGRAPH_REJECT_LIMIT;
    }
    if(!width || !height || width>2048 || height>2048 || !g_pg_guest_reader) return PGRAPH_REJECT_LIMIT;
    uint64_t span=(uint64_t)(height-1)*pitch+(uint64_t)width*bpp;
    if((uint64_t)address+span>0x100000000ULL) return PGRAPH_REJECT_MEMORY;
    unsigned char *raw=(unsigned char *)malloc((size_t)width*height*bpp);
    uint32_t *pixels=(uint32_t *)malloc((size_t)width*height*4u);
    if(!raw || !pixels) { free(raw);free(pixels);return PGRAPH_REJECT_LIMIT; }
    if(swizzled) {
        unsigned char *swz=(unsigned char *)malloc((size_t)width*height*bpp);
        if(!swz || !g_pg_guest_reader(address,swz,(size_t)width*height*bpp)) { free(swz);free(raw);free(pixels);return PGRAPH_REJECT_MEMORY; }
        xbox_unswizzle_rect(raw,swz,width,height,bpp);free(swz);
    } else for(unsigned y=0;y<height;y++)
        if(!g_pg_guest_reader(address+y*pitch,raw+(size_t)y*width*bpp,width*bpp)) { free(raw);free(pixels);return PGRAPH_REJECT_MEMORY; }
    for(size_t i=0;i<(size_t)width*height;i++) {
        uint32_t a=255,r=0,g=0,b=0;
        if(bpp==4) {
            uint32_t v=((const uint32_t *)raw)[i];
            a=kind==K_X8R8G8B8 ? 255u : v>>24;r=(v>>16)&255u;g=(v>>8)&255u;b=v&255u;
        } else if(bpp==2) {
            uint32_t v=((const uint16_t *)raw)[i];
            if(kind==K_A1R5G5B5 || kind==K_X1R5G5B5) {
                a=kind==K_X1R5G5B5 ? 255u : ((v>>15)&1u)*255u;
                r=((v>>10)&31u)*255u/31u;g=((v>>5)&31u)*255u/31u;b=(v&31u)*255u/31u;
            } else if(kind==K_A4R4G4B4) {
                a=((v>>12)&15u)*17u;r=((v>>8)&15u)*17u;g=((v>>4)&15u)*17u;b=(v&15u)*17u;
            } else if(kind==K_R5G6B5) {
                r=((v>>11)&31u)*255u/31u;g=((v>>5)&63u)*255u/63u;b=(v&31u)*255u/31u;
            } else { /* A8Y8: byte0 = Y, byte1 = A */
                r=g=b=v&255u;a=v>>8;
            }
        } else {
            uint32_t v=raw[i];
            if(kind==K_A8) { a=v;r=g=b=255u; } else if(kind==K_AY8) { a=v;r=g=b=v; } else { r=g=b=v; }
        }
        pixels[i]=(a<<24)|(r<<16)|(g<<8)|b;
    }
    free(raw);*out=pixels;*ow=width;*oh=height;return 0;
}

/* Texture-coordinate scale for a stage: linear formats are sampled with texel coordinates. */
static void pgraph_stage_scale(unsigned stage,float *sx,float *sy) {
    unsigned d=stage*0x40;
    uint32_t format=PG_REG(NV097_SET_TEXTURE_FORMAT+d);
    unsigned color=(format>>8)&0xFF;
    int linear=(color>=0x10 && color<=0x13) || (color>=0x17 && color<=0x18) || (color>=0x1B && color<=0x24 && color!=0x1A);
    if(color==0x0C || color==0x0E || color==0x0F) linear=0;
    *sx=1.0f;*sy=1.0f;
    if(linear) {
        uint32_t rect=PG_REG(NV097_SET_TEXTURE_IMAGE_RECT+d);
        unsigned w=rect>>16,h=rect&0xFFFFu;
        if(w) *sx=1.0f/(float)w;
        if(h) *sy=1.0f/(float)h;
    }
}

static int pgraph_upload_scene_texture(IDirect3DDevice8 *dev,unsigned stage,
    IDirect3DTexture8 *protected_texture,IDirect3DTexture8 **result) {
    uint32_t address=PG_REG(NV097_SET_TEXTURE_OFFSET+stage*0x40);
    uint32_t format=PG_REG(NV097_SET_TEXTURE_FORMAT+stage*0x40);
    unsigned color=(format>>8)&0xFF;
    if(color!=NV097_SET_TEXTURE_FORMAT_COLOR_L_DXT1_A1R5G5B5 && color!=NV097_SET_TEXTURE_FORMAT_COLOR_L_DXT23_A8R8G8B8 &&
       color!=NV097_SET_TEXTURE_FORMAT_COLOR_L_DXT45_A8R8G8B8) {
        uint32_t *pixels=NULL;unsigned uw=0,uh=0;
        int rc=pgraph_decode_uncompressed_texture(stage,&pixels,&uw,&uh);
        if(rc) return rc;
        uint64_t hash=1469598103934665603ULL;
        for(size_t i=0;i<(size_t)uw*uh;i++) { hash^=pixels[i];hash*=1099511628211ULL; }
        unsigned cached=16;
        for(unsigned i=0;i<16;i++) if(g_pg.scene_textures[i].texture && g_pg.scene_textures[i].guest_offset==address &&
            g_pg.scene_textures[i].format==format && g_pg.scene_textures[i].width==uw && g_pg.scene_textures[i].height==uh) { cached=i;break; }
        if(cached!=16 && g_pg.scene_textures[cached].content_hash==hash) { free(pixels);*result=g_pg.scene_textures[cached].texture;return 0; }
        unsigned slot=cached;
        if(slot==16) for(unsigned i=0;i<16;i++) if(!g_pg.scene_textures[i].texture) { slot=i;break; }
        if(slot==16) {
            unsigned candidate=(address>>4)&15;
            for(unsigned probe=0;probe<16 && slot==16;probe++) {
                unsigned tested=(candidate+probe)&15;
                IDirect3DTexture8 *tex=g_pg.scene_textures[tested].texture;
                int in_use=tex==protected_texture;
                for(unsigned k=0;k<4;k++) if(tex && tex==g_pg_scene_protect[k]) in_use=1;
                if(!in_use) slot=tested;
            }
            if(slot==16) { free(pixels);return PGRAPH_REJECT_LIMIT; }
        }
        if(g_pg.scene_textures[slot].texture) {
            g_pg.scene_textures[slot].texture->lpVtbl->Release(g_pg.scene_textures[slot].texture);
            g_pg.scene_textures[slot].texture=NULL;
        }
        IDirect3DTexture8 *texture=NULL;
        HRESULT hr=dev->lpVtbl->CreateTexture(dev,uw,uh,1,0,D3DFMT_LIN_A8R8G8B8,0,&texture);
        if(FAILED(hr) || !texture) { free(pixels);return PGRAPH_REJECT_DEVICE; }
        D3DLOCKED_RECT lock={0};
        hr=texture->lpVtbl->LockRect(texture,0,&lock,NULL,0);
        if(FAILED(hr) || !lock.pBits || lock.Pitch<=0 || (unsigned)lock.Pitch<uw*4u) {
            texture->lpVtbl->Release(texture);free(pixels);return PGRAPH_REJECT_DEVICE;
        }
        for(unsigned y=0;y<uh;y++) memcpy((unsigned char *)lock.pBits+(size_t)y*lock.Pitch,pixels+(size_t)y*uw,uw*4u);
        hr=texture->lpVtbl->UnlockRect(texture,0);free(pixels);
        if(FAILED(hr)) { texture->lpVtbl->Release(texture);return PGRAPH_REJECT_DEVICE; }
        g_pg.scene_textures[slot].guest_offset=address;g_pg.scene_textures[slot].format=format;
        g_pg.scene_textures[slot].width=uw;g_pg.scene_textures[slot].height=uh;
        g_pg.scene_textures[slot].content_hash=hash;g_pg.scene_textures[slot].texture=texture;
        *result=texture;return 0;
    }
    unsigned width=1u<<((format>>20)&15),height=1u<<((format>>24)&15);
    unsigned block_bytes=color==NV097_SET_TEXTURE_FORMAT_COLOR_L_DXT1_A1R5G5B5 ? 8u : 16u;
    D3DFORMAT host_format;
    if(color==NV097_SET_TEXTURE_FORMAT_COLOR_L_DXT1_A1R5G5B5) host_format=D3DFMT_DXT1;
    else if(color==NV097_SET_TEXTURE_FORMAT_COLOR_L_DXT23_A8R8G8B8) host_format=D3DFMT_DXT3;
    else if(color==NV097_SET_TEXTURE_FORMAT_COLOR_L_DXT45_A8R8G8B8) host_format=D3DFMT_DXT5;
    else return PGRAPH_REJECT_STATE;
    if(!width || !height || width>2048 || height>2048 || !g_pg_guest_reader) return PGRAPH_REJECT_LIMIT;
    unsigned row_bytes=((width+3)/4)*block_bytes,rows=(height+3)/4;
    size_t size=(size_t)row_bytes*rows;
    if((uint64_t)address+size>0x100000000ULL) return PGRAPH_REJECT_MEMORY;
    unsigned char *data=(unsigned char *)malloc(size);
    if(!data) return PGRAPH_REJECT_LIMIT;
    if(!g_pg_guest_reader(address,data,size)) { free(data);return PGRAPH_REJECT_MEMORY; }
    uint64_t content_hash=1469598103934665603ULL;
    for(size_t i=0;i<size;i++) { content_hash^=data[i];content_hash*=1099511628211ULL; }
    unsigned slot=16;
    for(unsigned i=0;i<16;i++) if(g_pg.scene_textures[i].texture &&
        g_pg.scene_textures[i].guest_offset==address && g_pg.scene_textures[i].format==format) { slot=i;break; }
    if(slot!=16 && g_pg.scene_textures[slot].width==width &&
       g_pg.scene_textures[slot].height==height &&
       g_pg.scene_textures[slot].content_hash==content_hash) {
        free(data);*result=g_pg.scene_textures[slot].texture;return 0;
    }
    if(slot==16) {
        for(unsigned i=0;i<16;i++) if(!g_pg.scene_textures[i].texture) { slot=i;break; }
        if(slot==16) {
            unsigned candidate=(address>>4)&15;
            for(unsigned probe=0;probe<16;probe++) {
                unsigned tested=(candidate+probe)&15;
                IDirect3DTexture8 *tex=g_pg.scene_textures[tested].texture;
                int in_use=tex==protected_texture;
                for(unsigned k=0;k<4;k++) if(tex && tex==g_pg_scene_protect[k]) in_use=1;
                if(!in_use) {
                    slot=tested;break;
                }
            }
        }
    }
    if(g_pg.scene_textures[slot].texture) {
        g_pg.scene_textures[slot].texture->lpVtbl->Release(g_pg.scene_textures[slot].texture);
        g_pg.scene_textures[slot].texture=NULL;
    }
    IDirect3DTexture8 *texture=NULL;
    unsigned host_width=(width+3u)&~3u,host_height=(height+3u)&~3u;
    HRESULT hr=dev->lpVtbl->CreateTexture(dev,host_width,host_height,1,0,host_format,0,&texture);
    if(FAILED(hr) || !texture) { free(data);return PGRAPH_REJECT_DEVICE; }
    D3DLOCKED_RECT lock={0};
    hr=texture->lpVtbl->LockRect(texture,0,&lock,NULL,0);
    if(FAILED(hr) || !lock.pBits || lock.Pitch<=0 || (unsigned)lock.Pitch<row_bytes) {
        texture->lpVtbl->Release(texture);free(data);return PGRAPH_REJECT_DEVICE;
    }
    for(unsigned y=0;y<rows;y++)
        memcpy((unsigned char *)lock.pBits+(size_t)y*lock.Pitch,data+(size_t)y*row_bytes,row_bytes);
    hr=texture->lpVtbl->UnlockRect(texture,0);free(data);
    if(FAILED(hr)) { texture->lpVtbl->Release(texture);return PGRAPH_REJECT_DEVICE; }
    g_pg.scene_textures[slot].guest_offset=address;g_pg.scene_textures[slot].format=format;
    g_pg.scene_textures[slot].width=width;g_pg.scene_textures[slot].height=height;
    g_pg.scene_textures[slot].content_hash=content_hash;
    g_pg.scene_textures[slot].texture=texture;
    *result=texture;
    return 0;
}
static int pgraph_instruction_uses_source(const NV2AVPInstruction *inst,unsigned source) {
    unsigned mac=inst->mac;
    if(source==0) return mac!=0;
    if(source==1) return mac==2 || mac==5 || mac==6 || mac==7 || mac==8 || (mac>=9 && mac<=12);
    return mac==3 || mac==4 || inst->ilu!=0;
}

static int pgraph_diag_unsigned_list_contains(const char *list,unsigned value) {
    if(!list || !list[0]) return 0;
    const char *cursor=list;
    while(*cursor) {
        char *end=NULL;
        unsigned long parsed=strtoul(cursor,&end,10);
        if(end==cursor || parsed>UINT_MAX) return 0;
        if((unsigned)parsed==value) return 1;
        if(!*end) return 0;
        if(*end!=',') return 0;
        cursor=end+1;
    }
    return 0;
}

static void submit_indexed_draw(void) {
    static int freeze_major_telemetry;
    OutputVertex *vertices=NULL;
    NV2ADrawVertexCache vertex_cache={0};
    NV2AVPPreparedProgram prepared_program;
    size_t vertex_stride=sizeof(OutputVertex);
    unsigned reason=g_pg.draw_error,detail=0,length=0,attributes=0;
    float scene_min_x=INFINITY,scene_max_x=-INFINITY;
    float scene_min_y=INFINITY,scene_max_y=-INFINITY;
    unsigned scene_extreme_index=0;
    float scene_extreme_abs=0;
    unsigned scene_triangle_list=0,scene_triangle_vertex_count=0;
    unsigned profile=pgraph_array_profile();
    static unsigned scene_ordinal_frame=UINT_MAX,scene_ordinal_cursor;
    unsigned scene_ordinal=0;
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        if(scene_ordinal_frame!=g_pg.stats.frames) {
            scene_ordinal_frame=g_pg.stats.frames;
            scene_ordinal_cursor=0;
        }
        scene_ordinal=++scene_ordinal_cursor;
    }
    if(getenv("DAH2_DRAW_ORDER_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN") &&
       g_pg.stats.frames>=1033u && g_pg.stats.frames<=1036u) {
        fprintf(stdout,
            "[PGRAPH-DRAW-ORDER] frame=%u ordinal=%u profile=%u count=%u target=%08X zeta=%08X "
            "depthTest=%d depthFunc=%08X depthMask=%08X blend=%d texture=%08X\n",
            g_pg.stats.frames,scene_ordinal,profile,g_pg.index_count,
            PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),PG_REG(NV097_SET_SURFACE_ZETA_OFFSET),
            g_pg.depth_test,PG_REG(NV097_SET_DEPTH_FUNC),PG_REG(NV097_SET_DEPTH_MASK),
            g_pg.blend_enable,PG_REG(NV097_SET_TEXTURE_OFFSET));
        fflush(stdout);
    }    /* DAH2_TELEMETRY_ONLY_COUNT=N keeps the 64-entry telemetry ring for draws with exactly N indices (others share the last slot). */
    static int only_count_cfg=-1;
    if(only_count_cfg<0) { const char *v=getenv("DAH2_TELEMETRY_ONLY_COUNT"); only_count_cfg=v ? atoi(v) : 0; }
    unsigned telemetry_sequence=freeze_major_telemetry ?
        g_dah2_pgraph_draw_telemetry_cursor : g_dah2_pgraph_draw_telemetry_cursor++;
    unsigned telemetry_slot=telemetry_sequence%64u;
    if(only_count_cfg>0 && g_pg.index_count!=(unsigned)only_count_cfg) {
        if(!freeze_major_telemetry) g_dah2_pgraph_draw_telemetry_cursor--;
        telemetry_slot=63u;
    } else if(only_count_cfg>0) telemetry_slot=telemetry_sequence%63u;
    volatile Dah2PgraphDrawTelemetry *telemetry=&g_dah2_pgraph_draw_telemetry[telemetry_slot];
    telemetry->profile=profile;telemetry->count=g_pg.index_count;telemetry->mode=g_pg.draw_mode;
    telemetry->target=PG_REG(NV097_SET_SURFACE_COLOR_OFFSET);telemetry->texture=PG_REG(NV097_SET_TEXTURE_OFFSET);
    telemetry->clip_h=g_pg.surface_clip_h;telemetry->clip_v=g_pg.surface_clip_v;
    telemetry->combiner=PG_REG(NV097_SET_COMBINER_CONTROL);telemetry->reason=reason;telemetry->detail=0;
    telemetry->source_object=g_dah2_menu_active_object;telemetry->source_node=g_dah2_menu_active_node;
    if (!freeze_major_telemetry && getenv("DAH2_FREEZE_MAJOR_DRAW") &&
        profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 && g_pg.index_count>=100)
        freeze_major_telemetry=1;
    memset((void *)g_dah2_pgraph_draw_outputs[telemetry_slot],0,sizeof(g_dah2_pgraph_draw_outputs[telemetry_slot]));
    memset((void *)g_dah2_pgraph_draw_output_masks[telemetry_slot],0,sizeof(g_dah2_pgraph_draw_output_masks[telemetry_slot]));
    memset((void *)g_dah2_pgraph_draw_memory_failures[telemetry_slot],0,sizeof(g_dah2_pgraph_draw_memory_failures[telemetry_slot]));
    if(pgraph_draw_state_enabled()) {
        memcpy((void *)g_dah2_pgraph_draw_registers[telemetry_slot],g_pg.registers,sizeof(g_pg.registers));
        memcpy((void *)g_dah2_pgraph_draw_programs[telemetry_slot],g_pg.program,sizeof(g_pg.program));
        memcpy((void *)g_dah2_pgraph_draw_program_valid[telemetry_slot],g_pg.program_valid,sizeof(g_pg.program_valid));
        memcpy((void *)g_dah2_pgraph_draw_constants[telemetry_slot],g_pg.constants,sizeof(g_pg.constants));
        memcpy((void *)g_dah2_pgraph_draw_constant_valid[telemetry_slot],g_pg.constant_valid,sizeof(g_pg.constant_valid));
    }
    for(unsigned s=0;s<4;s++) {
        g_pg_stage_scale[s][0]=g_pg_stage_scale[s][1]=1.0f;
        if(profile==PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC && ((PG_REG(NV097_SET_SHADER_STAGE_PROGRAM)>>(s*5))&31u))
            pgraph_stage_scale(s,&g_pg_stage_scale[s][0],&g_pg_stage_scale[s][1]);
    }
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
    /* Hidden diagnostics: keep the title/post-process pipeline intact while
     * submitting selected scene meshes. Ordinals are one-based per frame. */
    {
        const char *only_count=getenv("DAH2_SCENE_ONLY_COUNT");
        const char *only_counts=getenv("DAH2_SCENE_ONLY_COUNTS");
        const char *only_ordinals=getenv("DAH2_SCENE_ONLY_ORDINALS");
        if(getenv("DAH2_TEST_WINDOW_HIDDEN") &&
           profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
            int selected=1;
            if(only_count && only_count[0]) {
                char *end=NULL;
                unsigned long wanted=strtoul(only_count,&end,10);
                selected=end && !*end && wanted<=UINT_MAX &&
                    g_pg.index_count==(unsigned)wanted;
            }
            if(only_counts && only_counts[0])
                selected=selected && pgraph_diag_unsigned_list_contains(only_counts,g_pg.index_count);
            if(only_ordinals && only_ordinals[0])
                selected=selected && pgraph_diag_unsigned_list_contains(only_ordinals,scene_ordinal);
            if(!selected) return;
        }
    }
    if (reason) goto rejected;
    if (g_pg.draw_mode!=5 && g_pg.draw_mode!=6) { reason=PGRAPH_REJECT_TOPOLOGY;goto rejected; }
    if (g_pg.index_count<3 || (g_pg.draw_mode==5 && g_pg.index_count%3)) { reason=PGRAPH_REJECT_TOPOLOGY;goto rejected; }
    detail=pgraph_supported_array_state(profile);
    if (detail) { reason=PGRAPH_REJECT_STATE;goto rejected; }
    unsigned start=PG_REG(NV097_SET_TRANSFORM_PROGRAM_START);
    if (nv2a_vp_prepare_mov(g_pg.program,NV2A_VP_SLOTS,start,&prepared_program,&detail)!=NV2A_VP_OK) {
        reason=PGRAPH_REJECT_SHADER;goto rejected;
    }
    length=prepared_program.length;
    for (unsigned i=start;i<start+length;i++) {
        for(unsigned w=0;w<4;w++)if(!g_pg.program_valid[i*4+w]) { reason=PGRAPH_REJECT_SHADER;detail=i;goto rejected; }
        NV2AVPInstruction inst;nv2a_vp_decode_instruction(g_pg.program+i*4,&inst);
        for (unsigned source=0;source<3;source++) {
            if (!pgraph_instruction_uses_source(&inst,source)) continue;
            if (inst.source[source].mux==2) attributes|=1u<<inst.attribute;
            if (inst.source[source].mux==3 && !inst.relative) for(unsigned c=0;c<4;c++)
                if(inst.constant>=NV2A_VP_CONSTANTS || !g_pg.constant_valid[inst.constant*4+c]) {
                    reason=PGRAPH_REJECT_SHADER;detail=inst.constant;goto rejected;
                }
        }
    }
    unsigned width=PG_REG(NV097_SET_TEXTURE_IMAGE_RECT)>>16;
    unsigned height=PG_REG(NV097_SET_TEXTURE_IMAGE_RECT)&0xFFFF;
    unsigned pitch=PG_REG(NV097_SET_TEXTURE_CONTROL1)>>16;
    unsigned texture_bpp=((PG_REG(NV097_SET_TEXTURE_FORMAT)>>8)&0xFFu)==
        NV097_SET_TEXTURE_FORMAT_COLOR_LU_IMAGE_A4R4G4B4 ? 2u : 4u;
    if (profile<PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 && (!width || !height || width>2048 || height>2048 || pitch<width*texture_bpp || (uint64_t)width*height*texture_bpp>16*1024*1024)) {
        reason=PGRAPH_REJECT_LIMIT;detail=NV097_SET_TEXTURE_IMAGE_RECT;goto rejected;
    }
    if (profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2)
        vertex_stride=sizeof(PgraphSceneVertex);
    else if (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB)
        vertex_stride=sizeof(PgraphOutputVertex4);
    vertices=(OutputVertex *)malloc(g_pg.index_count*vertex_stride);
    if (!vertices) { reason=PGRAPH_REJECT_LIMIT;goto rejected; }
    /* Preserve every strip position while transforming each repeated source
     * index once. Arrays, program, constants and packing state remain fixed
     * throughout this synchronous draw; no cache crosses the draw boundary. */
    nv2a_draw_vertex_cache_init(&vertex_cache,g_pg.indices,g_pg.index_count);
    for(unsigned i=0;i<g_pg.index_count;i++) {
        detail=g_pg.indices[i];
        OutputVertex *vertex=(OutputVertex *)((unsigned char *)vertices+i*vertex_stride);
        uint32_t previous_position;
        if(nv2a_draw_vertex_cache_find(&vertex_cache,detail,&previous_position)) {
            memcpy(vertex,(unsigned char *)vertices+(size_t)previous_position*vertex_stride,vertex_stride);
        } else {
            NV2AVertexResult result;
            if (!pgraph_read_vertex(detail,attributes,&result,telemetry_slot,&prepared_program)) { reason=PGRAPH_REJECT_MEMORY;goto rejected; }
            if (i==0) {
                memcpy((void *)g_dah2_pgraph_draw_outputs[telemetry_slot],result.output,sizeof(result.output));
                memcpy((void *)g_dah2_pgraph_draw_output_masks[telemetry_slot],result.written_mask,sizeof(result.written_mask));
            }
            if (profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
                if (!pgraph_pack_scene_vertex(&result,(PgraphSceneVertex *)vertex)) {
                    memcpy((void *)g_dah2_pgraph_draw_outputs[telemetry_slot],result.output,sizeof(result.output));
                    memcpy((void *)g_dah2_pgraph_draw_output_masks[telemetry_slot],result.written_mask,sizeof(result.written_mask));
                    reason=PGRAPH_REJECT_OUTPUT;goto rejected;
                }
            } else if (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) {
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
            nv2a_draw_vertex_cache_store(&vertex_cache,detail,i);
        }
        if (profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
            PgraphSceneVertex *scene_vertex=(PgraphSceneVertex *)vertex;
            scene_min_x=fminf(scene_min_x,scene_vertex->x);scene_max_x=fmaxf(scene_max_x,scene_vertex->x);
            scene_min_y=fminf(scene_min_y,scene_vertex->y);scene_max_y=fmaxf(scene_max_y,scene_vertex->y);
            float extreme=fmaxf(fabsf(scene_vertex->x),fabsf(scene_vertex->y));
            if(extreme>scene_extreme_abs){scene_extreme_abs=extreme;scene_extreme_index=detail;}
        }
    }
    nv2a_draw_vertex_cache_destroy(&vertex_cache);
    /* Pretransformed D3D vertices cannot represent the NV2A near-plane clip.
     * Expand strips and keep only fully front-facing-W triangles so rejected
     * vertices cannot become giant connector triangles across the menu. */
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        PgraphSceneVertex *source=(PgraphSceneVertex *)vertices;
        PgraphSceneVertex *front=(PgraphSceneVertex *)malloc((g_pg.index_count-2u)*3u*sizeof(*front));
        if(!front){reason=PGRAPH_REJECT_LIMIT;goto rejected;}
        unsigned positive=0,nonpositive=0;
        float min_w=INFINITY,max_w=-INFINITY;
        for(unsigned i=0;i<g_pg.index_count;i++) {
            float w=1.0f/source[i].rhw;
            min_w=fminf(min_w,w);max_w=fmaxf(max_w,w);
            if(isfinite(w) && w>0) positive++; else nonpositive++;
        }
        unsigned nondegenerate=0,positive_area=0,negative_area=0;
        float min_z=INFINITY,max_z=-INFINITY,max_abs_area=0;
        for(unsigned i=0;i<g_pg.index_count;i++) {
            min_z=fminf(min_z,source[i].z);max_z=fmaxf(max_z,source[i].z);
        }
        for(unsigned i=0;i+2u<g_pg.index_count;i++) {
            unsigned a=i,b=i+1u,c=i+2u;
            if(i&1u){unsigned swap=a;a=b;b=swap;}
            if(!(source[a].rhw>0) || !(source[b].rhw>0) || !(source[c].rhw>0)) continue;
            float area=(source[b].x-source[a].x)*(source[c].y-source[a].y)-
                (source[b].y-source[a].y)*(source[c].x-source[a].x);
            max_abs_area=fmaxf(max_abs_area,fabsf(area));
            if(area>0.00001f){nondegenerate++;positive_area++;}
            else if(area<-0.00001f){nondegenerate++;negative_area++;}
            front[scene_triangle_vertex_count++]=source[a];
            front[scene_triangle_vertex_count++]=source[b];
            front[scene_triangle_vertex_count++]=source[c];
        }
        if(getenv("DAH2_SCENE_FORCE_Z_DIAGNOSTIC"))
            for(unsigned i=0;i<scene_triangle_vertex_count;i++) front[i].z=0.5f;
        if(getenv("DAH2_SCENE_FORCE_RHW_DIAGNOSTIC"))
            for(unsigned i=0;i<scene_triangle_vertex_count;i++) front[i].rhw=1.0f;
        if(getenv("DAH2_SCENE_FORCE_COLOR_DIAGNOSTIC"))
            for(unsigned i=0;i<scene_triangle_vertex_count;i++) front[i].diffuse=0xFFFFFFFFu;
        if(getenv("DAH2_SCENE_PROMOTE_TRIANGLE_DIAGNOSTIC")) {
            unsigned promoted_index=UINT_MAX;
            float promoted_area=0;
            for(unsigned i=0;i+2u<scene_triangle_vertex_count;i+=3u) {
                float area=(front[i+1].x-front[i].x)*(front[i+2].y-front[i].y)-
                    (front[i+1].y-front[i].y)*(front[i+2].x-front[i].x);
                if(fabsf(area)>promoted_area){promoted_area=fabsf(area);promoted_index=i;}
            }
            if(promoted_index!=UINT_MAX) {
                unsigned i=promoted_index;
                PgraphSceneVertex promoted[3]={front[i],front[i+1],front[i+2]};
                for(unsigned j=0;j<3;j++) {
                    promoted[j].z=0.5f;promoted[j].rhw=1.0f;
                    promoted[j].diffuse=0xFFFFFFFFu;promoted[j].specular=0;
                    promoted[j].u0=promoted[j].v0=promoted[j].u1=promoted[j].v1=promoted[j].u2=promoted[j].v2=promoted[j].u3=promoted[j].v3=0;
                    front[j]=promoted[j];
                }
                fprintf(stdout,"[PGRAPH-PROMOTED] area=%.9g xy=(%.3f,%.3f)(%.3f,%.3f)(%.3f,%.3f)\n",
                    promoted_area,front[0].x,front[0].y,front[1].x,front[1].y,front[2].x,front[2].y);
                fflush(stdout);
            }
        }
        if(getenv("DAH2_SCENE_CANARY_TRIANGLE_DIAGNOSTIC") &&
           scene_triangle_vertex_count>=3u) {
            const float canary_xy[3][2]={{100,100},{200,100},{100,200}};
            for(unsigned i=0;i<3;i++) {
                front[i].x=canary_xy[i][0];front[i].y=canary_xy[i][1];
                front[i].z=0.5f;front[i].rhw=1.0f;
                front[i].diffuse=0xFFFFFFFFu;front[i].specular=0;
            }
        }
        static unsigned front_reports,isolated_front_reports;
        const char *isolated_count=getenv("DAH2_SCENE_ONLY_COUNT");
        int isolated_front=isolated_count && isolated_count[0] &&
            strtoul(isolated_count,NULL,10)==g_pg.index_count &&
            isolated_front_reports++<8u;
        if(front_reports++<8u || isolated_front) {
            fprintf(stdout,"[PGRAPH-FRONT-TRIANGLES] count=%u positive=%u nonpositive=%u w=%.9g..%.9g z=%.9g..%.9g triangles=%u/%u nondegenerate=%u areaSign=%u/%u maxArea=%.9g\n",
                g_pg.index_count,positive,nonpositive,min_w,max_w,min_z,max_z,
                scene_triangle_vertex_count/3u,g_pg.index_count-2u,nondegenerate,
                positive_area,negative_area,max_abs_area);
            fflush(stdout);
        }
        if(getenv("DAH2_SCENE_Z_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN") &&
           g_pg.stats.frames>=1348u && g_pg.stats.frames<=1350u) {
            fprintf(stdout,"[PGRAPH-SCENE-Z] frame=%u profile=%u count=%u clip=%08X/%.9g w=%.9g..%.9g z=%.9g..%.9g triangles=%u\n",
                g_pg.stats.frames,profile,g_pg.index_count,PG_REG(NV097_SET_CLIP_MAX),
                u2f(PG_REG(NV097_SET_CLIP_MAX)),min_w,max_w,min_z,max_z,
                scene_triangle_vertex_count/3u);
            fflush(stdout);
        }
        free(vertices);vertices=(OutputVertex *)front;scene_triangle_list=1;
    }
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2){
        uint32_t bits;
        memcpy(&bits,&scene_min_x,4);g_dah2_pgraph_draw_memory_failures[telemetry_slot][6]=bits;
        memcpy(&bits,&scene_max_x,4);g_dah2_pgraph_draw_memory_failures[telemetry_slot][7]=bits;
        memcpy(&bits,&scene_min_y,4);g_dah2_pgraph_draw_memory_failures[telemetry_slot][8]=bits;
        memcpy(&bits,&scene_max_y,4);g_dah2_pgraph_draw_memory_failures[telemetry_slot][9]=bits;
        g_dah2_pgraph_draw_memory_failures[telemetry_slot][10]=scene_extreme_index;
        static unsigned scene_bounds_reports;
        if(g_pg.stats.frames>=1350 && scene_bounds_reports<256){
            fprintf(stdout,"[PGRAPH-SCENE-BOUNDS] frame=%u profile=%u count=%u x=%.3f..%.3f y=%.3f..%.3f extremeIndex=%u\n",
                g_pg.stats.frames,profile,g_pg.index_count,scene_min_x,scene_max_x,
                scene_min_y,scene_max_y,scene_extreme_index);
            fflush(stdout);scene_bounds_reports++;
        }
        static unsigned scene_state_reports;
        if(g_pg.stats.frames>=1348 && g_pg.stats.frames<=1350 && scene_state_reports<64){
            fprintf(stdout,"[PGRAPH-SCENE-STATE] frame=%u count=%u target=%08X zeta=%08X depthTest=%d depthFunc=%08X depthMask=%08X\n",
                g_pg.stats.frames,g_pg.index_count,PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),
                PG_REG(NV097_SET_SURFACE_ZETA_OFFSET),g_pg.depth_test,
                PG_REG(NV097_SET_DEPTH_FUNC),PG_REG(NV097_SET_DEPTH_MASK));
            fflush(stdout);scene_state_reports++;
        }
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
    IDirect3DTexture8 *scene_texture[4]={NULL,NULL,NULL,NULL};
    int postprocess_diag=getenv("DAH2_POSTPROCESS_DIAGNOSTIC") &&
        g_pg.stats.frames>=1500u &&
        getenv("DAH2_TEST_WINDOW_HIDDEN") &&
        (profile==PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB ||
         profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB);
    if(postprocess_diag && surface_texture)
        pgraph_report_surface(PG_REG(NV097_SET_TEXTURE_OFFSET),"post-source");

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
    if(profile==PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC) {
        uint32_t program=PG_REG(NV097_SET_SHADER_STAGE_PROGRAM);
        memset(g_pg_scene_protect,0,sizeof(g_pg_scene_protect));
        for(unsigned s=0;s<4;s++) {
            if(!((program>>(s*5))&31u)) continue;
            IDirect3DTexture8 *surface=pgraph_surface_texture(PG_REG(NV097_SET_TEXTURE_OFFSET+s*0x40));
            if(surface) { scene_texture[s]=surface;g_pg_scene_protect[s]=surface;continue; }
            reason=pgraph_upload_scene_texture(dev,s,NULL,&scene_texture[s]);
            if(reason) { detail=NV097_SET_TEXTURE_FORMAT+s*0x40;goto rejected; }
            g_pg_scene_protect[s]=scene_texture[s];
        }
    } else if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 &&
       profile!=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_UNTEXTURED) {
        reason=pgraph_upload_scene_texture(dev,0,NULL,&scene_texture[0]);
        if(reason) goto rejected;
        if(PG_REG(NV097_SET_TEXTURE_CONTROL0+0x40)&NV097_SET_TEXTURE_CONTROL0_ENABLE) {
            reason=pgraph_upload_scene_texture(dev,1,scene_texture[0],&scene_texture[1]);
            if(reason) goto rejected;
        }
    }
    reason=pgraph_bind_array_target(dev);
    if (reason) goto rejected;
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {

        static unsigned cleared_frame=UINT_MAX;
        if(cleared_frame!=g_pg.stats.frames) {
            int slot=pgraph_surface_index(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
            if(slot>=0) {
                if(getenv("DAH2_DEPTH_CLEAR_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN")) {
                    fprintf(stdout,"[PGRAPH-SCENE-REPLAY] frame=%u profile=%u count=%u target=%08X slot=%d\n",
                        g_pg.stats.frames,profile,g_pg.index_count,
                        PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),slot);
                    fflush(stdout);
                }
                ID3D11DeviceContext_ClearDepthStencilView(
                    d3d8_GetD3D11Context(),g_pg.array_surfaces[slot].dsv,
                    D3D11_CLEAR_DEPTH|D3D11_CLEAR_STENCIL,1.0f,0);
                g_pg.pending_scene_depth_replay=0;
                cleared_frame=g_pg.stats.frames;
            }
        }
    }    if(getenv("DAH2_DRAW_ORDER_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN") &&
       g_pg.stats.frames>=1033u && g_pg.stats.frames<=1036u) {
        int bound_slot=pgraph_surface_index(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
        if(bound_slot>=0) {
            fprintf(stdout,"[PGRAPH-BOUND-DSV] frame=%u profile=%u count=%u dsv=%p depth=%p size=%ux%u\n",
                g_pg.stats.frames,profile,g_pg.index_count,
                (void *)g_pg.array_surfaces[bound_slot].dsv,
                (void *)g_pg.array_surfaces[bound_slot].depth,
                g_pg.array_surfaces[bound_slot].width,g_pg.array_surfaces[bound_slot].height);
            fflush(stdout);
        }
    }
    reason=PGRAPH_REJECT_DEVICE;
#define PG_CALL(call) do { HRESULT pg_call_hr=(call); if (FAILED(pg_call_hr)) { detail=(uint32_t)__LINE__; goto rejected; } } while(0)
#define PG_RS(state,value) PG_CALL(dev->lpVtbl->SetRenderState(dev,state,value))
#define PG_TSS(state,value) PG_CALL(dev->lpVtbl->SetTextureStageState(dev,0,state,value))
#define PG_TSS_STAGE(stage,state,value) PG_CALL(dev->lpVtbl->SetTextureStageState(dev,stage,state,value))
    /* Scene draws carry surface-absolute pixel coordinates; the surface clip only limits where they may land (scissor below).  The older
     * title/menu profiles keep the clip-sized viewport (their clip equals the surface). */
    D3DVIEWPORT8 viewport={0,0,g_pg.surface_clip_h>>16,g_pg.surface_clip_v>>16,0,1};
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        int viewport_slot=pgraph_surface_index(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
        if(viewport_slot>=0) { viewport.Width=g_pg.array_surfaces[viewport_slot].width;viewport.Height=g_pg.array_surfaces[viewport_slot].height; }
    }
    PG_CALL(dev->lpVtbl->SetViewport(dev,&viewport));
    int scene_solid_diag=profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 &&
        getenv("DAH2_SCENE_SOLID_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN");
    int scene_no_depth_diag=scene_solid_diag && getenv("DAH2_SCENE_NO_DEPTH_DIAGNOSTIC");
    int scene_no_cull_diag=scene_solid_diag && getenv("DAH2_SCENE_NO_CULL_DIAGNOSTIC");
    int scene_no_alpha_diag=scene_solid_diag && getenv("DAH2_SCENE_NO_ALPHA_DIAGNOSTIC");
    int scene_no_blend_diag=scene_solid_diag && getenv("DAH2_SCENE_NO_BLEND_DIAGNOSTIC");
    int scene_keep_shader_diag=scene_solid_diag && getenv("DAH2_SCENE_KEEP_SHADER_DIAGNOSTIC");
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        uint32_t control=PG_REG(NV097_SET_COMBINER_CONTROL);
        uint32_t shader=PG_REG(NV097_SET_SHADER_STAGE_PROGRAM);
        uint32_t combiner_token=control&15,texture_modes=0;
        for(unsigned s=0;s<4;s++) {
            unsigned guest_mode=(shader>>(s*5))&31;
            unsigned host_mode=guest_mode ? 0u : 3u; /* active 2D or disabled */
            combiner_token|=host_mode<<(8+s*4);texture_modes|=host_mode<<(s*4);
        }
        for(unsigned i=0;i<8;i++) {
            PG_RS(D3DRS_PSALPHAINPUTS0+i,PG_REG(NV097_SET_COMBINER_ALPHA_ICW+i*4));
            PG_RS(D3DRS_PSRGBINPUTS0+i,PG_REG(NV097_SET_COMBINER_COLOR_ICW+i*4));
            PG_RS(D3DRS_PSRGBOUTPUTS0+i,PG_REG(NV097_SET_COMBINER_COLOR_OCW+i*4));
            PG_RS(D3DRS_PSALPHAOUTPUTS0+i,PG_REG(NV097_SET_COMBINER_ALPHA_OCW+i*4));
            PG_RS(D3DRS_PSCONSTANT0_0+i,PG_REG(NV097_SET_COMBINER_FACTOR0+i*4));
            PG_RS(D3DRS_PSCONSTANT1_0+i,PG_REG(NV097_SET_COMBINER_FACTOR1+i*4));
        }
        PG_RS(D3DRS_PSFINALCOMBINERINPUTSABCD,PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW0));
        PG_RS(D3DRS_PSFINALCOMBINERINPUTSEFG,PG_REG(NV097_SET_COMBINER_SPECULAR_FOG_CW1));
        PG_RS(D3DRS_PSCOMBINERCOUNT,control);PG_RS(D3DRS_PSTEXTUREMODES,texture_modes);
        PG_CALL(dev->lpVtbl->SetPixelShader(dev,
            scene_solid_diag && !scene_keep_shader_diag ? 0 : combiner_token));
        PG_CALL(dev->lpVtbl->SetVertexShader(dev,D3DFVF_XYZRHW|D3DFVF_DIFFUSE|D3DFVF_SPECULAR|D3DFVF_TEX4));
    } else {
        PG_CALL(dev->lpVtbl->SetPixelShader(dev,0));
        PG_CALL(dev->lpVtbl->SetVertexShader(dev,D3DFVF_XYZRHW|D3DFVF_DIFFUSE|
            (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB ? D3DFVF_TEX4 : D3DFVF_TEX1)));
    }
    PG_RS(D3DRS_LIGHTING,FALSE);PG_RS(D3DRS_FOGENABLE,FALSE);PG_RS(D3DRS_SPECULARENABLE,FALSE);
    { uint32_t fc=PG_REG(NV097_SET_FOG_COLOR); /* NV097: R=0xFF G=0xFF00 B=0xFF0000 A=0xFF000000 -> D3DCOLOR ARGB */
      PG_RS(D3DRS_FOGCOLOR,(fc&0xFF000000u)|((fc&0xFFu)<<16)|(fc&0xFF00u)|((fc>>16)&0xFFu)); }
    PG_RS(D3DRS_FILLMODE,D3DFILL_SOLID);PG_RS(D3DRS_SHADEMODE,2 /* D3DSHADE_GOURAUD */);
    PG_RS(D3DRS_ZENABLE,scene_no_depth_diag ? FALSE : g_pg.depth_test);
    PG_RS(D3DRS_ZWRITEENABLE,scene_no_depth_diag ? FALSE : PG_REG(NV097_SET_DEPTH_MASK)!=0);
    PG_RS(D3DRS_ZFUNC,PG_REG(NV097_SET_DEPTH_FUNC)-0x1FF);
    { /* NV2A stencil -> host stencil (D24S8 depth buffers); the minimap and HUD masks rely on it. */
      int stencil=PG_REG(NV097_SET_STENCIL_TEST_ENABLE)!=0 && profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2;
      PG_RS(D3DRS_STENCILENABLE,stencil);
      if(stencil) {
          static const uint32_t gl_ops[8]={NV097_SET_STENCIL_OP_V_KEEP,NV097_SET_STENCIL_OP_V_ZERO,NV097_SET_STENCIL_OP_V_REPLACE,
              NV097_SET_STENCIL_OP_V_INCRSAT,NV097_SET_STENCIL_OP_V_DECRSAT,NV097_SET_STENCIL_OP_V_INVERT,
              NV097_SET_STENCIL_OP_V_INCR,NV097_SET_STENCIL_OP_V_DECR};
          static const DWORD d3d_ops[8]={1,2,3,4,5,6,7,8};
          DWORD ops[3]={1,1,1};
          const uint32_t regs3[3]={PG_REG(NV097_SET_STENCIL_OP_FAIL),PG_REG(NV097_SET_STENCIL_OP_ZFAIL),PG_REG(NV097_SET_STENCIL_OP_ZPASS)};
          for(unsigned o=0;o<3;o++) for(unsigned k=0;k<8;k++) if(regs3[o]==gl_ops[k]) ops[o]=d3d_ops[k];
          PG_RS(D3DRS_STENCILFUNC,PG_REG(NV097_SET_STENCIL_FUNC)-0x1FF);
          PG_RS(D3DRS_STENCILREF,PG_REG(NV097_SET_STENCIL_FUNC_REF)&255u);
          PG_RS(D3DRS_STENCILMASK,PG_REG(NV097_SET_STENCIL_FUNC_MASK)&255u);
          PG_RS(D3DRS_STENCILWRITEMASK,(PG_REG(NV097_SET_CONTROL0)&NV097_SET_CONTROL0_STENCIL_WRITE_ENABLE) ? (PG_REG(NV097_SET_STENCIL_MASK)&255u) : 0u);
          PG_RS(D3DRS_STENCILFAIL,ops[0]);PG_RS(D3DRS_STENCILZFAIL,ops[1]);PG_RS(D3DRS_STENCILPASS,ops[2]);
      }
    }
    PG_RS(D3DRS_CULLMODE,scene_no_cull_diag ? D3DCULL_NONE :
        (g_pg.cull_enable ? D3DCULL_CCW : D3DCULL_NONE));
    PG_RS(D3DRS_ALPHATESTENABLE,scene_no_alpha_diag ? FALSE : g_pg.alpha_test);PG_RS(D3DRS_ALPHAFUNC,PG_REG(NV097_SET_ALPHA_FUNC)-0x1FF);
    PG_RS(D3DRS_ALPHAREF,PG_REG(NV097_SET_ALPHA_REF)&255);
    PG_RS(D3DRS_ALPHABLENDENABLE,scene_no_blend_diag ? FALSE : g_pg.blend_enable);
    PG_RS(D3DRS_SRCBLEND,g_pg.blend_sfactor==1 ? D3DBLEND_ONE : D3DBLEND_SRCALPHA);
    PG_RS(D3DRS_DESTBLEND,g_pg.blend_dfactor==0 ? D3DBLEND_ZERO :
        g_pg.blend_dfactor==1 ? D3DBLEND_ONE : D3DBLEND_INVSRCALPHA);
    { uint32_t equation=PG_REG(NV097_SET_BLEND_EQUATION);
      PG_RS(D3DRS_BLENDOP,equation==0x800Au ? 2 : equation==0x800Bu ? 3 :
          equation==0x8007u ? 4 : equation==0x8008u ? 5 : 1); }
    uint32_t mask=g_pg.color_mask;
    PG_RS(D3DRS_COLORWRITEENABLE,((mask>>16)&1)|(((mask>>8)&1)<<1)|((mask&1)<<2)|(((mask>>24)&1)<<3));
    if(postprocess_diag && getenv("DAH2_POSTPROCESS_NO_TESTS_DIAGNOSTIC")) {
        PG_RS(D3DRS_ZENABLE,FALSE);PG_RS(D3DRS_ZWRITEENABLE,FALSE);
        PG_RS(D3DRS_CULLMODE,D3DCULL_NONE);PG_RS(D3DRS_ALPHATESTENABLE,FALSE);
        PG_RS(D3DRS_ALPHABLENDENABLE,FALSE);PG_RS(D3DRS_COLORWRITEENABLE,15);
    }
    for(unsigned s=0;s<4;s++) {
        IDirect3DBaseTexture8 *binding=NULL;
        if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
            binding=(IDirect3DBaseTexture8 *)scene_texture[s];
        } else if(profile!=PGRAPH_ARRAY_PROFILE_MOVIE &&
            (s==0 || profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB))
            binding=(IDirect3DBaseTexture8 *)(surface_texture ? surface_texture : g_pg.array_texture);
        PG_CALL(dev->lpVtbl->SetTexture(dev,s,binding));
    }
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        if(scene_solid_diag && !scene_keep_shader_diag) {
            PG_RS(D3DRS_TEXTUREFACTOR,0xFFFFFFFFu);
            PG_TSS(D3DTSS_COLOROP,D3DTOP_SELECTARG1);PG_TSS(D3DTSS_COLORARG1,D3DTA_TFACTOR);
            PG_TSS(D3DTSS_ALPHAOP,D3DTOP_SELECTARG1);PG_TSS(D3DTSS_ALPHAARG1,D3DTA_TFACTOR);
            for(unsigned s=1;s<4;s++) {
                PG_TSS_STAGE(s,D3DTSS_COLOROP,D3DTOP_DISABLE);
                PG_TSS_STAGE(s,D3DTSS_ALPHAOP,D3DTOP_DISABLE);
            }
        }
        /* Otherwise raw NV2A register combiners above replace the fixed-function stages. */
    } else if (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB) {
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
        PG_TSS(D3DTSS_COLOROP,getenv("DAH2_POSTPROCESS_FORCE_COPY_DIAGNOSTIC") ? D3DTOP_SELECTARG1 : D3DTOP_SUBTRACT);
        PG_TSS(D3DTSS_COLORARG1,2);PG_TSS(D3DTSS_COLORARG2,0);
        PG_TSS(D3DTSS_ALPHAOP,D3DTOP_SELECTARG1);PG_TSS(D3DTSS_ALPHAARG1,2);PG_TSS(D3DTSS_ALPHAARG2,0);
    } else if (profile==PGRAPH_ARRAY_PROFILE_TEXTURED_ARGB || profile==PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB) {
        PG_TSS(D3DTSS_COLOROP,D3DTOP_MODULATE2X);PG_TSS(D3DTSS_COLORARG1,2);PG_TSS(D3DTSS_COLORARG2,0);
        PG_TSS(D3DTSS_ALPHAOP,D3DTOP_MODULATE);PG_TSS(D3DTSS_ALPHAARG1,2);PG_TSS(D3DTSS_ALPHAARG2,0);
    } else {
        PG_RS(D3DRS_TEXTUREFACTOR,0xFFFFFFFFu);
        PG_TSS(D3DTSS_COLOROP,D3DTOP_MODULATE2X);PG_TSS(D3DTSS_COLORARG1,0);PG_TSS(D3DTSS_COLORARG2,3);
        PG_TSS(D3DTSS_ALPHAOP,D3DTOP_SELECTARG1);PG_TSS(D3DTSS_ALPHAARG1,0);PG_TSS(D3DTSS_ALPHAARG2,0);
    }
    unsigned sampler_count=profile==PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC ? 4u : profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 ? 2u :
        (profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB ? 4u : 1u);
    for (unsigned s=0;s<sampler_count;s++) {
        uint32_t address=profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 ?
            PG_REG(NV097_SET_TEXTURE_ADDRESS+s*0x40) : 0x303u;
        unsigned address_u=address&7,address_v=(address>>8)&7;
        if(address_u<1 || address_u>5) address_u=D3DTADDRESS_CLAMP;
        if(address_v<1 || address_v>5) address_v=D3DTADDRESS_CLAMP;
        PG_TSS_STAGE(s,D3DTSS_ADDRESSU,address_u);PG_TSS_STAGE(s,D3DTSS_ADDRESSV,address_v);
        PG_TSS_STAGE(s,D3DTSS_MINFILTER,D3DTEXF_LINEAR);PG_TSS_STAGE(s,D3DTSS_MAGFILTER,D3DTEXF_LINEAR);
        PG_TSS_STAGE(s,D3DTSS_MIPFILTER,D3DTEXF_NONE);PG_TSS_STAGE(s,D3DTSS_MAXMIPLEVEL,0);
        PG_TSS_STAGE(s,D3DTSS_MIPMAPLODBIAS,0);
    }
    if(scene_solid_diag && getenv("DAH2_SCENE_ONLY_COUNT") &&
       getenv("DAH2_TEST_WINDOW_HIDDEN"))
        pgraph_clear_array_target(0xF0u,0xFFFF0000u);
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 &&
       getenv("DAH2_SCENE_CLEAR_DEPTH_DIAGNOSTIC") &&
       getenv("DAH2_TEST_WINDOW_HIDDEN")) {
        static unsigned cleared_frame=UINT_MAX;
        if(cleared_frame!=g_pg.stats.frames) {
            int slot=pgraph_surface_index(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
            if(slot>=0) ID3D11DeviceContext_ClearDepthStencilView(
                d3d8_GetD3D11Context(),g_pg.array_surfaces[slot].dsv,
                D3D11_CLEAR_DEPTH|D3D11_CLEAR_STENCIL,1.0f,0);
            cleared_frame=g_pg.stats.frames;
        }
    }
    if(postprocess_diag) {
        static unsigned postprocess_state_reports;
        if(postprocess_state_reports<24) {
            fprintf(stdout,"[PGRAPH-POST-STATE] frame=%u profile=%u target=%08X source=%08X depth=%d func=%08X write=%08X cull=%d alpha=%d blend=%d sf=%08X df=%08X eq=%08X mask=%08X vertices=",
                g_pg.stats.frames,profile,PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),
                PG_REG(NV097_SET_TEXTURE_OFFSET),g_pg.depth_test,PG_REG(NV097_SET_DEPTH_FUNC),
                PG_REG(NV097_SET_DEPTH_MASK),g_pg.cull_enable,g_pg.alpha_test,g_pg.blend_enable,
                g_pg.blend_sfactor,g_pg.blend_dfactor,PG_REG(NV097_SET_BLEND_EQUATION),g_pg.color_mask);
            for(unsigned i=0;i<g_pg.index_count;i++) {
                OutputVertex *vertex=(OutputVertex *)((unsigned char *)vertices+i*vertex_stride);
                fprintf(stdout,"%s%u:(%.3f,%.3f %.5f,%.5f %08X)",i ? " " : "",
                    i,vertex->x,vertex->y,vertex->u,vertex->v,vertex->color);
            }
            fprintf(stdout,"\n");fflush(stdout);postprocess_state_reports++;
        }
    }
    {   /* DAH2_DRAW_DUMP=<first>,<last>: one line of state per accepted draw in that frame window */
        static int dump_lo=-2,dump_hi=-2;
        if(dump_lo==-2) { const char *e=getenv("DAH2_DRAW_DUMP"); dump_lo=dump_hi=-1; if(e) sscanf(e,"%d,%d",&dump_lo,&dump_hi); }
        if(dump_lo>=0 && (int)g_pg.stats.frames>=dump_lo && (int)g_pg.stats.frames<=dump_hi) {
            fprintf(stdout,"[PGRAPH-DRAW] f=%u prof=%u n=%u tgt=%08X tex0=%08X z=%d zf=%X zmask=%X st=%08X stf=%X/%X/%X sto=%X/%X/%X al=%d af=%X ar=%X bl=%d bs=%X bd=%X cm=%08X cull=%d ctl0=%08X wc=%08X/%08X sc=%08X/%08X bx=%.0f..%.0f by=%.0f..%.0f""%s",
                g_pg.stats.frames,profile,g_pg.index_count,PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),PG_REG(NV097_SET_TEXTURE_OFFSET),
                g_pg.depth_test,PG_REG(NV097_SET_DEPTH_FUNC),PG_REG(NV097_SET_DEPTH_MASK),PG_REG(NV097_SET_STENCIL_TEST_ENABLE),
                PG_REG(NV097_SET_STENCIL_FUNC),PG_REG(NV097_SET_STENCIL_FUNC_REF),PG_REG(NV097_SET_STENCIL_FUNC_MASK),
                PG_REG(NV097_SET_STENCIL_OP_FAIL),PG_REG(NV097_SET_STENCIL_OP_ZFAIL),PG_REG(NV097_SET_STENCIL_OP_ZPASS),
                g_pg.alpha_test,PG_REG(NV097_SET_ALPHA_FUNC),PG_REG(NV097_SET_ALPHA_REF),g_pg.blend_enable,g_pg.blend_sfactor,g_pg.blend_dfactor,
                g_pg.color_mask,g_pg.cull_enable,PG_REG(NV097_SET_CONTROL0),PG_REG(NV097_SET_WINDOW_CLIP_HORIZONTAL),PG_REG(NV097_SET_WINDOW_CLIP_VERTICAL),
                g_pg.surface_clip_h,g_pg.surface_clip_v,scene_min_x,scene_max_x,scene_min_y,scene_max_y,"\n");
            fprintf(stdout,"   wclip type=%u:",PG_REG(NV097_SET_WINDOW_CLIP_TYPE));
            for(unsigned r=0;r<8;r++) fprintf(stdout," %08X/%08X",PG_REG(NV097_SET_WINDOW_CLIP_HORIZONTAL+r*4),PG_REG(NV097_SET_WINDOW_CLIP_VERTICAL+r*4));
            fprintf(stdout,"\n");
            if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 && g_pg.index_count<=12) {
                const PgraphSceneVertex *sv=(const PgraphSceneVertex *)vertices;
                unsigned nv=scene_triangle_list ? scene_triangle_vertex_count : g_pg.index_count;
                for(unsigned i=0;i<nv && i<12;i++)
                    fprintf(stdout,"   v%u: %.1f,%.1f z=%.5f rhw=%.5f d=%08X uv=%.3f,%.3f\n",i,sv[i].x,sv[i].y,sv[i].z,sv[i].rhw,sv[i].diffuse,sv[i].u0,sv[i].v0);
            }
            fflush(stdout);
        }
    }
    pgraph_draw_surface_probe_before(profile);
    PG_CALL(dev->lpVtbl->BeginScene(dev));
    d3d8_shaders_set_texel_coord_mask(texel_coord_mask);
    d3d8_shaders_set_fog_from_specular(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2);
    { unsigned alpha_one_mask=0;
      for(unsigned s=0;s<4;s++) {
          unsigned d=s*0x40;
          unsigned color=(PG_REG(NV097_SET_TEXTURE_FORMAT+d)>>8)&0xFFu;
          if((PG_REG(NV097_SET_TEXTURE_CONTROL0+d)&NV097_SET_TEXTURE_CONTROL0_ENABLE) &&
             (color==0x07u || color==0x1Eu)) alpha_one_mask|=1u<<s;
      }
      d3d8_shaders_set_texture_alpha_one_mask(alpha_one_mask);
    }
    unsigned primitives=scene_triangle_list ? scene_triangle_vertex_count/3u :
        (g_pg.draw_mode==5 ? g_pg.index_count/3 : g_pg.index_count-2);
    /* A scene strip may be fully rejected by the NV2A near-plane clip.  Xbox
     * treats the resulting zero-primitive submission as a successful no-op;
     * the D3D11 compatibility path rejects it as E_INVALIDARG. */
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2) {
        uint32_t wh=PG_REG(NV097_SET_WINDOW_CLIP_HORIZONTAL),wv=PG_REG(NV097_SET_WINDOW_CLIP_VERTICAL);
        int left=(int)(wh&0xFFFu),right=(int)((wh>>16)&0xFFFu),top=(int)(wv&0xFFFu),bottom=(int)((wv>>16)&0xFFFu);
        int cx=(int)(g_pg.surface_clip_h&0xFFFFu),cy=(int)(g_pg.surface_clip_v&0xFFFFu);
        int cw=cx+(int)(g_pg.surface_clip_h>>16),ch=cy+(int)(g_pg.surface_clip_v>>16);
        int sw=(int)viewport.Width,sh=(int)viewport.Height;
        if(left<cx) left=cx;
        if(top<cy) top=cy;
        if(right>cw) right=cw;
        if(bottom>ch) bottom=ch;
        if(left>0 || top>0 || right<sw || bottom<sh) d3d8_states_set_scissor(1,left,top,right>left?right:left,bottom>top?bottom:top);
    }
    HRESULT draw_result=primitives ? dev->lpVtbl->DrawPrimitiveUP(dev,
        scene_triangle_list || g_pg.draw_mode==5 ? D3DPT_TRIANGLELIST : D3DPT_TRIANGLESTRIP,
        primitives,vertices,(UINT)vertex_stride) : S_OK;
    HRESULT end_result=dev->lpVtbl->EndScene(dev);
    if((FAILED(draw_result) || FAILED(end_result)) && getenv("DAH2_TEST_WINDOW_HIDDEN")) {
        fprintf(stdout,
            "[PGRAPH-DRAW-HRESULT] frame=%u profile=%u count=%u target=%08X texture=%08X "
            "draw=%08X end=%08X primitives=%u stride=%u\n",
            g_pg.stats.frames,profile,g_pg.index_count,
            PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),PG_REG(NV097_SET_TEXTURE_OFFSET),
            (unsigned)draw_result,(unsigned)end_result,primitives,(unsigned)vertex_stride);
        fflush(stdout);
    }
    d3d8_states_set_scissor(0,0,0,0,0);
    d3d8_shaders_set_texel_coord_mask(0);
    d3d8_shaders_set_fog_from_specular(0);
    d3d8_shaders_set_texture_alpha_one_mask(0);
    PG_CALL(draw_result);PG_CALL(end_result);
    pgraph_record_profile_result(profile,g_pg.index_source,primitives,0);
    if(profile==PGRAPH_ARRAY_PROFILE_DAH2_SCENE_GENERIC) { g_dah2_pg_generic_draws++;g_dah2_pg_generic_prims+=primitives; }
    pgraph_draw_surface_probe_after();
    if(postprocess_diag)
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"post-target");
    if(getenv("DAH2_SURFACE_TIMELINE_DIAGNOSTIC") && getenv("DAH2_TEST_WINDOW_HIDDEN"))
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"draw-after");
    if(profile>=PGRAPH_ARRAY_PROFILE_DAH2_SCENE_LIT2 &&
       getenv("DAH2_SCENE_ONLY_COUNT") && getenv("DAH2_TEST_WINDOW_HIDDEN"))
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"isolated-scene");
    if (g_pg.stats.indexed_draws<8)
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"early-target");
    if (title_content_trace)
        pgraph_report_surface(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET),"target");
    pgraph_copy_primary_to_backbuffer(PG_REG(NV097_SET_SURFACE_COLOR_OFFSET));
    g_pg.stats.draw_calls++;g_pg.stats.indexed_draws++;g_pg.stats.vertices_submitted+=g_pg.index_count;
    { static unsigned profile_reports[9];
      if (g_pg.stats.indexed_draws<=2 || (profile<9 && profile_reports[profile]<8)) {
        fprintf(stderr,"[PGRAPH-ARRAY] submitted profile=%u mode=%u indices=%u shader=%u texture=%ux%u pitch=%u\n",
            profile,g_pg.draw_mode,g_pg.index_count,length,width,height,pitch);
        if (profile<9) profile_reports[profile]++;
      }
    }
    free(vertices);
    return;
rejected:
    nv2a_draw_vertex_cache_destroy(&vertex_cache);
    telemetry->reason=reason;telemetry->detail=detail;
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
