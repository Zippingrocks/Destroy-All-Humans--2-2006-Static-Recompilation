#include "nv2a_vertex_program.h"
#include <string.h>

/* Encoding facts cross-checked against the primary NV2A reference:
 * https://github.com/xemu-project/xemu/blob/master/hw/xbox/nv2a/pgraph/glsl/vsh-prog.c
 * Implementation below is independent and intentionally supports only the
 * MOV/MUL/NOP subset observed in the DAH2 boot and title draws, not xemu's
 * general translator.
 * DWORD0 is reserved; opcodes live in DWORD1, not DWORD0.
 */
static unsigned field(uint32_t word, unsigned shift, unsigned mask) {
    return (word >> shift) & mask;
}

void nv2a_vp_decode_instruction(const uint32_t w[4], NV2AVPInstruction *d) {
    if (!w || !d) return;
    memset(d, 0, sizeof(*d));
    d->reserved_word = w[0];
    d->mac = field(w[1],21,15); d->ilu = field(w[1],25,7);
    d->constant = field(w[1],13,255); d->attribute = field(w[1],9,15);
    d->source[0].mux = field(w[2],26,3);
    d->source[0].temporary = field(w[2],28,15);
    d->source[0].negate = field(w[1],8,1);
    d->source[1].mux = field(w[2],11,3);
    d->source[1].temporary = field(w[2],13,15);
    d->source[1].negate = field(w[2],25,1);
    d->source[2].mux = field(w[3],28,3);
    d->source[2].temporary = ((w[2]&3)<<2) | field(w[3],30,3);
    d->source[2].negate = field(w[2],10,1);
    for (unsigned c=0;c<4;c++) {
        d->source[0].swizzle[c] = field(w[1],6-2*c,3);
        d->source[1].swizzle[c] = field(w[2],23-2*c,3);
        d->source[2].swizzle[c] = field(w[2],8-2*c,3);
    }
    d->mac_mask = field(w[3],24,15); d->temporary = field(w[3],20,15);
    d->ilu_mask = field(w[3],16,15); d->output_mask = field(w[3],12,15);
    d->output_is_register = field(w[3],11,1);
    d->output_address = field(w[3],3,255);
    d->output_is_ilu = field(w[3],2,1);
    d->relative = field(w[3],1,1); d->final = w[3]&1;
}

static NV2AVPStatus supported(const NV2AVPInstruction *d) {
    if (d->reserved_word || d->ilu || (d->mac != 0 && d->mac != 1 && d->mac != 3) || d->relative)
        return NV2A_VP_UNSUPPORTED_OPCODE;
    if (!d->mac) {
        return (d->mac_mask || d->ilu_mask || d->output_mask) ?
            NV2A_VP_INVALID_DESTINATION : NV2A_VP_OK;
    }
    unsigned source_count=d->mac==3 ? 3 : 1;
    for (unsigned i=0;i<source_count;i+=2) {
        const NV2AVPSource *a=&d->source[i];
        if (!a->mux || (a->mux == 1 && a->temporary > 12) ||
            (a->mux == 3 && d->constant >= NV2A_VP_CONSTANTS))
            return NV2A_VP_INVALID_SOURCE;
    }
    if (d->ilu_mask || (d->mac_mask && d->temporary > 12))
        return NV2A_VP_INVALID_DESTINATION;
    if (d->output_mask && (!d->output_is_register || d->output_is_ilu ||
        d->output_address >= NV2A_VP_OUTPUTS ||
        d->output_address == 1 || d->output_address == 2))
        return NV2A_VP_INVALID_DESTINATION;
    /* Non-x partial fog masks have special lane routing, not a vector store.
     * The captured program uses xyzw; only xyzw/x are admitted here. */
    if (d->output_address == 5 && d->output_mask &&
        d->output_mask != 15 && d->output_mask != 8)
        return NV2A_VP_INVALID_DESTINATION;
    return NV2A_VP_OK;
}

NV2AVPStatus nv2a_vp_validate_mov(const uint32_t *program, unsigned slots,
    unsigned start, unsigned *length, unsigned *bad_slot) {
    if (length) *length = 0;
    if (bad_slot) *bad_slot = start;
    if (!program || !slots || slots > NV2A_VP_SLOTS || start >= slots)
        return NV2A_VP_INVALID_ARGUMENT;
    for (unsigned slot=start;slot<slots;slot++) {
        NV2AVPInstruction d;
        nv2a_vp_decode_instruction(program+slot*4, &d);
        NV2AVPStatus status = supported(&d);
        if (status != NV2A_VP_OK) {
            if (bad_slot) *bad_slot = slot;
            return status;
        }
        if (d.final) {
            if (length) *length = slot-start+1;
            return NV2A_VP_OK;
        }
    }
    if (bad_slot) *bad_slot = slots;
    return NV2A_VP_MISSING_FINAL;
}

static void masked_store(float dest[4], const float value[4], unsigned mask) {
    for (unsigned c=0;c<4;c++) if (mask & (8u>>c)) dest[c] = value[c];
}

static const float *source_value(const NV2AVPSource *source,unsigned attribute,unsigned constant,
    const float attributes[NV2A_VP_ATTRIBUTES][4],const float constants[NV2A_VP_CONSTANTS][4],
    float temporaries[12][4],const NV2AVertexResult *result) {
    return source->mux==2 ? attributes[attribute] : source->mux==3 ? constants[constant] :
        source->temporary==12 ? result->output[0] : temporaries[source->temporary];
}

NV2AVPStatus nv2a_vp_execute_mov(const uint32_t *program, unsigned slots,
    unsigned start, const float attributes[NV2A_VP_ATTRIBUTES][4],
    const float constants[NV2A_VP_CONSTANTS][4], NV2AVertexResult *out) {
    unsigned length;
    if (!attributes || !constants || !out) return NV2A_VP_INVALID_ARGUMENT;
    NV2AVPStatus status = nv2a_vp_validate_mov(program,slots,start,&length,0);
    if (status != NV2A_VP_OK) return status;
    float temporaries[12][4] = {{0}};
    NV2AVertexResult result;
    memset(&result,0,sizeof(result));
    for (unsigned o=0;o<NV2A_VP_OUTPUTS;o++) result.output[o][3]=1.0f;
    for (unsigned slot=start;slot<start+length;slot++) {
        NV2AVPInstruction d;
        nv2a_vp_decode_instruction(program+slot*4,&d);
        if (!d.mac) continue;
        const NV2AVPSource *a = &d.source[0];
        const float *src = source_value(a,d.attribute,d.constant,attributes,constants,temporaries,&result);
        const NV2AVPSource *csrc_desc=&d.source[2];
        const float *csrc=d.mac==3 ? source_value(csrc_desc,d.attribute,d.constant,
            attributes,constants,temporaries,&result) : NULL;
        float value[4];
        for (unsigned c=0;c<4;c++) {
            value[c]=src[a->swizzle[c]];
            if (a->negate) value[c]=-value[c];
            if (d.mac==3) {
                float multiplier=csrc[csrc_desc->swizzle[c]];
                if (csrc_desc->negate) multiplier=-multiplier;
                value[c]*=multiplier;
            }
        }
        if (d.mac_mask) {
            float *dst = d.temporary==12 ? result.output[0] : temporaries[d.temporary];
            masked_store(dst,value,d.mac_mask);
            if (d.temporary==12) result.written_mask[0] |= (uint8_t)d.mac_mask;
        }
        if (d.output_mask) {
            masked_store(result.output[d.output_address],value,d.output_mask);
            result.written_mask[d.output_address] |= (uint8_t)d.output_mask;
        }
    }
    *out=result;
    return NV2A_VP_OK;
}

NV2AVPStatus nv2a_vp_decode_attribute(uint32_t format, const void *bytes,
    size_t byte_count, float out[4]) {
    unsigned type=format&15, count=(format>>4)&15;
    float value[4]={0,0,0,1};
    if (!bytes || !out) return NV2A_VP_INVALID_ARGUMENT;
    if (!count || count>4 || (type!=2 && !(type==0 && count==4)))
        return NV2A_VP_UNSUPPORTED_FORMAT;
    size_t needed=type==2 ? count*4 : 4;
    if (byte_count<needed) return NV2A_VP_INVALID_ARGUMENT;
    const uint8_t *p=(const uint8_t *)bytes;
    if (type==2) {
        for (unsigned c=0;c<count;c++) {
            uint32_t bits=(uint32_t)p[c*4] | ((uint32_t)p[c*4+1]<<8) |
                ((uint32_t)p[c*4+2]<<16) | ((uint32_t)p[c*4+3]<<24);
            memcpy(&value[c],&bits,4);
        }
    } else {
        value[0]=p[2]/255.0f;value[1]=p[1]/255.0f;
        value[2]=p[0]/255.0f;value[3]=p[3]/255.0f;
    }
    memcpy(out,value,sizeof(value));
    return NV2A_VP_OK;
}
