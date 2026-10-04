#ifndef NV2A_VERTEX_PROGRAM_H
#define NV2A_VERTEX_PROGRAM_H

#include <stddef.h>
#include <stdint.h>

/* A deliberately bounded CPU path for observed MOV-only NV2A programs.
 * It is not a general vertex-shader translator. Unsupported state fails closed.
 * Outputs retain guest screen-space coordinates; renderer conversion is separate.
 */
#define NV2A_VP_SLOTS 136
#define NV2A_VP_CONSTANTS 192
#define NV2A_VP_ATTRIBUTES 16
#define NV2A_VP_OUTPUTS 13

typedef enum NV2AVPStatus {
    NV2A_VP_OK = 0,
    NV2A_VP_INVALID_ARGUMENT,
    NV2A_VP_UNSUPPORTED_OPCODE,
    NV2A_VP_INVALID_SOURCE,
    NV2A_VP_INVALID_DESTINATION,
    NV2A_VP_MISSING_FINAL,
    NV2A_VP_UNSUPPORTED_FORMAT
} NV2AVPStatus;

typedef struct NV2AVPSource {
    unsigned mux; /* 1=temp, 2=attribute, 3=constant; 0 is invalid when used. */
    unsigned temporary;
    unsigned negate;
    unsigned swizzle[4];
} NV2AVPSource;

typedef struct NV2AVPInstruction {
    uint32_t reserved_word;
    unsigned mac, ilu, constant, attribute;
    NV2AVPSource source[3];
    unsigned mac_mask, temporary, ilu_mask;
    unsigned output_mask, output_is_register, output_address, output_is_ilu;
    unsigned relative, final;
} NV2AVPInstruction;

typedef struct NV2AVertexResult {
    /* 0=oPos, 3=oD0, 4=oD1, 5=oFog, 6=oPts, 7/8=oB0/oB1, 9..12=oT0..3. */
    float output[NV2A_VP_OUTPUTS][4];
    uint8_t written_mask[NV2A_VP_OUTPUTS]; /* x=8, y=4, z=2, w=1 */
} NV2AVertexResult;

void nv2a_vp_decode_instruction(const uint32_t words[4], NV2AVPInstruction *out);
NV2AVPStatus nv2a_vp_validate_mov(const uint32_t *program, unsigned slots,
    unsigned start, unsigned *length, unsigned *bad_slot);
NV2AVPStatus nv2a_vp_execute_mov(const uint32_t *program, unsigned slots,
    unsigned start, const float attributes[NV2A_VP_ATTRIBUTES][4],
    const float constants[NV2A_VP_CONSTANTS][4], NV2AVertexResult *out);
/* Decode one attribute at an already bounds-checked guest address. Stride is
 * encoded in format but the caller owns index*stride/address overflow checks.
 * F1..4 and UB_D3D4 are supported; outputs are unchanged on error.
 */
NV2AVPStatus nv2a_vp_decode_attribute(uint32_t format, const void *bytes,
    size_t byte_count, float out[4]);

#endif
