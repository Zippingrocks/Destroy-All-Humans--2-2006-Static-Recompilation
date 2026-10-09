/* recomp_mmx.h - 64-bit MMX integer helpers for the lifted guest code.
 *
 * The lifter emits `mmN = MMX_<MNEMONIC>(mmN, src)` for the packed integer instructions of MMX / the SSE integer extensions.
 * mm0..mm7 are uint64_t locals of the lifted function (the retail code never carries an MMX value across a call: every use
 * sits between loads from memory and an emms).  Lane 0 is the low-order lane exactly as on x86.  Everything is written as plain
 * C on explicit lanes so the semantics (saturation, signedness, shift-count clamping) are visible and host-independent. */
#ifndef RECOMP_MMX_H
#define RECOMP_MMX_H
#include <stdint.h>

typedef union { uint64_t q; uint8_t b[8]; int8_t sb[8]; uint16_t w[4]; int16_t sw[4]; uint32_t d[2]; int32_t sd[2]; } recomp_mm_t;

#define MMX_LANES_B(name, expr) static inline uint64_t name(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; r.q = 0; \
    for (i = 0; i < 8; ++i) { expr; } return r.q; }
#define MMX_LANES_W(name, expr) static inline uint64_t name(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; r.q = 0; \
    for (i = 0; i < 4; ++i) { expr; } return r.q; }
#define MMX_LANES_D(name, expr) static inline uint64_t name(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; r.q = 0; \
    for (i = 0; i < 2; ++i) { expr; } return r.q; }

static inline int32_t recomp_sat_s8(int32_t v)  { return v > 127 ? 127 : (v < -128 ? -128 : v); }
static inline int32_t recomp_sat_s16(int32_t v) { return v > 32767 ? 32767 : (v < -32768 ? -32768 : v); }
static inline int32_t recomp_sat_u8(int32_t v)  { return v > 255 ? 255 : (v < 0 ? 0 : v); }
static inline int32_t recomp_sat_u16(int32_t v) { return v > 65535 ? 65535 : (v < 0 ? 0 : v); }

/* add / subtract */
MMX_LANES_B(MMX_PADDB,   r.b[i] = (uint8_t)(a.b[i] + b.b[i]))
MMX_LANES_W(MMX_PADDW,   r.w[i] = (uint16_t)(a.w[i] + b.w[i]))
MMX_LANES_D(MMX_PADDD,   r.d[i] = a.d[i] + b.d[i])
MMX_LANES_B(MMX_PSUBB,   r.b[i] = (uint8_t)(a.b[i] - b.b[i]))
MMX_LANES_W(MMX_PSUBW,   r.w[i] = (uint16_t)(a.w[i] - b.w[i]))
MMX_LANES_D(MMX_PSUBD,   r.d[i] = a.d[i] - b.d[i])
MMX_LANES_B(MMX_PADDSB,  r.sb[i] = (int8_t)recomp_sat_s8((int32_t)a.sb[i] + b.sb[i]))
MMX_LANES_W(MMX_PADDSW,  r.sw[i] = (int16_t)recomp_sat_s16((int32_t)a.sw[i] + b.sw[i]))
MMX_LANES_B(MMX_PADDUSB, r.b[i] = (uint8_t)recomp_sat_u8((int32_t)a.b[i] + b.b[i]))
MMX_LANES_W(MMX_PADDUSW, r.w[i] = (uint16_t)recomp_sat_u16((int32_t)a.w[i] + b.w[i]))
MMX_LANES_B(MMX_PSUBSB,  r.sb[i] = (int8_t)recomp_sat_s8((int32_t)a.sb[i] - b.sb[i]))
MMX_LANES_W(MMX_PSUBSW,  r.sw[i] = (int16_t)recomp_sat_s16((int32_t)a.sw[i] - b.sw[i]))
MMX_LANES_B(MMX_PSUBUSB, r.b[i] = (uint8_t)recomp_sat_u8((int32_t)a.b[i] - b.b[i]))
MMX_LANES_W(MMX_PSUBUSW, r.w[i] = (uint16_t)recomp_sat_u16((int32_t)a.w[i] - b.w[i]))

/* compare (all-ones / all-zeros lane masks) */
MMX_LANES_B(MMX_PCMPEQB, r.b[i] = a.b[i] == b.b[i] ? 0xFFu : 0u)
MMX_LANES_W(MMX_PCMPEQW, r.w[i] = a.w[i] == b.w[i] ? 0xFFFFu : 0u)
MMX_LANES_D(MMX_PCMPEQD, r.d[i] = a.d[i] == b.d[i] ? 0xFFFFFFFFu : 0u)
MMX_LANES_B(MMX_PCMPGTB, r.b[i] = a.sb[i] > b.sb[i] ? 0xFFu : 0u)
MMX_LANES_W(MMX_PCMPGTW, r.w[i] = a.sw[i] > b.sw[i] ? 0xFFFFu : 0u)
MMX_LANES_D(MMX_PCMPGTD, r.d[i] = a.sd[i] > b.sd[i] ? 0xFFFFFFFFu : 0u)

/* logic */
#define MMX_PAND(a, b)  ((uint64_t)(a) & (uint64_t)(b))
#define MMX_PANDN(a, b) (~(uint64_t)(a) & (uint64_t)(b))
#define MMX_POR(a, b)   ((uint64_t)(a) | (uint64_t)(b))
#define MMX_PXOR(a, b)  ((uint64_t)(a) ^ (uint64_t)(b))

/* multiply */
MMX_LANES_W(MMX_PMULLW,  r.w[i] = (uint16_t)((int32_t)a.sw[i] * (int32_t)b.sw[i]))
MMX_LANES_W(MMX_PMULHW,  r.w[i] = (uint16_t)(((int32_t)a.sw[i] * (int32_t)b.sw[i]) >> 16))
MMX_LANES_W(MMX_PMULHUW, r.w[i] = (uint16_t)(((uint32_t)a.w[i] * (uint32_t)b.w[i]) >> 16))
static inline uint64_t MMX_PMADDWD(uint64_t a_, uint64_t b_)
{
    recomp_mm_t a, b, r; a.q = a_; b.q = b_;
    r.sd[0] = (int32_t)((int32_t)a.sw[0] * b.sw[0] + (int32_t)a.sw[1] * b.sw[1]);
    r.sd[1] = (int32_t)((int32_t)a.sw[2] * b.sw[2] + (int32_t)a.sw[3] * b.sw[3]);
    return r.q;
}

/* average / min / max / sad */
MMX_LANES_B(MMX_PAVGB,  r.b[i] = (uint8_t)(((uint32_t)a.b[i] + b.b[i] + 1u) >> 1))
MMX_LANES_W(MMX_PAVGW,  r.w[i] = (uint16_t)(((uint32_t)a.w[i] + b.w[i] + 1u) >> 1))
MMX_LANES_B(MMX_PMAXUB, r.b[i] = a.b[i] > b.b[i] ? a.b[i] : b.b[i])
MMX_LANES_B(MMX_PMINUB, r.b[i] = a.b[i] < b.b[i] ? a.b[i] : b.b[i])
MMX_LANES_W(MMX_PMAXSW, r.sw[i] = a.sw[i] > b.sw[i] ? a.sw[i] : b.sw[i])
MMX_LANES_W(MMX_PMINSW, r.sw[i] = a.sw[i] < b.sw[i] ? a.sw[i] : b.sw[i])
static inline uint64_t MMX_PSADBW(uint64_t a_, uint64_t b_)
{
    recomp_mm_t a, b; uint32_t s = 0; int i; a.q = a_; b.q = b_;
    for (i = 0; i < 8; ++i) s += a.b[i] > b.b[i] ? (uint32_t)(a.b[i] - b.b[i]) : (uint32_t)(b.b[i] - a.b[i]);
    return (uint64_t)s;
}

/* unpack / pack */
static inline uint64_t MMX_PUNPCKLBW(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; for (i = 0; i < 4; ++i) { r.b[2 * i] = a.b[i]; r.b[2 * i + 1] = b.b[i]; } return r.q; }
static inline uint64_t MMX_PUNPCKHBW(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; for (i = 0; i < 4; ++i) { r.b[2 * i] = a.b[4 + i]; r.b[2 * i + 1] = b.b[4 + i]; } return r.q; }
static inline uint64_t MMX_PUNPCKLWD(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; for (i = 0; i < 2; ++i) { r.w[2 * i] = a.w[i]; r.w[2 * i + 1] = b.w[i]; } return r.q; }
static inline uint64_t MMX_PUNPCKHWD(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; for (i = 0; i < 2; ++i) { r.w[2 * i] = a.w[2 + i]; r.w[2 * i + 1] = b.w[2 + i]; } return r.q; }
static inline uint64_t MMX_PUNPCKLDQ(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; a.q = a_; b.q = b_; r.d[0] = a.d[0]; r.d[1] = b.d[0]; return r.q; }
static inline uint64_t MMX_PUNPCKHDQ(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; a.q = a_; b.q = b_; r.d[0] = a.d[1]; r.d[1] = b.d[1]; return r.q; }
static inline uint64_t MMX_PACKSSWB(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; for (i = 0; i < 4; ++i) { r.sb[i] = (int8_t)recomp_sat_s8(a.sw[i]); r.sb[4 + i] = (int8_t)recomp_sat_s8(b.sw[i]); } return r.q; }
static inline uint64_t MMX_PACKUSWB(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; for (i = 0; i < 4; ++i) { r.b[i] = (uint8_t)recomp_sat_u8(a.sw[i]); r.b[4 + i] = (uint8_t)recomp_sat_u8(b.sw[i]); } return r.q; }
static inline uint64_t MMX_PACKSSDW(uint64_t a_, uint64_t b_) { recomp_mm_t a, b, r; int i; a.q = a_; b.q = b_; for (i = 0; i < 2; ++i) { r.sw[i] = (int16_t)recomp_sat_s16(a.sd[i]); r.sw[2 + i] = (int16_t)recomp_sat_s16(b.sd[i]); } return r.q; }

/* shifts: the count is a full 64-bit value (imm8 zero-extended, or the whole mm/m64 operand) */
static inline uint64_t MMX_PSLLW(uint64_t a_, uint64_t c) { recomp_mm_t a; int i; a.q = a_; for (i = 0; i < 4; ++i) a.w[i] = c > 15 ? 0 : (uint16_t)(a.w[i] << c); return a.q; }
static inline uint64_t MMX_PSRLW(uint64_t a_, uint64_t c) { recomp_mm_t a; int i; a.q = a_; for (i = 0; i < 4; ++i) a.w[i] = c > 15 ? 0 : (uint16_t)(a.w[i] >> c); return a.q; }
static inline uint64_t MMX_PSRAW(uint64_t a_, uint64_t c) { recomp_mm_t a; int i; a.q = a_; for (i = 0; i < 4; ++i) a.sw[i] = (int16_t)(a.sw[i] >> (c > 15 ? 15 : (int)c)); return a.q; }
static inline uint64_t MMX_PSLLD(uint64_t a_, uint64_t c) { recomp_mm_t a; int i; a.q = a_; for (i = 0; i < 2; ++i) a.d[i] = c > 31 ? 0 : a.d[i] << c; return a.q; }
static inline uint64_t MMX_PSRLD(uint64_t a_, uint64_t c) { recomp_mm_t a; int i; a.q = a_; for (i = 0; i < 2; ++i) a.d[i] = c > 31 ? 0 : a.d[i] >> c; return a.q; }
static inline uint64_t MMX_PSRAD(uint64_t a_, uint64_t c) { recomp_mm_t a; int i; a.q = a_; for (i = 0; i < 2; ++i) a.sd[i] = a.sd[i] >> (c > 31 ? 31 : (int)c); return a.q; }
static inline uint64_t MMX_PSLLQ(uint64_t a, uint64_t c) { return c > 63 ? 0 : a << c; }
static inline uint64_t MMX_PSRLQ(uint64_t a, uint64_t c) { return c > 63 ? 0 : a >> c; }

/* shuffle / extract / insert / mask */
static inline uint64_t MMX_PSHUFW(uint64_t a_, uint32_t imm) { recomp_mm_t a, r; int i; a.q = a_; for (i = 0; i < 4; ++i) r.w[i] = a.w[(imm >> (2 * i)) & 3u]; return r.q; }
static inline uint32_t MMX_PMOVMSKB(uint64_t a_) { recomp_mm_t a; uint32_t m = 0; int i; a.q = a_; for (i = 0; i < 8; ++i) m |= (uint32_t)(a.b[i] >> 7) << i; return m; }
static inline uint32_t MMX_PEXTRW(uint64_t a_, uint32_t imm) { recomp_mm_t a; a.q = a_; return a.w[imm & 3u]; }
static inline uint64_t MMX_PINSRW(uint64_t a_, uint32_t v, uint32_t imm) { recomp_mm_t a; a.q = a_; a.w[imm & 3u] = (uint16_t)v; return a.q; }
#endif
