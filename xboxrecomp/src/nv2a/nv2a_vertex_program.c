#include "nv2a_vertex_program.h"
#include <float.h>
#include <math.h>
#include <string.h>

volatile int nv2a_vp_last_error_slot=-1;
volatile int nv2a_vp_last_error_source=-1;
volatile int nv2a_vp_last_error_constant=-1;
volatile int nv2a_vp_last_error_a0=0;
volatile int nv2a_vp_last_error_index=-1;

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

static unsigned mac_sources(unsigned mac) {
    switch (mac) {
    case 1: case 13: return 1; /* MOV/ARL: A */
    case 2: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12: return 3; /* A,B */
    case 3: return 5; /* A,C */
    case 4: return 7; /* A,B,C */
    default: return 0;
    }
}

static int source_valid(const NV2AVPInstruction *d, unsigned index) {
    const NV2AVPSource *s=&d->source[index];
    if (!s->mux || s->mux>3 || (s->mux==1 && s->temporary>12)) return 0;
    return s->mux!=3 || d->relative || d->constant<NV2A_VP_CONSTANTS;
}

static NV2AVPStatus supported(const NV2AVPInstruction *d) {
    unsigned used=mac_sources(d->mac);
    if (d->reserved_word || d->mac>13 || d->ilu>7)
        return NV2A_VP_UNSUPPORTED_OPCODE;
    if ((!d->mac && d->mac_mask) || (!d->ilu && d->ilu_mask))
        return NV2A_VP_INVALID_DESTINATION;
    if (((used&1) && !source_valid(d,0)) || ((used&2) && !source_valid(d,1)) ||
        (((used&4) || d->ilu) && !source_valid(d,2))) return NV2A_VP_INVALID_SOURCE;
    if ((d->mac_mask && d->mac!=13 && d->temporary>12) ||
        (d->ilu_mask && !d->mac && d->temporary>12)) return NV2A_VP_INVALID_DESTINATION;
    if (d->output_mask && (!d->output_is_register || d->output_address>=NV2A_VP_OUTPUTS ||
        d->output_address==1 || d->output_address==2 ||
        (d->output_is_ilu ? !d->ilu : !d->mac))) return NV2A_VP_INVALID_DESTINATION;
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

NV2AVPStatus nv2a_vp_prepare_mov(const uint32_t *program,unsigned slots,
    unsigned start,NV2AVPPreparedProgram *out,unsigned *bad_slot) {
    if(bad_slot)*bad_slot=start;
    if(!out)return NV2A_VP_INVALID_ARGUMENT;
    out->start=start;out->length=0;out->status=NV2A_VP_INVALID_ARGUMENT;
    if(!program || !slots || slots>NV2A_VP_SLOTS || start>=slots)return out->status;
    for(unsigned slot=start;slot<slots;slot++) {
        unsigned index=slot-start;
        NV2AVPInstruction *d=&out->instruction[index];
        nv2a_vp_decode_instruction(program+slot*4,d);
        out->status=supported(d);
        if(out->status!=NV2A_VP_OK) {
            if(bad_slot)*bad_slot=slot;
            return out->status;
        }
        out->sources[index]=(uint8_t)mac_sources(d->mac);
        if(d->final) {
            out->length=index+1;return NV2A_VP_OK;
        }
    }
    if(bad_slot)*bad_slot=slots;
    out->status=NV2A_VP_MISSING_FINAL;return out->status;
}

static void masked_store(float dest[4], const float value[4], unsigned mask) {
    for (unsigned c=0;c<4;c++) if (mask & (8u>>c)) dest[c]=value[c];
}

static void output_store(NV2AVertexResult *r,unsigned output,const float value[4],unsigned mask) {
    if (output==5) {
        unsigned dst=0;
        for (unsigned c=0;c<4;c++) if (mask&(8u>>c)) r->output[output][dst++]=value[c];
        r->written_mask[output]|=(uint8_t)((1u<<dst)-1u);
    } else {
        masked_store(r->output[output],value,mask);
        r->written_mask[output]|=(uint8_t)mask;
    }
}

static int fetch_source(const NV2AVPInstruction *d,unsigned slot,unsigned which,int a0,
    const float attributes[NV2A_VP_ATTRIBUTES][4],const float constants[NV2A_VP_CONSTANTS][4],
    float temporaries[12][4],const NV2AVertexResult *result,float value[4]) {
    const NV2AVPSource *s=&d->source[which]; const float *base=NULL;
    if (s->mux==1) base=s->temporary==12 ? result->output[0] : temporaries[s->temporary];
    else if (s->mux==2) base=attributes[d->attribute];
    else if (s->mux==3) {
        int index=(int)d->constant+(d->relative?a0:0);
        if (index<0 || index>=NV2A_VP_CONSTANTS) {
            nv2a_vp_last_error_slot=(int)slot;
            nv2a_vp_last_error_source=(int)which;
            nv2a_vp_last_error_constant=(int)d->constant;
            nv2a_vp_last_error_a0=a0;
            nv2a_vp_last_error_index=index;
            /* NV vertex-program parameter reads outside the constant file
             * return (0,0,0,0); they do not invalidate the draw. */
            memset(value,0,4*sizeof(*value));
            return 1;
        }
        base=constants[index];
    } else return 0;
    for (unsigned c=0;c<4;c++) value[c]=s->negate ? -base[s->swizzle[c]] : base[s->swizzle[c]];
    return 1;
}

static float nv_mul(float a,float b) { return (a==0.0f || b==0.0f) ? 0.0f : a*b; }

static void mac_value(unsigned op,const float a[4],const float b[4],const float c[4],float out[4]) {
    float scalar;
    switch(op) {
    case 1: memcpy(out,a,16); break;
    case 2: for(unsigned i=0;i<4;i++)out[i]=nv_mul(a[i],b[i]); break;
    case 3: for(unsigned i=0;i<4;i++)out[i]=a[i]+c[i]; break;
    case 4: for(unsigned i=0;i<4;i++)out[i]=nv_mul(a[i],b[i])+c[i]; break;
    case 5: scalar=nv_mul(a[0],b[0])+nv_mul(a[1],b[1])+nv_mul(a[2],b[2]); for(unsigned i=0;i<4;i++)out[i]=scalar; break;
    case 6: scalar=nv_mul(a[0],b[0])+nv_mul(a[1],b[1])+nv_mul(a[2],b[2])+b[3]; for(unsigned i=0;i<4;i++)out[i]=scalar; break;
    case 7: scalar=nv_mul(a[0],b[0])+nv_mul(a[1],b[1])+nv_mul(a[2],b[2])+nv_mul(a[3],b[3]); for(unsigned i=0;i<4;i++)out[i]=scalar; break;
    case 8: out[0]=1.0f;out[1]=nv_mul(a[1],b[1]);out[2]=a[2];out[3]=b[3]; break; /* DST */
    case 9: for(unsigned i=0;i<4;i++)out[i]=fminf(a[i],b[i]); break;
    case 10: for(unsigned i=0;i<4;i++)out[i]=fmaxf(a[i],b[i]); break;
    case 11: for(unsigned i=0;i<4;i++)out[i]=a[i]<b[i]?1.0f:0.0f; break;
    case 12: for(unsigned i=0;i<4;i++)out[i]=a[i]>=b[i]?1.0f:0.0f; break;
    default: memset(out,0,16); break;
    }
}

static float clamp_away_zero_inf(float v) {
    const float lo=5.421010862427522e-20f,hi=1.8446744073709552e19f;
    return signbit(v) ? fmaxf(-hi,fminf(-lo,v)) : fminf(hi,fmaxf(lo,v));
}

static void ilu_value(unsigned op,const float c[4],float out[4]) {
    float x=c[0],e,t;
    switch(op) {
    case 1: memcpy(out,c,16); break;
    case 2: for(unsigned i=0;i<4;i++)out[i]=1.0f/x; break;
    case 3: t=clamp_away_zero_inf(1.0f/x);for(unsigned i=0;i<4;i++)out[i]=t;break;
    case 4: t=x==0.0f?INFINITY:isinf(x)?0.0f:1.0f/sqrtf(fabsf(x));for(unsigned i=0;i<4;i++)out[i]=t;break;
    case 5: e=floorf(x);out[0]=exp2f(e);out[1]=x-e;out[2]=exp2f(x);out[3]=1;break;
    case 6: t=fabsf(x);if(t==0){out[0]=-INFINITY;out[1]=1;out[2]=-INFINITY;out[3]=1;}else{e=floorf(log2f(t));out[0]=e;out[1]=t/exp2f(e);out[2]=log2f(t);out[3]=1;}break;
    case 7: { float sx=fmaxf(c[0],0),sy=fmaxf(c[1],0),sw=fminf(127.99609375f,fmaxf(-127.99609375f,c[3]));out[0]=1;out[1]=sx;out[2]=sx>0?exp2f(sw*log2f(sy)):0;out[3]=1;break; }
    default: memset(out,0,16); break;
    }
}

NV2AVPStatus nv2a_vp_execute_mov(const uint32_t *program,unsigned slots,
    unsigned start,const float attributes[NV2A_VP_ATTRIBUTES][4],
    const float constants[NV2A_VP_CONSTANTS][4],NV2AVertexResult *out) {
    unsigned length;
    if(!attributes||!constants||!out)return NV2A_VP_INVALID_ARGUMENT;
    nv2a_vp_last_error_slot=-1;nv2a_vp_last_error_source=-1;
    nv2a_vp_last_error_constant=-1;nv2a_vp_last_error_a0=0;nv2a_vp_last_error_index=-1;
    NV2AVPStatus status=nv2a_vp_validate_mov(program,slots,start,&length,NULL);
    if(status!=NV2A_VP_OK)return status;
    float temporaries[12][4]={{0}};NV2AVertexResult result;memset(&result,0,sizeof(result));
    for(unsigned o=0;o<NV2A_VP_OUTPUTS;o++)result.output[o][3]=1;
    int a0=0;
    for(unsigned slot=start;slot<start+length;slot++) {
        NV2AVPInstruction d;float a[4]={0},b[4]={0},c[4]={0},mac[4]={0},ilu[4]={0};
        nv2a_vp_decode_instruction(program+slot*4,&d);unsigned used=mac_sources(d.mac);
        if((used&1)&&!fetch_source(&d,slot,0,a0,attributes,constants,temporaries,&result,a))return NV2A_VP_INVALID_SOURCE;
        if((used&2)&&!fetch_source(&d,slot,1,a0,attributes,constants,temporaries,&result,b))return NV2A_VP_INVALID_SOURCE;
        if(((used&4)||d.ilu)&&!fetch_source(&d,slot,2,a0,attributes,constants,temporaries,&result,c))return NV2A_VP_INVALID_SOURCE;
        if(d.mac&&d.mac!=13)mac_value(d.mac,a,b,c,mac);if(d.ilu)ilu_value(d.ilu,c,ilu);
        if(d.output_mask)output_store(&result,d.output_address,d.output_is_ilu?ilu:mac,d.output_mask);
        if(d.mac==13)a0=(int)floorf(a[0]+0.001f);
        else if(d.mac_mask&&!(d.ilu&&d.temporary==1)){float *dst=d.temporary==12?result.output[0]:temporaries[d.temporary];masked_store(dst,mac,d.mac_mask);if(d.temporary==12)result.written_mask[0]|=(uint8_t)d.mac_mask;}
        if(d.ilu_mask){unsigned reg=d.mac?1:d.temporary;float *dst=reg==12?result.output[0]:temporaries[reg];masked_store(dst,ilu,d.ilu_mask);if(reg==12)result.written_mask[0]|=(uint8_t)d.ilu_mask;}
    }
    *out=result;return NV2A_VP_OK;
}
NV2AVPStatus nv2a_vp_execute_prepared(const NV2AVPPreparedProgram *prepared,
    const float attributes[NV2A_VP_ATTRIBUTES][4],
    const float constants[NV2A_VP_CONSTANTS][4],NV2AVertexResult *out) {
    if(!attributes||!constants||!out)return NV2A_VP_INVALID_ARGUMENT;
    nv2a_vp_last_error_slot=-1;nv2a_vp_last_error_source=-1;
    nv2a_vp_last_error_constant=-1;nv2a_vp_last_error_a0=0;nv2a_vp_last_error_index=-1;
    if(!prepared)return NV2A_VP_INVALID_ARGUMENT;
    if(prepared->status!=NV2A_VP_OK)return prepared->status;
    if(!prepared->length || prepared->length>NV2A_VP_SLOTS ||
       prepared->start>=NV2A_VP_SLOTS || prepared->length>NV2A_VP_SLOTS-prepared->start)
        return NV2A_VP_INVALID_ARGUMENT;
    /* Identical arithmetic, temporary initialization, masked writes and error
     * metadata as execute_mov. Only immutable decode/validation work is reused. */
    float temporaries[12][4]={{0}};NV2AVertexResult result;memset(&result,0,sizeof(result));
    for(unsigned o=0;o<NV2A_VP_OUTPUTS;o++)result.output[o][3]=1;
    int a0=0;
    for(unsigned index=0;index<prepared->length;index++) {
        unsigned slot=prepared->start+index;
        const NV2AVPInstruction *d=&prepared->instruction[index];
        float a[4]={0},b[4]={0},c[4]={0},mac[4]={0},ilu[4]={0};
        unsigned used=prepared->sources[index];
        if((used&1)&&!fetch_source(d,slot,0,a0,attributes,constants,temporaries,&result,a))return NV2A_VP_INVALID_SOURCE;
        if((used&2)&&!fetch_source(d,slot,1,a0,attributes,constants,temporaries,&result,b))return NV2A_VP_INVALID_SOURCE;
        if(((used&4)||d->ilu)&&!fetch_source(d,slot,2,a0,attributes,constants,temporaries,&result,c))return NV2A_VP_INVALID_SOURCE;
        if(d->mac&&d->mac!=13)mac_value(d->mac,a,b,c,mac);if(d->ilu)ilu_value(d->ilu,c,ilu);
        if(d->output_mask)output_store(&result,d->output_address,d->output_is_ilu?ilu:mac,d->output_mask);
        if(d->mac==13)a0=(int)floorf(a[0]+0.001f);
        else if(d->mac_mask&&!(d->ilu&&d->temporary==1)){float *dst=d->temporary==12?result.output[0]:temporaries[d->temporary];masked_store(dst,mac,d->mac_mask);if(d->temporary==12)result.written_mask[0]|=(uint8_t)d->mac_mask;}
        if(d->ilu_mask){unsigned reg=d->mac?1:d->temporary;float *dst=reg==12?result.output[0]:temporaries[reg];masked_store(dst,ilu,d->ilu_mask);if(reg==12)result.written_mask[0]|=(uint8_t)d->ilu_mask;}
    }
    *out=result;return NV2A_VP_OK;
}

static float sext_norm(uint32_t raw,unsigned bits,float scale) {
    uint32_t sign=1u<<(bits-1);
    int32_t v=(int32_t)(raw&((1u<<bits)-1u));
    if(raw&sign) v-=(int32_t)(1u<<bits);
    float f=(float)v/scale;
    return f<-1.0f?-1.0f:f;
}

/* Vertex-array element types (NV097_SET_VERTEX_DATA_ARRAY_FORMAT_TYPE): 0 UB_D3D (BGRA bytes, normalized), 1 S1 (shorts, normalized),
 * 2 F, 4 UB_OGL (RGBA bytes, normalized), 5 S32K (shorts, raw), 6 CMP (11:11:10 packed, normalized).  Missing components default to
 * (0,0,0,1) like the hardware's current-value registers. */
NV2AVPStatus nv2a_vp_decode_attribute(uint32_t format, const void *bytes,
    size_t byte_count, float out[4]) {
    unsigned type=format&15,count=(format>>4)&15;float value[4]={0,0,0,1};
    if(!bytes||!out)return NV2A_VP_INVALID_ARGUMENT;
    if(type==6) count=3;
    if(!count||count>4||!(type==0||type==1||type==2||type==4||type==5||type==6))return NV2A_VP_UNSUPPORTED_FORMAT;
    if(type==0&&count!=4)return NV2A_VP_UNSUPPORTED_FORMAT;
    size_t needed=type==2?count*4:(type==1||type==5)?count*2:type==4?count:4;if(byte_count<needed)return NV2A_VP_INVALID_ARGUMENT;
    const uint8_t *p=(const uint8_t *)bytes;
    if(type==2)for(unsigned c=0;c<count;c++){uint32_t bits=(uint32_t)p[c*4]|((uint32_t)p[c*4+1]<<8)|((uint32_t)p[c*4+2]<<16)|((uint32_t)p[c*4+3]<<24);memcpy(&value[c],&bits,4);}
    else if(type==1)for(unsigned c=0;c<count;c++){int16_t raw=(int16_t)((uint16_t)p[c*2]|((uint16_t)p[c*2+1]<<8));value[c]=raw==-32768?-1.0f:(float)raw/32767.0f;}
    else if(type==5)for(unsigned c=0;c<count;c++){int16_t raw=(int16_t)((uint16_t)p[c*2]|((uint16_t)p[c*2+1]<<8));value[c]=(float)raw;}
    else if(type==4)for(unsigned c=0;c<count;c++)value[c]=p[c]/255.0f;
    else if(type==6){uint32_t v=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
        value[0]=sext_norm(v,11,1023.0f);value[1]=sext_norm(v>>11,11,1023.0f);value[2]=sext_norm(v>>22,10,511.0f);}
    else{value[0]=p[2]/255.0f;value[1]=p[1]/255.0f;value[2]=p[0]/255.0f;value[3]=p[3]/255.0f;}
    memcpy(out,value,sizeof(value));return NV2A_VP_OK;
}
