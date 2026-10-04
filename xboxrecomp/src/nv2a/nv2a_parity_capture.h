#ifndef NV2A_PARITY_CAPTURE_H
#define NV2A_PARITY_CAPTURE_H

/* Opt-in first-two-draw diagnostic. These are raw GPU state and memory
 * previews, not reconstructed images or claims that unsupported draws work. */
static PgraphGuestReader g_pg_guest_reader;
void pgraph_d3d11_set_guest_reader(PgraphGuestReader reader) {
    g_pg_guest_reader = reader;
}

static void pgraph_parity_words(const uint32_t *values, unsigned count) {
    fputc('[', stderr);
    for (unsigned i=0;i<count;i++)
        fprintf(stderr, "%s\"0x%08x\"", i ? "," : "", values[i]);
    fputc(']', stderr);
}

static void pgraph_parity_method(uint32_t method, uint32_t value) {
    static int enabled = -1;
    static uint32_t registers[0x2000/4], program[136*4], constants[192*4];
    static unsigned program_word, constant_word, draws, indices;
    if (enabled < 0) {
        char flag[8];
        DWORD length = GetEnvironmentVariableA("DAH2_PARITY_GPU", flag, sizeof(flag));
        enabled = length == 1 && flag[0] == '1';
    }
    if (!enabled) return;
    if (method < 0x2000 && !(method & 3)) registers[method/4] = value;
    if (method == NV097_SET_TRANSFORM_PROGRAM_LOAD) program_word = value < 136 ? value * 4 : 136*4;
    if (method == NV097_SET_TRANSFORM_CONSTANT_LOAD) constant_word = value < 192 ? value * 4 : 192*4;
    if (method >= NV097_SET_TRANSFORM_PROGRAM && method < NV097_SET_TRANSFORM_PROGRAM+0x80) {
        if (program_word < 136*4) program[program_word++] = value;
    }
    if (method >= NV097_SET_TRANSFORM_CONSTANT && method < NV097_SET_TRANSFORM_CONSTANT+0x80) {
        if (constant_word < 192*4) constants[constant_word++] = value;
    }
    if (draws && draws <= 2 && indices < 32 &&
        (method == NV097_ARRAY_ELEMENT16 || method == NV097_ARRAY_ELEMENT32 || method == NV097_DRAW_ARRAYS)) {
        indices++;
        fprintf(stderr, "[PARITY-GPU-INDEX] draw=%u method=%04x value=%08x\n", draws, method, value);
    }
    if (method != NV097_SET_BEGIN_END || !value) return;
    if (draws >= 2) { draws=3; return; }
    draws++; indices=0;
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-GPU] {\"schema\":\"dah2-gpu-draw-preview-v1\",\"draw\":%u,\"timing_perturbed\":true,\"registers\":", draws);
    pgraph_parity_words(registers, 0x2000/4);
    fprintf(stderr, ",\"program\":"); pgraph_parity_words(program, 136*4);
    fprintf(stderr, ",\"constants\":"); pgraph_parity_words(constants, 192*4);
    fprintf(stderr, ",\"vertex_previews\":[");
    for (unsigned a=0; a<16; a++) {
        uint32_t offset = registers[NV097_SET_VERTEX_DATA_ARRAY_OFFSET/4+a];
        uint32_t format = registers[NV097_SET_VERTEX_DATA_ARRAY_FORMAT/4+a];
        uint32_t words[32];
        fprintf(stderr, "%s{\"offset\":\"0x%08x\",\"format\":\"0x%08x\",\"first_128_bytes\":", a ? "," : "", offset, format);
        if ((format & 0xF0) && g_pg_guest_reader && g_pg_guest_reader(offset & 0x7FFFFFFF, words, sizeof(words)))
            pgraph_parity_words(words, 32);
        else fprintf(stderr, "null");
        fputc('}', stderr);
    }
    fprintf(stderr, "]}\n");
    _unlock_file(stderr);
}
#endif
