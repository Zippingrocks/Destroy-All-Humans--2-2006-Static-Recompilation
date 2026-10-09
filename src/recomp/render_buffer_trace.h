#ifndef DAH2_RENDER_BUFFER_TRACE_H
#define DAH2_RENDER_BUFFER_TRACE_H

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

/* Bounded observational hooks for the retail stride-28 vertex producer.
 * All addresses are recorded as guest VAs; no guest memory/register writes. */
typedef struct Dah2RenderBufferTrace {
    uint32_t object, stack, vertex, index, input, count;
    LONG ordinal;
} Dah2RenderBufferTrace;

static int dah2_render_trace_enabled(void) {
    static LONG cached = -1;
    if (cached < 0) {
        char flag[8];
        DWORD length = GetEnvironmentVariableA("DAH2_PARITY_GPU", flag, sizeof(flag));
        InterlockedExchange(&cached, length == 1 && flag[0] == '1');
    }
    return cached != 0;
}

static int dah2_render_trace_read(uint32_t address, uint32_t *value) {
    MEMORY_BASIC_INFORMATION info;
    uintptr_t native = XBOX_PTR(address);
    if (address > 0xFFFFFFFCu ||
        VirtualQuery((const void *)native, &info, sizeof(info)) != sizeof(info) ||
        info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
        native+4 > (uintptr_t)info.BaseAddress+info.RegionSize) return 0;
    memcpy(value, (const void *)native, 4);
    return 1;
}

static uint32_t dah2_render_trace_word(uint32_t address) {
    uint32_t value = 0;
    (void)dah2_render_trace_read(address, &value);
    return value;
}

static void dah2_render_trace_words(uint32_t address, unsigned count) {
    fputc('[', stderr);
    for (unsigned i=0;i<count;i++) {
        uint32_t value;
        if (i) fputc(',', stderr);
        if (dah2_render_trace_read(address+4*i, &value)) fprintf(stderr,"\"%08X\"",value);
        else fputs("null",stderr);
    }
    fputc(']',stderr);
}

static void dah2_render_trace_state(uint32_t object) {
    uint32_t slot = dah2_render_trace_word(object+0x668)&255;
    uint32_t vertex_resource = slot<2 ? dah2_render_trace_word(object+0x688+4*slot) : 0;
    uint32_t index_resource = slot<2 ? dah2_render_trace_word(object+0x690+4*slot) : 0;
    fprintf(stderr,"\"slot\":%u,\"vertex_resource\":\"%08X\",\"vertex_data\":\"%08X\",\"index_resource\":\"%08X\",\"index_data\":\"%08X\",\"vertex_writer\":\"%08X\",\"index_writer\":\"%08X\",\"vertex_count\":%u,\"index_count\":%u",
        slot,vertex_resource,vertex_resource ? dah2_render_trace_word(vertex_resource+4):0,
        index_resource,index_resource ? dah2_render_trace_word(index_resource+4):0,
        dah2_render_trace_word(object+0x698),dah2_render_trace_word(object+0x6A0),
        dah2_render_trace_word(object+0x69C)&65535,dah2_render_trace_word(object+0x6A4)&65535);
}

static Dah2RenderBufferTrace dah2_render_trace_begin(uint32_t object, int producer) {
    static LONG locks, producers, title_producers;
    Dah2RenderBufferTrace trace = {0};
    if (!dah2_render_trace_enabled()) return trace;
    uint32_t return_address = dah2_render_trace_word(g_esp);
    int title_producer = producer &&
        (return_address == 0x001A8290u || return_address == 0x001A8404u);
    trace.ordinal = InterlockedIncrement(title_producer ? &title_producers : producer ? &producers : &locks);
    if (trace.ordinal > (title_producer ? 32 : producer ? 12 : 4)) { trace.ordinal=0; return trace; }
    trace.object=object; trace.stack=g_esp;
    trace.vertex=dah2_render_trace_word(object+0x698);
    trace.index=dah2_render_trace_word(object+0x6A0);
    trace.input=dah2_render_trace_word(g_esp+4);
    trace.count=dah2_render_trace_word(g_esp+8);
    _lock_file(stderr);
    fprintf(stderr,"[VERTEX-PRODUCER] {\"stage\":\"%s.entry\",\"ordinal\":%ld,\"object\":\"%08X\",\"esp\":\"%08X\",\"return\":\"%08X\",\"title_mode\":\"%08X\",\"title_gate\":\"%08X\",\"title_primary\":\"%08X\",\"title_secondary\":\"%08X\",",
            producer ? "170C30":"170B80",trace.ordinal,object,g_esp,return_address,
            dah2_render_trace_word(0x31D9BC),dah2_render_trace_word(0x2EC0B8),
            dah2_render_trace_word(0x31DA8C),dah2_render_trace_word(0x31DA90));
    dah2_render_trace_state(object);
    if (producer) {
        fprintf(stderr,",\"input\":\"%08X\",\"count\":%u,\"input_words\":",trace.input,trace.count);
        dah2_render_trace_words(trace.input,18);
    }
    fputs("}\n",stderr); _unlock_file(stderr);
    return trace;
}

static void dah2_render_trace_end(Dah2RenderBufferTrace trace, int producer) {
    if (!trace.ordinal) return;
    _lock_file(stderr);
    fprintf(stderr,"[VERTEX-PRODUCER] {\"stage\":\"%s.exit\",\"ordinal\":%ld,\"object\":\"%08X\",\"esp\":\"%08X\",",
            producer ? "170C30":"170B80",trace.ordinal,trace.object,g_esp);
    dah2_render_trace_state(trace.object);
    if (producer) {
        fprintf(stderr,",\"written_vertex_va\":\"%08X\",\"written_vertices\":",trace.vertex);
        dah2_render_trace_words(trace.vertex,28);
        fprintf(stderr,",\"written_index_va\":\"%08X\",\"written_indices\":",trace.index);
        dah2_render_trace_words(trace.index,4);
    }
    fputs("}\n",stderr); _unlock_file(stderr);
}

/* Trace the title renderer's bulk vertex-constant records before D3D8 copies
 * them into the push buffer. This is observational and intentionally bounded:
 * title skinning palettes start at c86 and are the only large uploads needed
 * for the parity investigation. */
static void dah2_constant_source_trace(uint32_t record, uint32_t target,
                                       uint32_t source, uint32_t count) {
    static LONG ordinal;
    if (!dah2_render_trace_enabled() || target < 80 || target > 192 || count < 16)
        return;
    LONG current = InterlockedIncrement(&ordinal);
    if (current > 64) return;
    _lock_file(stderr);
    fprintf(stderr,
        "[CONSTANT-SOURCE] {\"ordinal\":%ld,\"record\":\"%08X\","
        "\"target\":%u,\"source\":\"%08X\",\"count\":%u,"
        "\"record_words\":", current, record, target, source, count);
    dah2_render_trace_words(record, 4);
    fputs(",\"source_prefix\":", stderr);
    dah2_render_trace_words(source >= 32 ? source - 32 : source, 8);
    fputs(",\"source_words\":", stderr);
    dah2_render_trace_words(source, count < 32 ? count : 32);
    fputs("}\n", stderr);
    _unlock_file(stderr);
}

static void dah2_matrix_multiply_trace(uint32_t destination, uint32_t left,
                                       uint32_t right) {
    enum { PROBE_CAPACITY = 512, PROBE_WORDS = 52 };
    extern volatile LONG g_dah2_matrix_probe_sequence;
    extern volatile uint32_t g_dah2_matrix_probe_ring[PROBE_CAPACITY][PROBE_WORDS];
    static LONG ordinal;
    if (!dah2_render_trace_enabled()) return;
    LONG sequence = InterlockedIncrement(&g_dah2_matrix_probe_sequence);
    volatile uint32_t *sample = g_dah2_matrix_probe_ring[(sequence - 1) & (PROBE_CAPACITY - 1)];
    sample[0] = (uint32_t)sequence;
    sample[1] = destination; sample[2] = left; sample[3] = right;
    for (unsigned i = 0; i < 16; ++i) {
        sample[4 + i] = dah2_render_trace_word(left + i * 4);
        sample[20 + i] = dah2_render_trace_word(right + i * 4);
        sample[36 + i] = dah2_render_trace_word(destination + i * 4);
    }
    LONG current = InterlockedIncrement(&ordinal);
    if (current > 32) return;
    _lock_file(stderr);
    fprintf(stderr,
        "[MATRIX-MULTIPLY] {\"ordinal\":%ld,\"destination\":\"%08X\","
        "\"left\":\"%08X\",\"right\":\"%08X\",\"left_words\":",
        current, destination, left, right);
    dah2_render_trace_words(left, 16);
    fputs(",\"right_words\":", stderr);
    dah2_render_trace_words(right, 16);
    fputs(",\"destination_before\":", stderr);
    dah2_render_trace_words(destination, 16);
    fputs("}\n", stderr);
    _unlock_file(stderr);
}

static void dah2_skeleton_guard_trace(uint32_t stage, uint32_t owner,
                                      uint32_t parent, uint32_t bone,
                                      uint32_t local, int32_t index) {
    enum { PROBE_CAPACITY = 512, PROBE_WORDS = 55 };
    extern volatile LONG g_dah2_skeleton_probe_sequence;
    extern volatile uint32_t g_dah2_skeleton_probe_ring[PROBE_CAPACITY][PROBE_WORDS];
    static LONG ordinal;
    if (!dah2_render_trace_enabled()) return;
    LONG sequence = InterlockedIncrement(&g_dah2_skeleton_probe_sequence);
    volatile uint32_t *sample = g_dah2_skeleton_probe_ring[(sequence - 1) & (PROBE_CAPACITY - 1)];
    sample[0] = (uint32_t)sequence; sample[1] = stage; sample[2] = owner;
    sample[3] = parent; sample[4] = bone; sample[5] = local; sample[6] = (uint32_t)index;
    for (unsigned i = 0; i < 32; ++i) sample[7 + i] = dah2_render_trace_word(owner + i * 4);
    for (unsigned i = 0; i < 16; ++i) sample[39 + i] = dah2_render_trace_word(local + i * 4);
    LONG current = InterlockedIncrement(&ordinal);
    if (current > 96) return;
    _lock_file(stderr);
    fprintf(stderr,
        "[SKELETON-GUARD] {\"ordinal\":%ld,\"stage\":%u,\"owner\":\"%08X\","
        "\"parent\":\"%08X\",\"bone\":\"%08X\",\"local\":\"%08X\","
        "\"index\":%d,\"owner_words\":",
        current, stage, owner, parent, bone, local, index);
    dah2_render_trace_words(owner, 32);
    fputs(",\"local_words\":", stderr);
    dah2_render_trace_words(local, 16);
    fputs("}\n", stderr);
    _unlock_file(stderr);
}
#endif