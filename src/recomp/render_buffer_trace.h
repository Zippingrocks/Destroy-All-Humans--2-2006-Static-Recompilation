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
    static LONG locks, producers;
    Dah2RenderBufferTrace trace = {0};
    if (!dah2_render_trace_enabled()) return trace;
    trace.ordinal = InterlockedIncrement(producer ? &producers : &locks);
    if (trace.ordinal > (producer ? 12:4)) { trace.ordinal=0; return trace; }
    trace.object=object; trace.stack=g_esp;
    trace.vertex=dah2_render_trace_word(object+0x698);
    trace.index=dah2_render_trace_word(object+0x6A0);
    trace.input=dah2_render_trace_word(g_esp+4);
    trace.count=dah2_render_trace_word(g_esp+8);
    _lock_file(stderr);
    fprintf(stderr,"[VERTEX-PRODUCER] {\"stage\":\"%s.entry\",\"ordinal\":%ld,\"object\":\"%08X\",\"esp\":\"%08X\",\"return\":\"%08X\",",
            producer ? "170C30":"170B80",trace.ordinal,object,g_esp,dah2_render_trace_word(g_esp));
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
#endif
