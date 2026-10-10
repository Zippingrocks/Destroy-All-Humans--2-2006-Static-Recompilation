#ifndef DAH2_PARITY_CHECKPOINT_H
#define DAH2_PARITY_CHECKPOINT_H

/* Opt-in, bounded evidence at the same retail instruction boundaries used by
 * tools/parity_boot_trace.py. Reads only; guest registers/memory are untouched.
 * Host QPC is acquisition time, not proof of guest timing equivalence. */
#include <windows.h>
#include <stdio.h>
#include "recomp/recomp_types.h"

static int dah2_parity_read(uint32_t address, uint32_t *value)
{
    __try {
        *value = *(volatile uint32_t *)((uintptr_t)g_xbox_mem_offset + address);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void dah2_parity_words_file(FILE *stream, uint32_t address,
                                   unsigned count)
{
    unsigned i;
    fprintf(stream, "[");
    for (i = 0; i < count; ++i) {
        uint32_t value;
        if (i) fprintf(stream, ",");
        if (dah2_parity_read(address + i * 4u, &value))
            fprintf(stream, "\"0x%08x\"", value);
        else fprintf(stream, "null");
    }
    fprintf(stream, "]");
}

static void dah2_parity_words(uint32_t address, unsigned count)
{
    dah2_parity_words_file(stderr, address, count);
}

typedef struct Dah2DsoundLifetimeEvent {
    LONG sequence;
    const char *stage;
    uint32_t address;
    uint32_t object;
    uint32_t owner;
    uint32_t vtable;
    uint32_t refcount;
    DWORD thread;
} Dah2DsoundLifetimeEvent;

#define DAH2_DSOUND_LIFETIME_CAPACITY 256u
static Dah2DsoundLifetimeEvent
    dah2_dsound_lifetime[DAH2_DSOUND_LIFETIME_CAPACITY];
static volatile LONG dah2_dsound_lifetime_sequence;

static int dah2_dsound_trace_enabled(void)
{
    static volatile LONG cached;
    LONG value = InterlockedCompareExchange(&cached, 0, 0);
    char flag[8];
    DWORD length;
    if (value) return value > 0;
    length = GetEnvironmentVariableA("DAH2_DSOUND_TRACE", flag, sizeof(flag));
    value = (length == 1 && flag[0] == '1') ? 1 : -1;
    InterlockedCompareExchange(&cached, value, 0);
    return value > 0;
}

static void dah2_parity_dsound_lifetime(const char *stage, uint32_t address,
                                        uint32_t object, uint32_t owner)
{
    LONG sequence;
    Dah2DsoundLifetimeEvent *event;
    uint32_t vtable = 0, refcount = 0;
    if (!dah2_dsound_trace_enabled()) return;
    if (object) {
        dah2_parity_read(object, &vtable);
        dah2_parity_read(object + 4u, &refcount);
    }
    sequence = InterlockedIncrement(&dah2_dsound_lifetime_sequence);
    event = &dah2_dsound_lifetime[(unsigned)(sequence - 1) &
                                  (DAH2_DSOUND_LIFETIME_CAPACITY - 1u)];
    event->stage = stage;
    event->address = address;
    event->object = object;
    event->owner = owner;
    event->vtable = vtable;
    event->refcount = refcount;
    event->thread = GetCurrentThreadId();
    InterlockedExchange(&event->sequence, sequence);
}

static void dah2_parity_dsound_lifetime_dump(FILE *stream)
{
    LONG newest = InterlockedCompareExchange(&dah2_dsound_lifetime_sequence, 0, 0);
    LONG first = newest > (LONG)DAH2_DSOUND_LIFETIME_CAPACITY
                   ? newest - (LONG)DAH2_DSOUND_LIFETIME_CAPACITY + 1 : 1;
    LONG sequence;
    int emitted = 0;
    fprintf(stream, "[");
    for (sequence = first; sequence <= newest; ++sequence) {
        Dah2DsoundLifetimeEvent *event =
            &dah2_dsound_lifetime[(unsigned)(sequence - 1) &
                                   (DAH2_DSOUND_LIFETIME_CAPACITY - 1u)];
        if (event->sequence != sequence) continue;
        if (emitted++) fprintf(stream, ",");
        fprintf(stream,
                "{\"sequence\":%ld,\"stage\":\"%s\",\"address\":\"0x%08x\","
                "\"thread\":%lu,\"object\":\"0x%08x\",\"owner\":\"0x%08x\","
                "\"vtable\":\"0x%08x\",\"refcount\":%u}",
                sequence, event->stage, event->address,
                (unsigned long)event->thread, event->object, event->owner,
                event->vtable, event->refcount);
    }
    fprintf(stream, "]");
}

/* Temporary, opt-in construction snapshots used to locate the first Bink
 * object divergence. This is read-only and only emits when the existing
 * DAH2_PARITY_TRACE switch is enabled. */
static void dah2_parity_bink_object(const char *stage, uint32_t address,
                                    uint32_t handle)
{
    char flag[8];
    DWORD length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
    if (length != 1 || flag[0] != '1' || !handle) return;
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-BINK] {\"stage\":\"%s\",\"address\":\"0x%08x\",\"handle\":\"0x%08x\",\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\"},\"head\":",
            stage, address, handle, g_eax, g_ecx, g_edx, g_ebx, g_esi, g_edi, g_esp);
    dah2_parity_words(handle, 16);
    fprintf(stderr, ",\"queue\":");
    dah2_parity_words(handle + 0x2B8u, 16);
    fprintf(stderr, ",\"tail\":");
    dah2_parity_words(handle + 0x2F0u, 20);
    fprintf(stderr, "}\n");
    fflush(stderr);
    _unlock_file(stderr);
}

static void dah2_parity_dsound_object(const char *stage, uint32_t address,
                                      uint32_t object, uint32_t target)
{
    static volatile LONG emitted;
    static volatile LONG suspicious_emitted;
    char flag[8];
    LONG ordinal;
    int suspicious;
    DWORD length = GetEnvironmentVariableA("DAH2_DSOUND_TRACE", flag, sizeof(flag));
    if (length != 1 || flag[0] != '1') {
        length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
        if (length != 1 || flag[0] != '1') return;
    }
    ordinal = InterlockedIncrement(&emitted);
    suspicious = !object ||
                 !((object >= 0x00010000u && object < 0x04000000u) ||
                   (object >= 0x80000000u && object < 0x88000000u));
    if (ordinal > 24 && !suspicious) return;
    if (suspicious && InterlockedIncrement(&suspicious_emitted) > 64) return;
    _lock_file(stdout);
    fprintf(stdout, "[PARITY-DSOUND] {\"ordinal\":%ld,\"suspicious\":%s,\"stage\":\"%s\",\"address\":\"0x%08x\",\"thread\":%lu,\"object\":\"0x%08x\",\"target\":\"0x%08x\",\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\"},\"object_head\":",
            ordinal, suspicious ? "true" : "false", stage, address,
            (unsigned long)GetCurrentThreadId(), object, target, g_eax, g_ecx,
            g_edx, g_ebx, g_esi, g_edi, g_esp);
    if (object) dah2_parity_words_file(stdout, object, 32); else fprintf(stdout, "null");
    fprintf(stdout, ",\"stack\":");
    dah2_parity_words_file(stdout, g_esp, 12);
    if (suspicious) {
        fprintf(stdout, ",\"lifetime\":");
        dah2_parity_dsound_lifetime_dump(stdout);
    }
    fprintf(stdout, "}\n");
    fflush(stdout);
    _unlock_file(stdout);
}

static void dah2_parity_bink_audio(const char *stage, uint32_t address)
{
    static volatile LONG emitted;
    char flag[8];
    DWORD length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
    if (length != 1 || flag[0] != '1' || InterlockedIncrement(&emitted) > 96)
        return;
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-BINK-AUDIO] {\"stage\":\"%s\",\"address\":\"0x%08x\",\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\"},\"stack\":",
            stage, address, g_eax, g_ecx, g_edx, g_ebx, g_esi, g_edi, g_esp);
    dah2_parity_words(g_esp, 24);
    fprintf(stderr, "}\n");
    fflush(stderr);
    _unlock_file(stderr);
}

static void dah2_parity_bink_entropy(const char *stage, uint32_t address)
{
    static volatile LONG emitted;
    char flag[8];
    uint32_t state = 0, bits = 0;
    DWORD length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
    if (length != 1 || flag[0] != '1' || InterlockedIncrement(&emitted) > 512)
        return;
    dah2_parity_read(g_esp + 4u, &state);
    dah2_parity_read(g_esp + 8u, &bits);
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-BINK-ENTROPY] {\"stage\":\"%s\",\"address\":\"0x%08x\",\"thread\":%lu,\"state\":\"0x%08x\",\"bits\":\"0x%08x\",\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\"},\"stack\":",
            stage, address, (unsigned long)GetCurrentThreadId(), state, bits, g_eax, g_ecx, g_edx,
            g_ebx, g_esi, g_edi, g_esp);
    dah2_parity_words(g_esp, 12);
    fprintf(stderr, ",\"state_words\":");
    if (state) dah2_parity_words(state, 16); else fprintf(stderr, "null");
    fprintf(stderr, ",\"bit_words\":");
    if (bits) dah2_parity_words(bits, 4); else fprintf(stderr, "null");
    fprintf(stderr, "}\n");
    fflush(stderr);
    _unlock_file(stderr);
}

/* Temporary async-stream snapshots.  This is intentionally taken before
 * sub_00288DE0 adjusts ESP, so the five retail arguments and the caller's
 * return address remain at their ABI-defined offsets. */
static void dah2_parity_bink_stream(const char *stage, uint32_t address)
{
    static volatile LONG emitted;
    char flag[8];
    uint32_t object = 0;
    DWORD length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
    if (length != 1 || flag[0] != '1' || InterlockedIncrement(&emitted) > 192)
        return;
    dah2_parity_read(g_esp + 4u, &object);
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-BINK-STREAM] {\"stage\":\"%s\",\"address\":\"0x%08x\",\"thread\":%lu,\"object\":\"0x%08x\",\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\"},\"stack\":",
            stage, address, (unsigned long)GetCurrentThreadId(), object,
            g_eax, g_ecx, g_edx, g_ebx, g_esi, g_edi, g_esp);
    dah2_parity_words(g_esp, 24);
    fprintf(stderr, ",\"object_words\":");
    if (object) dah2_parity_words(object, 64); else fprintf(stderr, "null");
    fprintf(stderr, "}\n");
    fflush(stderr);
    _unlock_file(stderr);
}

static void dah2_parity_bink_worker(const char *stage, uint32_t address,
                                    uint32_t owner, uint32_t node,
                                    uint32_t target, uint32_t sentinel)
{
    static volatile LONG emitted;
    char flag[8];
    DWORD length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
    if (length != 1 || flag[0] != '1' || InterlockedIncrement(&emitted) > 256)
        return;
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-BINK-WORKER] {\"stage\":\"%s\",\"address\":\"0x%08x\",\"thread\":%lu,\"owner\":\"0x%08x\",\"node\":\"0x%08x\",\"target\":\"0x%08x\",\"sentinel\":\"0x%08x\",\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\"},\"owner_words\":",
            stage, address, (unsigned long)GetCurrentThreadId(), owner, node,
            target, sentinel, g_eax, g_ecx, g_edx, g_ebx, g_esi, g_edi, g_esp);
    if (owner) dah2_parity_words(owner, 16); else fprintf(stderr, "null");
    fprintf(stderr, ",\"node_words\":");
    if (node && node != 0xFFFFFFFFu) dah2_parity_words(node, 8); else fprintf(stderr, "null");
    fprintf(stderr, "}\n");
    fflush(stderr);
    _unlock_file(stderr);
}

static void dah2_parity_object_list(const char *stage, uint32_t address,
                                    uint32_t owner, uint32_t sentinel,
                                    uint32_t node, uint32_t payload)
{
    static volatile LONG emitted;
    char flag[8];
    LONG ordinal;
    uint32_t next = 0;
    int suspicious;
    DWORD length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
    if (length != 1 || flag[0] != '1') return;
    ordinal = InterlockedIncrement(&emitted);
    suspicious = node && node != 0xFFFFFFFFu &&
                 dah2_parity_read(node, &next) && next == 0xFFFFFFFFu;
    if (ordinal > 512 && !suspicious) return;
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-OBJECT-LIST] {\"ordinal\":%ld,\"suspicious\":%s,\"stage\":\"%s\",\"address\":\"0x%08x\",\"thread\":%lu,\"owner\":\"0x%08x\",\"sentinel\":\"0x%08x\",\"node\":\"0x%08x\",\"payload\":\"0x%08x\",\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\"},\"header\":",
            ordinal, suspicious ? "true" : "false", stage, address,
            (unsigned long)GetCurrentThreadId(), owner,
            sentinel, node, payload, g_eax, g_ecx, g_edx, g_ebx, g_esi,
            g_edi, g_esp);
    if (sentinel) dah2_parity_words(sentinel, 8); else fprintf(stderr, "null");
    fprintf(stderr, ",\"node_words\":");
    if (node && node != 0xFFFFFFFFu) dah2_parity_words(node, 8); else fprintf(stderr, "null");
    fprintf(stderr, ",\"payload_words\":");
    if (payload && payload != 0xFFFFFFFFu) dah2_parity_words(payload, 16); else fprintf(stderr, "null");
    fprintf(stderr, "}\n");
    fflush(stderr);
    _unlock_file(stderr);
}

static void dah2_parity_cleanup_node(const char *stage, uint32_t address,
                                     uint32_t owner, uint32_t node,
                                     uint32_t end, uint32_t payload)
{
    static unsigned ordinal;
    uint32_t payload84 = 0;
    int has_payload84 = payload && payload != 0xFFFFFFFFu &&
                        dah2_parity_read(payload + 0x84u, &payload84);
    int suspicious = !node || node == 0xFFFFFFFFu ||
                     (payload && payload < 0x01000000u) ||
                     (has_payload84 && (payload84 & 0xFFFF0000u) == 0xFFFF0000u);
    unsigned current = ++ordinal;
    if (current > 128u && !suspicious) return;

    fprintf(stderr,
            "[PARITY-CLEANUP-LIST] stage=%s address=%08X ordinal=%u suspicious=%d "
            "owner=%08X node=%08X end=%08X payload=%08X payload84=%08X esp=%08X\n",
            stage, address, current, suspicious, owner, node, end, payload,
            has_payload84 ? payload84 : 0u, g_esp);
    fprintf(stderr, "  node=");
    if (node && node != 0xFFFFFFFFu) dah2_parity_words(node, 4); else fprintf(stderr, "null");
    fprintf(stderr, "\n  payload=");
    if (payload && payload != 0xFFFFFFFFu) dah2_parity_words(payload, 40); else fprintf(stderr, "null");
    fprintf(stderr, "\n");
}

static void dah2_parity_checkpoint(const char *name, uint32_t address,
                                   uint32_t frame_pointer, LONG bit)
{
    static volatile LONG enabled = -1;
    static volatile LONG captured;
    uint32_t device = 0, pp = 0;
    LARGE_INTEGER counter, frequency;
    if (enabled < 0) {
        char flag[8];
        DWORD length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
        InterlockedExchange(&enabled, length == 1 && flag[0] == '1');
    }
    if (!enabled || (InterlockedOr(&captured, bit) & bit)) return;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    dah2_parity_read(0x25E5A8u, &device);
    dah2_parity_read(g_esp + 0x14u, &pp);
    _lock_file(stderr);
    fprintf(stderr, "[PARITY] {\"schema\":\"dah2-native-checkpoint-v1\",\"name\":\"%s\",\"address\":\"0x%08x\",\"host_qpc\":%lld,\"host_qpc_frequency\":%lld,\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esp\":\"0x%08x\",\"ebp\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\"},\"stack\":",
            name, address, counter.QuadPart, frequency.QuadPart,
            g_eax, g_ecx, g_edx, g_ebx, g_esp, frame_pointer, g_esi, g_edi);
    dah2_parity_words(g_esp, 32);
    fprintf(stderr, ",\"input_globals\":{");
    fprintf(stderr, "\"0x002c8ba4\":"); dah2_parity_words(0x2C8BA4u, 16);
    fprintf(stderr, ",\"0x002ca6a0\":"); dah2_parity_words(0x2CA6A0u, 16);
    fprintf(stderr, "}");
    fprintf(stderr, ",\"device\":\"0x%08x\",\"device_head\":", device);
    if (device) dah2_parity_words(device, 64); else fprintf(stderr, "null");
    if (device && address != 0x24DCB0u && address != 0xFAF3Bu) {
        uint32_t base = 0, end = 0;
        dah2_parity_read(device + 0x24u, &base);
        dah2_parity_read(device + 0x28u, &end);
        if (base && end > base) {
            unsigned bytes = end - base < 4096u ? end - base : 4096u;
            fprintf(stderr, ",\"push_buffer_prefix\":");
            dah2_parity_words(base, bytes / 4u);
        }
    }
    if (address == 0x24DCB0u) {
        fprintf(stderr, ",\"presentation_parameters_address\":\"0x%08x\",\"presentation_parameters\":", pp);
        if (pp) dah2_parity_words(pp, 17); else fprintf(stderr, "null");
    }
    if (address == 0x1A8518u) {
        fprintf(stderr, ",\"bink_handle\":\"0x%08x\",\"bink_header\":", g_eax);
        if (g_eax) dah2_parity_words(g_eax, 0x3A0u / 4u); else fprintf(stderr, "null");
    }
    fprintf(stderr, "}\n");
    fflush(stderr);
    _unlock_file(stderr);
}
#endif
