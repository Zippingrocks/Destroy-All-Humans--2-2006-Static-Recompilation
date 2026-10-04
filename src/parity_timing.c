#include "parity_timing.h"
#include "recomp/recomp_types.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static INIT_ONCE timing_once = INIT_ONCE_STATIC_INIT;
static SRWLOCK timing_lock = SRWLOCK_INIT;
static int timing_enabled;
static unsigned timing_limit = 32;
static unsigned timing_ordinal;

static BOOL CALLBACK timing_initialize(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    char flag[24];
    DWORD length;
    (void)once; (void)parameter; (void)context;
    length = GetEnvironmentVariableA("DAH2_PARITY_TRACE", flag, sizeof(flag));
    timing_enabled = length == 1 && flag[0] == '1';
    length = GetEnvironmentVariableA("DAH2_PARITY_EVENTS", flag, sizeof(flag));
    if (length && length < sizeof(flag)) {
        char *end = NULL;
        unsigned long limit = strtoul(flag, &end, 10);
        if (end && !*end && limit >= 1 && limit <= 4096) timing_limit = (unsigned)limit;
    }
    return TRUE;
}

static int timing_read(uint32_t address, uint32_t *value, unsigned bytes)
{
    if (address > UINT32_MAX - bytes + 1u) return 0;
    __try {
        if (bytes == 1) *value = *(volatile uint8_t *)((uintptr_t)g_xbox_mem_offset + address);
        else *value = *(volatile uint32_t *)((uintptr_t)g_xbox_mem_offset + address);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static uint32_t timing_pointer(uint32_t address)
{
    uint32_t value = 0;
    timing_read(address, &value, 4);
    return value;
}

static void timing_field(const char *name, uint32_t pointer, uint32_t offset, unsigned bytes)
{
    uint32_t value;
    fprintf(stderr, ",\"%s\":", name);
    if (pointer && offset <= UINT32_MAX - pointer && timing_read(pointer + offset, &value, bytes))
        fprintf(stderr, "\"0x%08x\"", value);
    else fprintf(stderr, "null");
}

void dah2_parity_timing(const char *kind, uint32_t address, uint32_t frame_pointer)
{
    uint32_t clock, simulation, configuration, device;
    LARGE_INTEGER counter, frequency;
    InitOnceExecuteOnce(&timing_once, timing_initialize, NULL, NULL);
    if (!timing_enabled) return;
    AcquireSRWLockExclusive(&timing_lock);
    if (timing_ordinal >= timing_limit) { ReleaseSRWLockExclusive(&timing_lock); return; }
    ++timing_ordinal;
    QueryPerformanceCounter(&counter); QueryPerformanceFrequency(&frequency);
    clock = timing_pointer(0x2C9C88u); simulation = timing_pointer(0x30FDE4u);
    configuration = timing_pointer(0x2CA6A0u); device = timing_pointer(0x25E5A8u);
    _lock_file(stderr);
    fprintf(stderr, "[PARITY-TIME] {\"schema\":\"dah2-timing-event-v1\",\"source\":\"native\",\"ordinal\":%u,\"kind\":\"%s\",\"address\":\"0x%08x\",\"host_timestamp\":{\"qpc\":%lld,\"frequency\":%lld},\"registers\":{\"eax\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"ebx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"esp\":\"0x%08x\",\"ebp\":\"0x%08x\"},\"state\":{",
            timing_ordinal, kind, address, counter.QuadPart, frequency.QuadPart,
            g_eax, g_ecx, g_edx, g_ebx, g_esi, g_edi, g_esp, frame_pointer);
    fprintf(stderr, "\"clock\":{\"pointer\":\"0x%08x\"", clock);
    timing_field("current_ms", clock, 0x24, 4); timing_field("delta_ms", clock, 0x28, 4);
    timing_field("sample_count", clock, 0x2C, 4);
    fprintf(stderr, "},\"simulation\":{\"pointer\":\"0x%08x\"", simulation);
    timing_field("rate_bits", simulation, 4, 4); timing_field("delta_bits", simulation, 0x10, 4);
    timing_field("clamp_byte", simulation, 0x303D, 1);
    fprintf(stderr, "},\"configuration\":{\"pointer\":\"0x%08x\"", configuration);
    timing_field("mode60", configuration, 0x238, 4); timing_field("multiplier", configuration, 0x27C, 4);
    fprintf(stderr, "},\"device\":{\"pointer\":\"0x%08x\"", device);
    timing_field("put", device, 0, 4); timing_field("ring_base", device, 0x24, 4);
    timing_field("ring_end", device, 0x28, 4); timing_field("swap_count", device, 0x2478, 4);
    fprintf(stderr, "}}}\n"); fflush(stderr); _unlock_file(stderr);
    ReleaseSRWLockExclusive(&timing_lock);
}
