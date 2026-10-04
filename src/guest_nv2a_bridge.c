#include "guest_nv2a_bridge.h"

#include "boot_window.h"
#include "d3d8_xbox.h"
#include "nv2a_pgraph_d3d11.h"
#include "recomp/recomp_types.h"
#include "xbox_memory_layout.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

#define DAH2_PB_ADDRESS_MASK       0x0FFFFFFCu
#define DAH2_PB_PACKET_MASK        0xE0030003u
#define DAH2_PB_INCREMENTING       0x00000000u
#define DAH2_PB_NON_INCREMENTING   0x40000000u
#define DAH2_PB_RETURN             0x00020000u
#define DAH2_PB_MAX_BYTES          (64u * 1024u * 1024u)
#define DAH2_CONTIG_START          0x80000000u
#define DAH2_CONTIG_END            0x88000000u

typedef struct Dah2GuestGpuBridge {
    SRWLOCK lock;
    int renderer_ready;
    int renderer_failed;
    IDirect3D8 *d3d;
    IDirect3DDevice8 *device;

    uint32_t guest_device;
    uint32_t pb_cpu_start;
    uint32_t pb_cpu_end;
    uint32_t pb_start;
    uint32_t pb_end;
    uint32_t cursor;
    uint32_t return_cursor;
    int return_active;

    uint64_t commits;
    uint64_t presents;
    uint64_t words;
    uint64_t methods;
    uint64_t malformed;
} Dah2GuestGpuBridge;

static Dah2GuestGpuBridge g_bridge = {
    .lock = SRWLOCK_INIT,
};

static uint32_t dah2_pb_address(uint32_t address)
{
    return address & DAH2_PB_ADDRESS_MASK;
}

void dah2_guest_gpu_note_pb_base(uint32_t guest_device, uint32_t base_put)
{
    /* This checkpoint is after initialization has already emitted commands.
     * Keep its diagnostic ABI, but never use this PUT as the allocation base. */
    fprintf(stderr, "[DAH2-GPU] post-init push buffer PUT: dev=0x%08X put=0x%08X\n",
            guest_device, base_put);
}

static int dah2_guest_span_valid(uint32_t address, uint32_t size)
{
    uint32_t last;
    uintptr_t native;
    uintptr_t native_last;

    if (size == 0 || address > UINT32_MAX - (size - 1))
        return 0;

    last = address + size - 1;
    if (xbox_IsXboxAddress(address) && xbox_IsXboxAddress(last))
        return 1;

    /* Contiguous Xbox allocations use a separately backed CPU alias. The
     * matched retail/native traces place the push allocation in this window. */
    if (!(address >= DAH2_CONTIG_START && last < DAH2_CONTIG_END)) {
        return 0;
    }

    native = XBOX_PTR(address);
    native_last = XBOX_PTR(last);
    while (native <= native_last) {
        MEMORY_BASIC_INFORMATION info;
        uintptr_t region_end;

        if (VirtualQuery((const void *)native, &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT ||
            (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
            return 0;

        region_end = (uintptr_t)info.BaseAddress + info.RegionSize;
        if (region_end == 0 || region_end <= native)
            return 0;
        if (region_end > native_last)
            break;
        native = region_end;
    }
    return 1;
}

static int dah2_read_guest_ring(uint32_t guest_device,
                                uint32_t *out_cpu_start,
                                uint32_t *out_cpu_end,
                                uint32_t *out_physical_start,
                                uint32_t *out_physical_end)
{
    uint32_t start_raw;
    uint32_t end_raw;
    uint32_t start;
    uint32_t end;
    uint32_t size;

    {
        static volatile long s_ring_diag_count;
        long _n = InterlockedIncrement(&s_ring_diag_count);
        int _trace = (_n <= 20 || (_n % 1000) == 0);
        if (!dah2_guest_span_valid(guest_device, 0x2Cu)) {
            if (_trace) fprintf(stderr, "[DAH2-RING] dev span invalid dev=0x%08X (#%ld)\n", guest_device, _n);
            return 0;
        }

        /* Retail sub_00254CC0 sets +24/+28 to allocation base/end and +0
         * to PUT. +4 is only a reservation threshold, changed by 00255310.
         * Start at the allocation base so the first commit includes commands
         * already emitted by CreateDevice before its post-init checkpoint. */
        start_raw = MEM32(guest_device + 0x24);
        end_raw = MEM32(guest_device + 0x28);
        if (_trace)
            fprintf(stderr, "[DAH2-RING] dev=0x%08X start_raw=0x%08X end_raw=0x%08X (#%ld)\n",
                    guest_device, start_raw, end_raw, _n);
        if ((start_raw & 3u) != 0 || (end_raw & 3u) != 0) {
            if (_trace) fprintf(stderr, "[DAH2-RING] misaligned (#%ld)\n", _n);
            return 0;
        }

        if (start_raw == 0 || end_raw <= start_raw) {
            if (_trace) fprintf(stderr, "[DAH2-RING] end<=start (#%ld)\n", _n);
            return 0;
        }

        size = end_raw - start_raw;
        start = dah2_pb_address(start_raw);
        if (size > DAH2_PB_MAX_BYTES || start > 0x10000000u - size ||
            !dah2_guest_span_valid(start_raw, size)) {
            if (_trace) fprintf(stderr, "[DAH2-RING] size/span check failed size=0x%08X start=0x%08X (#%ld)\n",
                                 size, start, _n);
            return 0;
        }
        end = start + size;
    }

    *out_cpu_start = start_raw;
    *out_cpu_end = end_raw;
    *out_physical_start = start;
    *out_physical_end = end;
    return 1;
}

static int dah2_guest_gpu_read_physical(uint32_t physical, void *output, uint32_t bytes)
{
    /* This title allocates GPU resources in its separately backed contiguous
     * CPU window. The low virtual window is NOT an alias in this runtime. */
    if (!bytes || physical >= DAH2_CONTIG_END - DAH2_CONTIG_START ||
        bytes > DAH2_CONTIG_END - DAH2_CONTIG_START - physical ||
        !dah2_guest_span_valid(DAH2_CONTIG_START + physical, bytes)) return 0;
    memcpy(output, (const void *)XBOX_PTR(DAH2_CONTIG_START + physical), bytes);
    return 1;
}

static int dah2_guest_gpu_init_locked(void)
{
    D3DPRESENT_PARAMETERS pp;
    IDirect3D8 *d3d;
    IDirect3DDevice8 *device = NULL;
    HWND hwnd;
    HRESULT hr;

    if (g_bridge.renderer_ready)
        return 1;
    if (g_bridge.renderer_failed)
        return 0;

    hwnd = dah2_boot_window_get_hwnd();
    {
        static volatile long s_noninit_count;
        long _n = InterlockedIncrement(&s_noninit_count);
        if ((!hwnd || !IsWindow(hwnd)) && (_n <= 20 || (_n % 1000) == 0))
            fprintf(stderr, "[DAH2-GPU] init skipped: hwnd=%p IsWindow=%d (call #%ld)\n",
                    (void *)hwnd, hwnd ? IsWindow(hwnd) : -1, _n);
    }
    if (!hwnd || !IsWindow(hwnd))
        return 0;

    memset(&pp, 0, sizeof(pp));
    pp.BackBufferWidth = 640;
    pp.BackBufferHeight = 480;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.BackBufferCount = 1;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hwnd;
    pp.Windowed = TRUE;
    pp.EnableAutoDepthStencil = TRUE;

    d3d = xbox_Direct3DCreate8(0);
    if (!d3d) {
        fprintf(stderr, "[DAH2-GPU] Host D3D8 factory creation failed\n");
        g_bridge.renderer_failed = 1;
        return 0;
    }

    hr = d3d->lpVtbl->CreateDevice(d3d, 0, 0, hwnd, 0, &pp, &device);
    if (FAILED(hr) || !device) {
        fprintf(stderr, "[DAH2-GPU] Host D3D8 device creation failed: 0x%08lX\n",
                (unsigned long)hr);
        g_bridge.renderer_failed = 1;
        return 0;
    }

    g_bridge.d3d = d3d;
    g_bridge.device = device;
    pgraph_d3d11_init();
    pgraph_d3d11_set_guest_reader(dah2_guest_gpu_read_physical);
    g_bridge.renderer_ready = 1;
    dah2_boot_window_set_renderer_owned(TRUE);
    fprintf(stderr,
            "[DAH2-GPU] Authentic guest renderer attached to boot HWND %p (640x480)\n",
            (void *)hwnd);
    return 1;
}

static int dah2_pb_cursor_valid(uint32_t cursor, int allow_end)
{
    if ((cursor & 3u) != 0 || cursor < g_bridge.pb_start)
        return 0;
    return allow_end ? cursor <= g_bridge.pb_end : cursor < g_bridge.pb_end;
}

static int dah2_pb_advance(uint32_t *cursor)
{
    if (*cursor > g_bridge.pb_end - 4)
        return 0;
    *cursor += 4;
    return 1;
}

static uint32_t dah2_pb_cpu_address(uint32_t physical)
{
    return g_bridge.pb_cpu_start + (physical - g_bridge.pb_start);
}

static void dah2_guest_gpu_commit_locked(uint32_t guest_device,
                                         uint32_t published_put)
{
    uint32_t cpu_start;
    uint32_t cpu_end;
    uint32_t start;
    uint32_t end;
    uint32_t put;
    uint32_t cursor;
    uint32_t budget;
    uint32_t commit_words = 0;
    uint32_t commit_methods = 0;
    uint32_t commit_malformed = 0;

    if (!dah2_read_guest_ring(guest_device, &cpu_start, &cpu_end, &start, &end))
        return;

    if ((published_put & 3u) != 0)
        return;
    put = dah2_pb_address(published_put);
    if (put < start || put > end)
        return;

    if (g_bridge.guest_device != guest_device ||
        g_bridge.pb_cpu_start != cpu_start || g_bridge.pb_cpu_end != cpu_end ||
        g_bridge.pb_start != start || g_bridge.pb_end != end) {
        g_bridge.guest_device = guest_device;
        g_bridge.pb_cpu_start = cpu_start;
        g_bridge.pb_cpu_end = cpu_end;
        g_bridge.pb_start = start;
        g_bridge.pb_end = end;
        g_bridge.cursor = start;
        g_bridge.return_cursor = 0;
        g_bridge.return_active = 0;
        fprintf(stderr,
                "[DAH2-GPU] Guest push buffer attached: dev=0x%08X cpu=0x%08X-0x%08X physical=0x%08X-0x%08X\n",
                guest_device, cpu_start, cpu_end, start, end);
    }

    if (!dah2_guest_gpu_init_locked())
        return;

    cursor = g_bridge.cursor;
    if (!dah2_pb_cursor_valid(cursor, 1)) {
        commit_malformed++;
        goto parse_complete;
    }
    /* Retail 00255310 emits a jump to roll over; GET must never wrap just
     * because it reaches our allocation bound. Bound all consumed words,
     * including control packets, to prevent a corrupt loop from hanging. */
    budget = (end - start) / 4u + 32u;
    while (cursor != put && budget != 0) {
        uint32_t packet_cursor = cursor;
        uint32_t header;

        budget--;

        if (!dah2_pb_cursor_valid(cursor, 0)) {
            commit_malformed++;
            break;
        }

        header = MEM32(dah2_pb_cpu_address(cursor));
        if (!dah2_pb_advance(&cursor)) {
            commit_malformed++;
            break;
        }
        commit_words++;

        /* NV2A PFIFO old-style jump encodes a 29-bit DMA offset. */
        if ((header & 0xE0000003u) == 0x20000000u) {
            uint32_t target = header & 0x1FFFFFFFu;
            if (!dah2_pb_cursor_valid(target, 0)) {
                cursor = packet_cursor;
                commit_malformed++;
                break;
            }
            cursor = target;
            continue;
        }
        /* New-style jump; the retail rollover writes (base & 0x0FFFFFFF)|1. */
        if ((header & 3u) == 1u) {
            uint32_t target = header & 0xFFFFFFFCu;
            if (!dah2_pb_cursor_valid(target, 0)) {
                cursor = packet_cursor;
                commit_malformed++;
                break;
            }
            cursor = target;
            continue;
        }

        /* The NV2A DMA pusher has one hardware subroutine return slot. */
        if ((header & 3u) == 2u) {
            uint32_t target = header & 0xFFFFFFFCu;
            if (g_bridge.return_active || !dah2_pb_cursor_valid(target, 0)) {
                cursor = packet_cursor;
                commit_malformed++;
                break;
            }
            g_bridge.return_cursor = cursor;
            g_bridge.return_active = 1;
            cursor = target;
            continue;
        }
        if (header == DAH2_PB_RETURN) {
            if (!g_bridge.return_active ||
                !dah2_pb_cursor_valid(g_bridge.return_cursor, 1)) {
                cursor = packet_cursor;
                commit_malformed++;
                break;
            }
            cursor = g_bridge.return_cursor;
            g_bridge.return_cursor = 0;
            g_bridge.return_active = 0;
            continue;
        }

        if ((header & DAH2_PB_PACKET_MASK) == DAH2_PB_INCREMENTING ||
            (header & DAH2_PB_PACKET_MASK) == DAH2_PB_NON_INCREMENTING) {
            uint32_t count = (header >> 18) & 0x7FFu;
            uint32_t method = header & 0x1FFCu;
            uint32_t subchannel = (header >> 13) & 7u;
            int incrementing =
                (header & DAH2_PB_PACKET_MASK) == DAH2_PB_INCREMENTING;
            uint32_t i;

            /* A zero-count header consumes no data, as in the NV2A pusher.
             * Check the complete packet before dispatching any side effects,
             * so a partial publication cannot replay an already-issued prefix. */
            if (count == 0)
                continue;
            if (count > (g_bridge.pb_end - cursor) / 4u || count > budget ||
                (put >= cursor && put < cursor + count * 4u)) {
                cursor = packet_cursor;
                commit_malformed++;
                break;
            }
            budget -= count;

            for (i = 0; i < count; ++i) {
                uint32_t param;

                if (cursor == put || !dah2_pb_cursor_valid(cursor, 0)) {
                    /* A kick should never expose a partial method packet. */
                    cursor = packet_cursor;
                    commit_malformed++;
                    goto parse_complete;
                }
                param = MEM32(dah2_pb_cpu_address(cursor));
                cursor += 4;
                commit_words++;
                pgraph_d3d11_method((int)subchannel,
                                    method + (incrementing ? i * 4u : 0u),
                                    param);
                commit_methods++;
            }
            continue;
        }

        /* Reserved command words stop parsing; skipping one can reinterpret
         * its payload as methods and fabricate GPU work. */
        cursor = packet_cursor;
        commit_malformed++;
        break;
    }

    if (budget == 0 && cursor != put)
        commit_malformed++;

parse_complete:
    g_bridge.cursor = cursor;
    g_bridge.commits++;
    g_bridge.words += commit_words;
    g_bridge.methods += commit_methods;
    g_bridge.malformed += commit_malformed;

    /* The Xbox pusher records completed fence/reference values through a
       small DMA report buffer.  Translation is synchronous here, so every
       successfully consumed kick is already complete when we reach this
       point.  Publish the current reference count or D3D's ring-space wait
       at 0x002552D7 will wait forever for hardware that does not exist. */
    if (commit_malformed == 0 && cursor == put &&
        dah2_guest_span_valid(guest_device + 0x2Cu, 8u)) {
        uint32_t completed_address = MEM32(guest_device + 0x30);
        if (dah2_guest_span_valid(completed_address, 4u))
            MEM32(completed_address) = MEM32(guest_device + 0x2C);
    }

    if (g_bridge.commits <= 8 || (g_bridge.commits % 600u) == 0) {
        fprintf(stderr,
                "[DAH2-GPU] Commit %llu: cursor=0x%08X put=0x%08X words=%u methods=%u malformed=%u\n",
                (unsigned long long)g_bridge.commits, cursor, put,
                commit_words, commit_methods, commit_malformed);
    }
}

void dah2_guest_gpu_commit(uint32_t guest_device, uint32_t published_put)
{
    AcquireSRWLockExclusive(&g_bridge.lock);
    dah2_guest_gpu_commit_locked(guest_device, published_put);
    ReleaseSRWLockExclusive(&g_bridge.lock);
}

static void dah2_frame_cap_30hz(void)
{
    static LARGE_INTEGER s_freq;
    static LARGE_INTEGER s_next;
    LARGE_INTEGER now;

    if (s_freq.QuadPart == 0) {
        QueryPerformanceFrequency(&s_freq);
        QueryPerformanceCounter(&s_next);
        return;
    }
    QueryPerformanceCounter(&now);
    if (now.QuadPart < s_next.QuadPart) {
        LONGLONG wait_ticks = s_next.QuadPart - now.QuadPart;
        DWORD wait_ms = (DWORD)(wait_ticks * 1000 / s_freq.QuadPart);
        if (wait_ms > 0 && wait_ms < 100)
            Sleep(wait_ms);
    }
    QueryPerformanceCounter(&now);
    s_next.QuadPart = now.QuadPart + s_freq.QuadPart / 30;
}

void dah2_guest_gpu_present(uint32_t guest_device)
{
    uint32_t current_put;

    /* TEMP diagnostic: [FPS]/[DAH2-GPU] logging is throttled after frame 8,
     * which could make a real per-frame slowdown look identical to this
     * function simply not being called anymore -- an UNTHROTTLED heartbeat
     * here settles it either way. See "frame presentation stalls" notes in
     * diagnostics/menu_recovery_2026-09-20.md. */
    {
        static volatile long s_heartbeat;
        static LARGE_INTEGER s_hb_freq, s_hb_start;
        LARGE_INTEGER now;
        long n = InterlockedIncrement(&s_heartbeat);
        if (n == 1) { QueryPerformanceFrequency(&s_hb_freq); QueryPerformanceCounter(&s_hb_start); }
        QueryPerformanceCounter(&now);
        double t = (double)(now.QuadPart - s_hb_start.QuadPart) / (double)s_hb_freq.QuadPart;
        fprintf(stderr, "[PRESENT-HEARTBEAT] call #%ld t=%.3fs guest_device=0x%08X\n", n, t, guest_device);
    }

    dah2_frame_cap_30hz();

    AcquireSRWLockExclusive(&g_bridge.lock);

    if (!dah2_guest_span_valid(guest_device, 4u)) {
        static volatile long s_span_invalid_count;
        long _n = InterlockedIncrement(&s_span_invalid_count);
        if (_n <= 20 || (_n % 1000) == 0)
            fprintf(stderr, "[DAH2-GPU] present: guest_device span invalid (call #%ld)\n", _n);
        ReleaseSRWLockExclusive(&g_bridge.lock);
        return;
    }

    current_put = MEM32(guest_device);
    dah2_guest_gpu_commit_locked(guest_device, current_put);
    {
        static volatile long s_after_commit_count;
        long _n = InterlockedIncrement(&s_after_commit_count);
        if (_n <= 20 || (_n % 1000) == 0)
            fprintf(stderr, "[DAH2-GPU] present: after commit, renderer_ready=%d renderer_failed=%d (call #%ld)\n",
                    g_bridge.renderer_ready, g_bridge.renderer_failed, _n);
    }
    if (g_bridge.renderer_ready) {
        PgraphD3D11Stats stats;

        pgraph_d3d11_flush();
        d3d8_PresentFrame();
        g_bridge.presents++;

        if (g_bridge.presents <= 8 || (g_bridge.presents % 300u) == 0) {
            pgraph_d3d11_get_stats(&stats);
            fprintf(stderr,
                    "[DAH2-GPU] Present %llu: translated frames=%u draws=%u verts=%u handled=%u ignored=%u clears=%u\n",
                    (unsigned long long)g_bridge.presents, stats.frames,
                    stats.draw_calls, stats.vertices_submitted,
                    stats.methods_handled, stats.methods_ignored, stats.clears);
        }
    }

    ReleaseSRWLockExclusive(&g_bridge.lock);
}
