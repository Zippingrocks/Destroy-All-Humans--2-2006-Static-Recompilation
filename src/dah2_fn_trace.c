#include "dah2_fn_trace.h"
#include <windows.h>
volatile uint32_t g_fnt_on;
volatile uint32_t g_fnt_stamp;
volatile uint32_t g_fnt_seq;
uint32_t g_fnt_first[DAH2_FNT_SPACE];
uint32_t g_fnt_order[DAH2_FNT_SPACE];
uint32_t g_fnt_count[DAH2_FNT_SPACE];
uint32_t g_fnt_nat[65536][8];
volatile uint32_t g_fnt_nat_idx;
volatile uint32_t g_fnt_vm_on, g_fnt_vm_idx;
uint32_t g_fnt_vm[65536][2];
volatile uint32_t g_fnt_vm_pre_idx;
uint32_t g_fnt_vm_pre[256][2];
uint32_t g_fnt_vm_pre_snap[256][2];
volatile uint32_t g_fnt_flog_idx;
uint32_t g_fnt_flog[16384];
volatile uint32_t g_fnt_wlo = 1, g_fnt_whi = 0, g_fnt_wlog_idx;
uint32_t g_fnt_wlog[1048576];
volatile uint32_t g_fnt_wvm_idx;
uint32_t g_fnt_wvm[262144][3];
uint32_t g_fnt_vm_ext[65536][4];
#include <stddef.h>
extern ptrdiff_t g_xbox_mem_offset;
uint32_t g_fnt_vm_ext_read(uint32_t va) { return *(volatile uint32_t *)((uintptr_t)va + g_xbox_mem_offset); }
uint32_t g_fnt_natres[65536][4];
uint32_t g_fnt_natargs[65536][8];
uint32_t g_fnt_probe[8192][5];
volatile uint32_t g_fnt_probe_idx;
volatile uint32_t g_fnt_probe_boot = 0, g_fnt_probe_lo = 0, g_fnt_probe_hi = 0xFFFFFFFFu;

/* Address-range watch: log every alloc/free hook call whose pointer lies in [g_fnt_watch_lo, g_fnt_watch_hi). */
volatile uint32_t g_fnt_watch_lo, g_fnt_watch_hi, g_fnt_watch_n;
uint32_t g_fnt_watch_log[256][6];
static void w_log(uint32_t kind, uint32_t ptr, uint32_t size, uint32_t ra)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t i;
    if (!(ptr >= g_fnt_watch_lo && ptr < g_fnt_watch_hi) || g_fnt_watch_n >= 256u) return;
    i = g_fnt_watch_n++; g_fnt_watch_log[i][0] = kind; g_fnt_watch_log[i][1] = ptr; g_fnt_watch_log[i][2] = size; g_fnt_watch_log[i][3] = ra; g_fnt_watch_log[i][4] = g_fnt_nat_idx; g_fnt_watch_log[i][5] = GetCurrentThreadId();
}
/* ---- Guest heap shadow checker (trace build only) ----------------------------------------------
 * Tracks every block handed out by the guest pool allocator (vtable alloc 0x13F390 / free 0x13FFC0)
 * in a per-4-byte owner map, and records an event when a new block overlaps a live one, or when a
 * free names no live block. Read g_fnt_heap_ov[] / g_fnt_heap_ov_n from outside (tools/dump_heap_check.py). */
#define DAH2_H_LO 0x80000000u
#define DAH2_H_HI 0x90000000u
#define DAH2_HREC_N (1u << 22)
typedef struct { uint32_t start, size, ra, tid; } dah2_hrec_t;
typedef struct { uint32_t kind, new_start, new_size, new_ra, new_tid, old_seq, old_start, old_size, old_ra, old_tid, nat_idx, seq; } dah2_hov_t;
dah2_hov_t g_fnt_heap_ov[64];
volatile uint32_t g_fnt_heap_ov_n, g_fnt_heap_allocs, g_fnt_heap_frees, g_fnt_heap_threads;
static uint32_t *g_howner; static dah2_hrec_t *g_hrec; static uint32_t g_hseq; static SRWLOCK g_hlock = SRWLOCK_INIT;
static uint32_t g_hfirst_tid;
static uint32_t h_rd32(uint32_t va) { return *(volatile uint32_t *)((uintptr_t)va + g_xbox_mem_offset); }
static int h_init(void)
{
    if (g_howner) return 1;
    g_howner = (uint32_t *)VirtualAlloc(NULL, (size_t)((DAH2_H_HI - DAH2_H_LO) / 4) * 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    g_hrec = (dah2_hrec_t *)VirtualAlloc(NULL, (size_t)DAH2_HREC_N * sizeof(dah2_hrec_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    return g_howner && g_hrec;
}
static void h_event(uint32_t kind, uint32_t ns, uint32_t nsz, uint32_t nra, uint32_t ntid, uint32_t oseq)
{
    uint32_t i = g_fnt_heap_ov_n; dah2_hov_t *e; dah2_hrec_t *o;
    static uint32_t nfree_events;
    if (kind != 1u && nfree_events++ >= 8u) return;
    if (i >= 64u) return;
    e = &g_fnt_heap_ov[i]; e->kind = kind; e->new_start = ns; e->new_size = nsz; e->new_ra = nra; e->new_tid = ntid; e->old_seq = oseq; e->seq = g_hseq;
    o = oseq ? &g_hrec[oseq & (DAH2_HREC_N - 1u)] : NULL;
    if (o) { e->old_start = o->start; e->old_size = o->size; e->old_ra = o->ra; e->old_tid = o->tid; }
    { extern volatile uint32_t g_fnt_nat_idx; e->nat_idx = g_fnt_nat_idx; }
    g_fnt_heap_ov_n = i + 1u;
}
static uint32_t h_block_of(uint32_t p)
{
    int n = 0;
    while (h_rd32(p - 4u) == 0xFFFFFFFFu && n++ < 64) p -= 4u;
    return p - 0xCu;
}
uint32_t g_fnt_alloc_null_log[16][2];
volatile uint32_t g_fnt_alloc_null, g_fnt_big_allocs, g_fnt_big_frees;
uint32_t g_fnt_bigalloc[48][12];
volatile uint32_t g_fnt_bigalloc_n;
void dah2_heap_alloc(uint32_t ptr, uint32_t size, uint32_t align, uint32_t ra)
{
    uint32_t blk, total, g, g1, tid = GetCurrentThreadId(), seq; (void)size; (void)align;
    w_log(1, ptr, size, ra);
    if (!ptr && g_fnt_on) { if (g_fnt_alloc_null < 16u) { g_fnt_alloc_null_log[g_fnt_alloc_null][0] = size; g_fnt_alloc_null_log[g_fnt_alloc_null][1] = ra; } g_fnt_alloc_null++; }
    if (!ptr || ptr < DAH2_H_LO + 0x20u || ptr >= DAH2_H_HI) return;
    if (!h_init()) return;
    { static int armed; extern volatile uint32_t g_fnt_vm_on;
      if (g_fnt_vm_on && !armed) {   /* start fresh at the anchor native: earlier blocks may have been dropped by pool resets */
          AcquireSRWLockExclusive(&g_hlock);
          if (!armed) { g_howner = (uint32_t *)VirtualAlloc(NULL, (size_t)((DAH2_H_HI - DAH2_H_LO) / 4) * 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); g_fnt_heap_ov_n = 0; armed = 1; }
          ReleaseSRWLockExclusive(&g_hlock);
      }
      if (!armed) return; }
    blk = h_block_of(ptr); total = (h_rd32(blk + 4u) & ~1u) + 0xCu;
    if (blk < DAH2_H_LO || total > 0x10000000u || blk + total > DAH2_H_HI) return;
    if (total >= 150000u) g_fnt_big_allocs++;
    if (total >= 150000u && g_fnt_bigalloc_n < 48u) {   /* who makes the very large blocks: the code-address words on the guest stack above the allocator */
        extern __declspec(thread) uint32_t g_esp; uint32_t *e = g_fnt_bigalloc[g_fnt_bigalloc_n], k, w = 0, sp = g_esp;
        e[0] = total; e[1] = ptr;
        for (k = 0; k < 160u && w < 10u; ++k) { uint32_t v = h_rd32(sp + 4u * k); if (v >= 0x11000u && v < 0x226000u) e[2 + w++] = v; }
        g_fnt_bigalloc_n++;
    }
    AcquireSRWLockExclusive(&g_hlock);
    if (!g_hfirst_tid) g_hfirst_tid = tid; else if (tid != g_hfirst_tid) g_fnt_heap_threads |= 1u;
    seq = ++g_hseq; ++g_fnt_heap_allocs;
    g_hrec[seq & (DAH2_HREC_N - 1u)] = (dah2_hrec_t){ blk, total, ra, tid };
    g = (blk - DAH2_H_LO) >> 2; g1 = (blk + total - DAH2_H_LO + 3u) >> 2;
    { int reported = 0; for (; g < g1; ++g) { if (g_howner[g] && !reported) { h_event(1, blk, total, ra, tid, g_howner[g]); reported = 1; } g_howner[g] = seq; } }
    ReleaseSRWLockExclusive(&g_hlock);
}
void dah2_heap_free(uint32_t ptr, uint32_t ra)
{
    uint32_t blk, g, g1, seq; dah2_hrec_t *r;
    w_log(2, ptr, 0, ra);
    if (!ptr || ptr < DAH2_H_LO + 0x20u || ptr >= DAH2_H_HI) return;
    if (!h_init()) return;
    { extern volatile uint32_t g_fnt_vm_on; if (!g_fnt_vm_on) return; }
    blk = h_block_of(ptr);
    AcquireSRWLockExclusive(&g_hlock);
    ++g_fnt_heap_frees;
    g = (blk - DAH2_H_LO) >> 2; seq = g_howner[g];
    if (!seq) { h_event(2, blk, 0, ra, GetCurrentThreadId(), 0); ReleaseSRWLockExclusive(&g_hlock); return; }
    r = &g_hrec[seq & (DAH2_HREC_N - 1u)];
    if (r->start != blk) { h_event(3, blk, 0, ra, GetCurrentThreadId(), seq); ReleaseSRWLockExclusive(&g_hlock); return; }
    if (r->size >= 150000u) g_fnt_big_frees++;
    for (g1 = (blk + r->size - DAH2_H_LO + 3u) >> 2; g < g1; ++g) if (g_howner[g] == seq) g_howner[g] = 0;
    ReleaseSRWLockExclusive(&g_hlock);
}

/* ---- Same shadow check for the small-block pool (alloc 0x1A7680 / free 0x1A76E0), tracked by requested size ---- */
static uint32_t *g_sowner; static dah2_hrec_t *g_srec; static uint32_t g_sseq; static SRWLOCK g_slock = SRWLOCK_INIT;
dah2_hov_t g_fnt_sheap_ov[64];
volatile uint32_t g_fnt_sheap_ov_n, g_fnt_sheap_allocs, g_fnt_sheap_frees;
static void s_event(uint32_t kind, uint32_t ns, uint32_t nsz, uint32_t nra, uint32_t oseq)
{
    uint32_t i = g_fnt_sheap_ov_n; dah2_hov_t *e; dah2_hrec_t *o; static uint32_t nfree_events;
    if (kind != 1u && nfree_events++ >= 8u) return;
    if (i >= 64u) return;
    e = &g_fnt_sheap_ov[i]; e->kind = kind; e->new_start = ns; e->new_size = nsz; e->new_ra = nra; e->new_tid = GetCurrentThreadId(); e->old_seq = oseq; e->seq = g_sseq;
    o = oseq ? &g_srec[oseq & (DAH2_HREC_N - 1u)] : NULL;
    if (o) { e->old_start = o->start; e->old_size = o->size; e->old_ra = o->ra; e->old_tid = o->tid; }
    { extern volatile uint32_t g_fnt_nat_idx; e->nat_idx = g_fnt_nat_idx; }
    g_fnt_sheap_ov_n = i + 1u;
}
void dah2_sheap_alloc(uint32_t ptr, uint32_t size, uint32_t ra)
{
    uint32_t g, g1, seq; static int armed; extern volatile uint32_t g_fnt_vm_on;
    w_log(3, ptr, size, ra);
    { extern void dah2_hw_start(void); dah2_hw_start(); }
    if (!ptr || ptr < DAH2_H_LO || ptr >= DAH2_H_HI || !size || size > 0x100000u) return;
    if (!g_fnt_vm_on) return;
    AcquireSRWLockExclusive(&g_slock);
    if (!armed) {
        g_sowner = (uint32_t *)VirtualAlloc(NULL, (size_t)((DAH2_H_HI - DAH2_H_LO) / 4) * 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        g_srec = (dah2_hrec_t *)VirtualAlloc(NULL, (size_t)DAH2_HREC_N * sizeof(dah2_hrec_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        armed = 1;
    }
    if (!g_sowner || !g_srec) { ReleaseSRWLockExclusive(&g_slock); return; }
    seq = ++g_sseq; ++g_fnt_sheap_allocs;
    g_srec[seq & (DAH2_HREC_N - 1u)] = (dah2_hrec_t){ ptr, size, ra, GetCurrentThreadId() };
    g = (ptr - DAH2_H_LO) >> 2; g1 = (ptr + size - DAH2_H_LO + 3u) >> 2;
    { int reported = 0; for (; g < g1; ++g) { if (g_sowner[g] && !reported) { s_event(1, ptr, size, ra, g_sowner[g]); reported = 1; } g_sowner[g] = seq; } }
    ReleaseSRWLockExclusive(&g_slock);
}
void dah2_sheap_free(uint32_t ptr, uint32_t ra)
{
    uint32_t g, g1, seq; dah2_hrec_t *r; extern volatile uint32_t g_fnt_vm_on;
    w_log(4, ptr, 0, ra);
    if (!ptr || ptr < DAH2_H_LO || ptr >= DAH2_H_HI || !g_fnt_vm_on || !g_sowner) return;
    AcquireSRWLockExclusive(&g_slock);
    ++g_fnt_sheap_frees;
    g = (ptr - DAH2_H_LO) >> 2; seq = g_sowner[g];
    if (!seq) { s_event(2, ptr, 0, ra, 0); ReleaseSRWLockExclusive(&g_slock); return; }
    r = &g_srec[seq & (DAH2_HREC_N - 1u)];
    if (r->start != ptr) { s_event(3, ptr, 0, ra, seq); ReleaseSRWLockExclusive(&g_slock); return; }
    for (g1 = (ptr + r->size - DAH2_H_LO + 3u) >> 2; g < g1; ++g) if (g_sowner[g] == seq) g_sowner[g] = 0;
    ReleaseSRWLockExclusive(&g_slock);
}

/* ---- Hardware write watchpoint on a guest address (trace build only) ----------------------------
 * Set g_fnt_hw_addr (guest VA, 4-byte aligned) from outside (tools/write_global32.py). A helper thread arms
 * DR0/DR7 on the present thread; the vectored handler logs each hit (host RIP + host backtrace + native idx). */
volatile uint32_t g_fnt_hw_addr, g_fnt_hw_n, g_fnt_hw_min, g_fnt_hw_len = 4, g_fnt_hw_gate, g_fnt_hw_auto;
uint64_t g_fnt_hw_log[64][20];
extern __declspec(thread) uint32_t g_ecx, g_esp;
static volatile LONG g_hw_started;
static LONG CALLBACK hw_veh(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP && (ep->ContextRecord->Dr6 & 0xFull)) {
        extern volatile uint32_t g_fnt_nat_idx; uint32_t i = g_fnt_hw_n; void *bt[16]; USHORT n, k;
        if (i < 64u && g_fnt_hw_gate && (g_fnt_hw_min == 0u || (g_fnt_hw_len == 2u ? (uint32_t)*(volatile uint16_t *)((uintptr_t)g_fnt_hw_addr + g_xbox_mem_offset) : *(volatile uint32_t *)((uintptr_t)g_fnt_hw_addr + g_xbox_mem_offset)) >= g_fnt_hw_min)) {
            n = RtlCaptureStackBackTrace(0, 16, bt, NULL);
            g_fnt_hw_log[i][0] = ep->ContextRecord->Rip; g_fnt_hw_log[i][1] = g_fnt_nat_idx; g_fnt_hw_log[i][2] = GetCurrentThreadId();
            for (k = 0; k < 14u; ++k) g_fnt_hw_log[i][3 + k] = k < n ? (uint64_t)(uintptr_t)bt[k] : 0;
            g_fnt_hw_log[i][17] = g_esp; g_fnt_hw_log[i][18] = g_ecx;
            g_fnt_hw_log[i][19] = g_fnt_hw_len == 2u ? *(volatile uint16_t *)((uintptr_t)g_fnt_hw_addr + g_xbox_mem_offset) : *(volatile uint32_t *)((uintptr_t)g_fnt_hw_addr + g_xbox_mem_offset);
            g_fnt_hw_n = i + 1u;
        }
        ep->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#include <tlhelp32.h>
static DWORD WINAPI hw_thread(LPVOID unused)
{
    uint32_t armed = 0; (void)unused;
    for (;;) {
        Sleep(1);
        if (g_fnt_hw_addr && g_fnt_hw_addr != armed) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); THREADENTRY32 te; DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
            te.dwSize = sizeof te;
            if (snap != INVALID_HANDLE_VALUE) {
                if (Thread32First(snap, &te)) do {
                    if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
                    { HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                      if (th) {
                        CONTEXT c; memset(&c, 0, sizeof c); c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        SuspendThread(th);
                        if (GetThreadContext(th, &c)) {
                            c.Dr0 = (DWORD64)((uintptr_t)g_fnt_hw_addr + g_xbox_mem_offset);
                            c.Dr7 = 1ull | (1ull << 16) | ((g_fnt_hw_len == 2u ? 1ull : 3ull) << 18);   /* L0, write, 2 or 4 bytes */
                            c.Dr6 = 0;
                            SetThreadContext(th, &c);
                        }
                        ResumeThread(th); CloseHandle(th);
                      } }
                } while (Thread32Next(snap, &te));
                CloseHandle(snap); armed = g_fnt_hw_addr;
            }
        }
    }
    return 0;
}
void dah2_hw_start(void)
{
    if (InterlockedCompareExchange(&g_hw_started, 1, 0) == 0) { AddVectoredExceptionHandler(1, hw_veh); CreateThread(NULL, 0, hw_thread, NULL, 0, NULL); }
}

/* ---- scene-node children validator (probe helper) -------------------------------------------
 * Nodes keep their children as {array ptr [self+0xBC], count [self+0xC0]}; every child must start with a vtable pointer in
 * the image (.rdata). Called from the 0x1831B0 / 0x183210 entry probes; logs the first invalid children. */
uint32_t g_fnt_chk[32][8];
uint32_t g_fnt_chk2[16][24];
volatile uint32_t g_fnt_chk2_last;
volatile uint32_t g_fnt_chk_n, g_fnt_chk_calls;
uint32_t dah2_chk_children(uint32_t self)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t arr, cnt, i, bad = 0;
    ++g_fnt_chk_calls;
    if (self < 0x10000u || self >= 0x90000000u) return 0xFFFFFFFFu;
    arr = h_rd32(self + 0xBCu); cnt = h_rd32(self + 0xC0u);
    { static uint32_t ring_i; uint32_t q = (ring_i++) & 15u, m = 0, j; g_fnt_chk2[q][0] = self; g_fnt_chk2[q][1] = h_rd32(self); g_fnt_chk2[q][2] = arr; g_fnt_chk2[q][3] = cnt; g_fnt_chk2[q][4] = g_fnt_nat_idx;
      for (j = 0; j < 6u && j < cnt && arr >= 0x10000u && arr < 0x90000000u; ++j) { uint32_t p = h_rd32(arr + 4u * j), vt = (p >= 0x10000u && p < 0x90000000u) ? h_rd32(p) : 0, f0 = (vt >= 0x10000u && vt < 0x90000000u) ? h_rd32(vt) : 0; g_fnt_chk2[q][5 + 3 * j] = p; g_fnt_chk2[q][6 + 3 * j] = vt; g_fnt_chk2[q][7 + 3 * j] = f0; m++; }
      g_fnt_chk2_last = q; }
    if (cnt == 0 || cnt > 0x10000u || arr < 0x10000u || arr >= 0x90000000u) { return cnt > 0x10000u ? 0xFFFFFFF0u : 0u; }
    for (i = 0; i < cnt; ++i) {
        uint32_t p = h_rd32(arr + 4u * i), vt = 0;
        if (!p) continue;
        if (p >= 0x10000u && p < 0x90000000u) vt = h_rd32(p);
        { uint32_t f0 = (vt >= 0x10000u && vt < 0x90000000u) ? h_rd32(vt) : 0; if (f0 >= 0x21A000u && f0 < 0x226000u) vt = 0xE0000000u | f0; }
        if (vt < 0x2A0000u || vt >= 0x330000u) {
            ++bad;
            if (g_fnt_chk_n < 32u) {
                uint32_t k = g_fnt_chk_n++; g_fnt_chk[k][0] = self; g_fnt_chk[k][1] = i; g_fnt_chk[k][2] = p; g_fnt_chk[k][3] = vt; g_fnt_chk[k][4] = cnt; g_fnt_chk[k][5] = arr; g_fnt_chk[k][6] = g_fnt_nat_idx;
                g_fnt_chk[k][7] = h_rd32(self);
            }
        }
    }
    return bad;
}

/* ---- bad indirect-call target log (called from RECOMP_ICALL* in trace builds) ---------------- */
uint32_t g_fnt_ib[32][14];
volatile uint32_t g_fnt_ib_n;
void dah2_icall_bad(uint32_t va, uint32_t ecx, uint32_t edx, uint32_t eax, uint32_t esp, uint32_t line, const char *file)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t i; const char *b = file, *q; size_t n;
    if (!g_fnt_on || !g_fnt_vm_on || g_fnt_ib_n >= 32u) return;
    for (i = 0; i < g_fnt_ib_n; ++i) if (g_fnt_ib[i][0] == va && g_fnt_ib[i][5] == line) return;   /* dedupe by (target, line) */
    i = g_fnt_ib_n++; g_fnt_ib[i][0] = va; g_fnt_ib[i][1] = ecx; g_fnt_ib[i][2] = edx; g_fnt_ib[i][3] = eax; g_fnt_ib[i][4] = esp; g_fnt_ib[i][5] = line; g_fnt_ib[i][6] = g_fnt_nat_idx;
    for (q = file; *q; ++q) if (*q == '\\' || *q == '/') b = q + 1;
    n = strlen(b) + 1; if (n > 28) n = 28;
    memset(&g_fnt_ib[i][7], 0, 28); memcpy(&g_fnt_ib[i][7], b, n);
}

/* ---- 0x1D0260 (depth sort) input logger: ecx=this, arg0 = key/ptr array, arg1 = box ptr, arg2 = count --------- */
uint32_t g_fnt_sort[512][40];
volatile uint32_t g_fnt_sort_n;
uint32_t dah2_log_sort(uint32_t self, uint32_t arr, uint32_t box, uint32_t cnt, uint32_t ra)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t q = (g_fnt_sort_n++) & 511u, j;
    g_fnt_sort[q][0] = self; g_fnt_sort[q][1] = arr; g_fnt_sort[q][2] = box; g_fnt_sort[q][3] = cnt; g_fnt_sort[q][4] = ra; g_fnt_sort[q][5] = g_fnt_nat_idx;
    for (j = 0; j < 8; ++j) g_fnt_sort[q][8 + j] = (box >= 0x10000u && box < 0x90000000u) ? h_rd32(box + 4u * j) : 0xDEADu;
    g_fnt_sort[q][16] = (arr >= 0x10000u && arr < 0x90000000u && h_rd32(arr) >= 0x10000u && h_rd32(arr) < 0x90000000u) ? h_rd32(h_rd32(arr)) : 0xDEADu;
    g_fnt_sort[q][17] = (arr >= 0x10000u && arr < 0x90000000u) ? h_rd32(arr) : 0xDEADu;
    { extern uint32_t dah2_sap(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t); dah2_sap(0x1D0260u, self, h_rd32(h_rd32(arr)), box, ra); }
    g_fnt_sort[q][18] = (self >= 0x10000u && self < 0x90000000u) ? h_rd32(self + 0x44u) : 0xDEADu;
    if (self >= 0x10000u && self < 0x90000000u) {
        uint32_t l0 = h_rd32(self + 0x4Cu), l1 = h_rd32(self + 0x58u), l2 = h_rd32(self + 0x64u), rc = h_rd32(self + 0x40u), id = g_fnt_sort[q][16];
        for (j = 0; j < 4; ++j) { g_fnt_sort[q][19 + j] = l2 ? h_rd32(l2 + 4u * j) : 0u; g_fnt_sort[q][23 + j] = l0 ? h_rd32(l0 + 4u * j) : 0u; g_fnt_sort[q][27 + j] = l1 ? h_rd32(l1 + 4u * j) : 0u; }
        if (rc && id < 0x400u) for (j = 0; j < 4; ++j) g_fnt_sort[q][31 + j] = h_rd32(rc + 16u * id + 4u * j);
    }
    return cnt;
}

/* ---- broadphase (vtbl 0x2ba970) consistency validator: called at the entry of every public method --------------------------- */
uint32_t g_fnt_sap[4096][10];
volatile uint32_t g_fnt_sap_n, g_fnt_sap_firstbad = 0xFFFFFFFFu;

typedef struct { uint32_t hdr[16]; uint32_t S[36]; uint32_t L[3][514]; uint32_t rec[260 * 4]; } fnt_snap_t;
fnt_snap_t g_snap_pre, g_snap_frozen_pre, g_snap_frozen_post;
volatile uint32_t g_snap_frozen_valid;
static void fnt_take_snap(fnt_snap_t *s, uint32_t tag, uint32_t self, uint32_t a0, uint32_t a1)
{
    extern volatile uint32_t g_fnt_nat_idx; static const uint32_t loff[3] = { 0x4Cu, 0x58u, 0x64u }; uint32_t i, li, cnt, p, n;
    memset(s, 0, sizeof *s);
    s->hdr[0] = tag; s->hdr[1] = g_fnt_nat_idx; s->hdr[2] = a0; s->hdr[3] = self; s->hdr[4] = a1;
    for (i = 0; i < 8; ++i) s->hdr[5 + i] = (a1 >= 0x10000u && a1 < 0x90000000u) ? h_rd32(a1 + 4u * i) : 0xDEADu;
    for (i = 0; i < 36; ++i) s->S[i] = h_rd32(self + 4u * i);
    cnt = h_rd32(self + 0x44u); if (cnt > 256u) cnt = 256u;
    for (li = 0; li < 3u; ++li) { p = h_rd32(self + loff[li]); n = h_rd32(self + loff[li] + 4u); if (n > 514u) n = 514u; for (i = 0; i < n; ++i) s->L[li][i] = h_rd32(p + 4u * i); }
    p = h_rd32(self + 0x40u); for (i = 0; i < (cnt + 1u) * 4u && i < 260u * 4u; ++i) s->rec[i] = h_rd32(p + 4u * i);
}
uint32_t dah2_sap(uint32_t tag, uint32_t self, uint32_t a0, uint32_t a1, uint32_t a2)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t st = 0, detail = 0, q, cnt, li, i, n, p, prevk;
    static const uint32_t loff[3] = { 0x4Cu, 0x58u, 0x64u };
    if (!g_fnt_on || self < 0x10000u || self >= 0x90000000u || h_rd32(self) != 0x2BA970u) return 0;
    cnt = h_rd32(self + 0x44u);
    if (cnt == 0u || cnt > 0x400u) st = 0x0100u;
    for (li = 0; li < 3u && !st; ++li) {
        static uint8_t seen[0x400];
        n = h_rd32(self + loff[li] + 4u); p = h_rd32(self + loff[li]);
        if (n != 2u * cnt) { st = 0x0200u | li; detail = n; break; }
        memset(seen, 0, sizeof seen); prevk = 0;
        for (i = 0; i < n; ++i) {
            uint32_t e = h_rd32(p + 4u * i), k = e & 0xFFFFu, id = e >> 16;
            if (k < prevk) { st = 0x0300u | li; detail = i; break; }
            prevk = k;
            if (id >= cnt) { st = 0x0400u | li; detail = (i << 16) | id; break; }
            if (seen[id] < 255u) seen[id]++;
        }
        if (st) break;
        for (i = 0; i < cnt; ++i) if (seen[i] != 2u) { st = 0x0500u | li; detail = (i << 8) | seen[i]; break; }
        if (st) break;
        {   /* every record's stored min/max index must point at its own entry (even key = min, odd key = max) */
            static const uint32_t moff[3] = { 8u, 0u, 2u }, xoff[3] = { 0xAu, 4u, 6u };
            uint32_t rp = h_rd32(self + 0x40u);
            for (i = 1; i < cnt; ++i) {
                uint32_t mi = h_rd32(rp + 16u * i + (moff[li] & ~3u)), xi = h_rd32(rp + 16u * i + (xoff[li] & ~3u)), me, xe;
                mi = (moff[li] & 2u) ? (mi >> 16) : (mi & 0xFFFFu); xi = (xoff[li] & 2u) ? (xi >> 16) : (xi & 0xFFFFu);
                if (mi >= n || xi >= n) { st = 0x0600u | li; detail = (i << 8); break; }
                me = h_rd32(p + 4u * mi); xe = h_rd32(p + 4u * xi);
                if ((me >> 16) != i || (me & 1u)) { st = 0x0700u | li; detail = (i << 16) | mi; break; }
                if ((xe >> 16) != i || !(xe & 1u)) { st = 0x0800u | li; detail = (i << 16) | xi; break; }
            }
        }
    }
    q = (g_fnt_sap_n++) & 4095u;
    g_fnt_sap[q][0] = tag; g_fnt_sap[q][1] = g_fnt_nat_idx; g_fnt_sap[q][2] = st; g_fnt_sap[q][3] = cnt;
    g_fnt_sap[q][4] = a0; g_fnt_sap[q][5] = a1; g_fnt_sap[q][6] = a2; g_fnt_sap[q][7] = detail; g_fnt_sap[q][8] = GetCurrentThreadId(); g_fnt_sap[q][9] = 0;
    if (st && g_fnt_sap_firstbad == 0xFFFFFFFFu) { g_fnt_sap_firstbad = g_fnt_sap_n - 1u; g_snap_frozen_pre = g_snap_pre; fnt_take_snap(&g_snap_frozen_post, tag, self, a0, a1); g_snap_frozen_valid = 1; }
    if (!st && g_fnt_sap_firstbad == 0xFFFFFFFFu) fnt_take_snap(&g_snap_pre, tag, self, a0, a1);
    return st;
}

/* ---- generic small note ring: dah2_note(tag, a, b, c) ---------------------------------------------------------------- */
uint32_t g_fnt_note[1024][8];
volatile uint32_t g_fnt_note_n;
void dah2_note(uint32_t tag, uint32_t a, uint32_t b, uint32_t c)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t q, j;
    if (!g_fnt_on) return;
    q = (g_fnt_note_n++) & 1023u;
    g_fnt_note[q][0] = tag; g_fnt_note[q][1] = g_fnt_nat_idx; g_fnt_note[q][2] = a; g_fnt_note[q][3] = b; g_fnt_note[q][4] = c; g_fnt_note[q][5] = GetCurrentThreadId();
    /* tag 0x147DC0: array of child pointers at [a+0x20], count in b -> first two entries */
    g_fnt_note[q][6] = (c >= 0x10000u && c < 0x90000000u) ? h_rd32(c) : 0u;
    g_fnt_note[q][7] = (c >= 0x10000u && c < 0x90000000u) ? h_rd32(c + 4u) : 0u;
    if ((tag == 0x147DC0u || tag == 0x148560u) && c >= 0x10000u && c < 0x90000000u && b < 4096u) {
        for (j = 0; j < b; ++j) {
            uint32_t e = h_rd32(c + 4u * j);
            if (e < 0x80000000u || e >= 0x88000000u) {
                uint32_t r = (g_fnt_note_n++) & 1023u;
                g_fnt_note[r][0] = 0x1BAD; g_fnt_note[r][1] = g_fnt_nat_idx; g_fnt_note[r][2] = a; g_fnt_note[r][3] = j; g_fnt_note[r][4] = e; g_fnt_note[r][5] = tag;
                g_fnt_note[r][6] = b; g_fnt_note[r][7] = c;
                break;
            }
        }
    }
}

/* ---- callee-saved register contract checker: every instrumented function is wrapped; esi/edi/ebx must be preserved --------- */
typedef struct { uint32_t fn, mask, olds[3], news[3], nat, tid, count, caller; } fnt_clob_t;
fnt_clob_t g_fnt_clob[512];
volatile uint32_t g_fnt_clob_n, g_fnt_clob_total;
void dah2_regclob(uint32_t fn, uint32_t s, uint32_t d, uint32_t b, uint32_t ns, uint32_t nd, uint32_t nb)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t i, mask = (s != ns ? 1u : 0u) | (d != nd ? 2u : 0u) | (b != nb ? 4u : 0u);
    g_fnt_clob_total++;
    for (i = 0; i < g_fnt_clob_n && i < 512u; ++i) if (g_fnt_clob[i].fn == fn && g_fnt_clob[i].mask == mask) { g_fnt_clob[i].count++; return; }
    if (g_fnt_clob_n >= 512u) return;
    i = g_fnt_clob_n++;
    g_fnt_clob[i].fn = fn; g_fnt_clob[i].mask = mask; g_fnt_clob[i].olds[0] = s; g_fnt_clob[i].olds[1] = d; g_fnt_clob[i].olds[2] = b;
    g_fnt_clob[i].news[0] = ns; g_fnt_clob[i].news[1] = nd; g_fnt_clob[i].news[2] = nb; g_fnt_clob[i].nat = g_fnt_nat_idx; g_fnt_clob[i].tid = GetCurrentThreadId(); g_fnt_clob[i].count = 1;
}

/* render-helper argument check: 0x1EB650(arg0, arg1, ...) both are objects whose [+8] is a matrix pointer */
void dah2_note_render(uint32_t tag, uint32_t a0, uint32_t a1)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t q, m0, m1;
    if (!g_fnt_on) return;
    m0 = (a0 >= 0x10000u && a0 < 0x90000000u) ? h_rd32(a0 + 8u) : 0xDEADu;
    m1 = (a1 >= 0x10000u && a1 < 0x90000000u) ? h_rd32(a1 + 8u) : 0xDEADu;
    if ((m0 >= 0x80000000u && m0 < 0x88000000u) && (m1 >= 0x80000000u && m1 < 0x88000000u)) return;     /* only record suspicious calls */
    q = (g_fnt_note_n++) & 1023u;
    g_fnt_note[q][0] = tag; g_fnt_note[q][1] = g_fnt_nat_idx; g_fnt_note[q][2] = a0; g_fnt_note[q][3] = a1; g_fnt_note[q][4] = m0; g_fnt_note[q][5] = m1;
    g_fnt_note[q][6] = h_rd32(a1); g_fnt_note[q][7] = GetCurrentThreadId();
}

/* ---- esp discipline checker: a function must return with the same esp delta (entry esp -> exit esp) on every call ------------ */
typedef struct { uint32_t fn, delta, nat, count, bad_delta, bad_nat, bad_count, pad; } fnt_esp_t;
fnt_esp_t g_fnt_esp[8192];
uint32_t g_fnt_esp_snap[16][67];
uint32_t g_fnt_esp_stk[16][48];
volatile uint32_t g_fnt_esp_bad;
void dah2_espchk(uint32_t fn, uint32_t esp_in, uint32_t esp_out)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t h = (fn * 2654435761u) >> 19, d = esp_out - esp_in, n;
    for (n = 0; n < 8192u; ++n, h = (h + 1u) & 8191u) {
        fnt_esp_t *e = &g_fnt_esp[h];
        if (e->fn == 0) { e->fn = fn; e->delta = d; e->nat = g_fnt_nat_idx; e->count = 1; return; }
        if (e->fn == fn) {
            e->count++;
            if (d != e->delta) {
                if (!e->bad_count) {
                    extern volatile uint32_t g_fnt_flog_idx; extern uint32_t g_fnt_flog[16384];
                    e->bad_delta = d; e->bad_nat = g_fnt_nat_idx;
                    if (g_fnt_esp_bad < 16u) {
                        uint32_t s = g_fnt_esp_bad, k;
                        g_fnt_esp_snap[s][0] = fn; g_fnt_esp_snap[s][1] = esp_in; g_fnt_esp_snap[s][2] = esp_out;
                        for (k = 0; k < 64u; ++k) g_fnt_esp_snap[s][3 + k] = g_fnt_flog[(g_fnt_flog_idx - 64u + k) & 16383u];
                        for (k = 0; k < 48u; ++k) g_fnt_esp_stk[s][k] = h_rd32(esp_in - 0x90u + 4u * k);
                    }
                    g_fnt_esp_bad++;
                }
                e->bad_count++;
            }
            return;
        }
    }
}

/* ---- unresolved indirect TAIL jump log (a switch default / bad table entry returns without running the epilogue) --------- */
uint32_t g_fnt_it[64][14];
volatile uint32_t g_fnt_it_n;
void dah2_itail_fail(uint32_t va, uint32_t ecx, uint32_t edx, uint32_t eax, uint32_t esp, uint32_t line, const char *file)
{
    extern volatile uint32_t g_fnt_nat_idx; uint32_t i, j; const char *b = file, *q; size_t n;
    if (!g_fnt_on) return;
    for (j = 0; j < g_fnt_it_n && j < 64u; ++j) if (g_fnt_it[j][0] == va && g_fnt_it[j][5] == line) { g_fnt_it[j][13]++; return; }
    if (g_fnt_it_n >= 64u) return;
    i = g_fnt_it_n++; g_fnt_it[i][0] = va; g_fnt_it[i][1] = ecx; g_fnt_it[i][2] = edx; g_fnt_it[i][3] = eax; g_fnt_it[i][4] = esp; g_fnt_it[i][5] = line; g_fnt_it[i][6] = g_fnt_nat_idx;
    for (q = file; *q; ++q) if (*q == '\\' || *q == '/') b = q + 1;
    n = strlen(b) + 1; if (n > 24) n = 24;
    memset(&g_fnt_it[i][7], 0, 24); memcpy(&g_fnt_it[i][7], b, n); g_fnt_it[i][13] = 1;
}

/* ---- label path ring: dah2_path(va) is inserted after every label of selected functions (tools/instrument_fn_trace.py PATH_FUNCS) ---- */
uint32_t g_fnt_path[2048][3];
volatile uint32_t g_fnt_path_n;
void dah2_path(uint32_t va, uint32_t esp, uint32_t extra)
{
    uint32_t q;
    if (!g_fnt_on) return;
    q = (g_fnt_path_n++) & 2047u; g_fnt_path[q][0] = va; g_fnt_path[q][1] = esp; g_fnt_path[q][2] = extra;
}

/* loop-index monotonicity check for the 0x178490 loop of sub_00177FB0: i must advance by exactly one per iteration.  The first
 * violation freezes the label path ring (g_fnt_on = 0) so the 2048 labels leading up to it can be read back. */
volatile uint32_t g_fnt_loop_anom, g_fnt_loop_freeze;
void dah2_loopchk(uint32_t i, uint32_t n, uint32_t esp, uint32_t reset)
{
    static uint32_t prev = 0xFFFFFFFFu;
    if (!g_fnt_on) return;
    if (reset) { prev = 0xFFFFFFFFu; return; }
    if (prev != 0xFFFFFFFFu && i != prev + 1u && !g_fnt_loop_anom) {
        g_fnt_loop_anom = 1; dah2_note(0x1784FF, prev, i, esp); dah2_note(0x1784FE, n, esp, 0); if (g_fnt_loop_freeze) g_fnt_on = 0;
    }
    prev = i;
}

/* ---- allocation / free counts per caller of the game's allocator wrappers (0xF96C0 alloc, 0xF96E0 free) ------------------------ */
typedef struct { uint32_t ra, allocs, bytes, frees; } fnt_acaller_t;
fnt_acaller_t g_fnt_acaller[4096];
void dah2_alloc_caller(uint32_t ra, uint32_t size, uint32_t is_free)
{
    uint32_t h, n;
    if (!g_fnt_on) return;
    h = (ra * 2654435761u) >> 20;
    for (n = 0; n < 4096u; ++n, h = (h + 1u) & 4095u) {
        fnt_acaller_t *e = &g_fnt_acaller[h];
        if (e->ra == 0 || e->ra == ra) {
            e->ra = ra;
            if (is_free) e->frees++; else { e->allocs++; e->bytes += size; }
            return;
        }
    }
}

/* stream-buffer pointer log: kind 0 = constructor stored it, kind 1 = destructor is about to free it */
uint32_t g_fnt_arena[2][1024];
volatile uint32_t g_fnt_arena_n[2];
void dah2_arena(uint32_t kind, uint32_t ptr)
{
    uint32_t i;
    if (!g_fnt_on || kind > 1u) return;
    i = g_fnt_arena_n[kind]++;
    if (i < 1024u) g_fnt_arena[kind][i] = ptr;
}

/* allocator free probe: chunk header size word before/after the game's free() for large aligned chunks */
uint32_t g_fnt_free_log[64][6];
volatile uint32_t g_fnt_free_log_n;
void dah2_free_probe(uint32_t ptr, uint32_t hdr, uint32_t before, uint32_t after, uint32_t freebytes, uint32_t top)
{
    uint32_t i;
    if (!g_fnt_on || (before & ~1u) < 150000u || g_fnt_free_log_n >= 64u) return;
    i = g_fnt_free_log_n++;
    g_fnt_free_log[i][0] = ptr; g_fnt_free_log[i][1] = hdr; g_fnt_free_log[i][2] = before; g_fnt_free_log[i][3] = after; g_fnt_free_log[i][4] = freebytes; g_fnt_free_log[i][5] = top;
}

/* ---- ring of the last indirect-call targets (RECOMP_ICALL_SAFE sites) ---------------------------------------------------- */
uint32_t g_fnt_ics[512][4];
uint32_t g_fnt_ics2[64][6];
volatile uint32_t g_fnt_ics2_n;
volatile uint32_t g_fnt_ics_n;
volatile uint32_t g_fnt_icall_line;        /* set from outside: histogram the targets of the ICALL_SAFE at this generated-source line */
uint32_t g_fnt_icall_hist[64][2];
void dah2_icall_seen(uint32_t va, uint32_t esp, uint32_t ecx, uint32_t line)
{
    uint32_t q;
    if (!g_fnt_on || va == 0u) return;
    if (g_fnt_icall_line && h_rd32(esp) == g_fnt_icall_line) {
        uint32_t k; for (k = 0; k < 64u; ++k) { if (g_fnt_icall_hist[k][0] == va) { g_fnt_icall_hist[k][1]++; break; } if (!g_fnt_icall_hist[k][0]) { g_fnt_icall_hist[k][0] = va; g_fnt_icall_hist[k][1] = 1; break; } }
    }
    q = (g_fnt_ics_n++) & 511u; g_fnt_ics[q][0] = va; g_fnt_ics[q][1] = esp; g_fnt_ics[q][2] = ecx; g_fnt_ics[q][3] = line;
    if (line == 66411u) { static uint32_t s_n; uint32_t k = (s_n++) & 63u; extern uint32_t g_fnt_ics2[64][6]; extern volatile uint32_t g_fnt_ics2_n;
        g_fnt_ics2[k][0] = va; g_fnt_ics2[k][1] = esp; g_fnt_ics2[k][2] = ecx; g_fnt_ics2[k][3] = h_rd32(ecx); g_fnt_ics2[k][4] = h_rd32(esp + 4u); g_fnt_ics2[k][5] = s_n; g_fnt_ics2_n = s_n; }
}
