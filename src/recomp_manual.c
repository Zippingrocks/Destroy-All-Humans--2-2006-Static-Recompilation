/**
 * Manual function overrides and ICALL diagnostics
 *
 * This file provides:
 *   - recomp_lookup_manual()  : intercept specific Xbox VAs with hand-written code
 *   - recomp_icall_fail_log() : log when an indirect call target can't be resolved
 *   - ICALL trace ring buffer  : globals used by the RECOMP_ICALL macro
 *
 * The recomp pipeline generates an auto-dispatch table (recomp_lookup) that
 * resolves most function addresses. recomp_lookup_manual() is called FIRST,
 * giving you a chance to override any function with a custom implementation.
 *
 * Common reasons to add manual overrides:
 *   - Trace a function to understand call flow (wrap the generated version)
 *   - Fix a function the lifter translated incorrectly
 *   - Stub out a function that crashes (return early, set eax to a safe value)
 *   - Redirect a function to a native implementation (e.g., skip CRT init)
 *   - Intercept D3D/audio calls for custom rendering or sound
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <windows.h>  /* GetCurrentThreadId, for multi-thread-aware tracing */
#include "trace_control.h"
#include "parity_checkpoint.h"

/* ── ICALL trace ring buffer ───────────────────────────────── */

/*
 * These globals are written by the RECOMP_ICALL macro (defined in
 * recomp_types.h) every time an indirect call is dispatched. When a
 * crash occurs, the VEH handler or recomp_icall_fail_log() can dump
 * the last 16 call targets to help you trace what happened.
 *
 * If your recomp_types.h defines these as extern, they must be
 * defined here (or in xbox_memory_layout.c if you use that pattern).
 */
extern volatile uint32_t g_icall_trace[16];
extern volatile uint32_t g_icall_trace_idx;
extern volatile uint64_t g_icall_count;

typedef void (*recomp_func_t)(void);

/* Forward declarations for functions used before their definition in this file */
recomp_func_t recomp_lookup_manual(uint32_t xbox_va);
extern recomp_func_t recomp_lookup(uint32_t xbox_va);

/* ── Register state (defined in xbox_memory_layout.c) ──────── */

extern __declspec(thread) uint32_t g_eax;
extern __declspec(thread) uint32_t g_esp;
extern __declspec(thread) uint32_t g_ecx;
extern __declspec(thread) uint32_t g_edx;
extern __declspec(thread) uint32_t g_ebx;
extern __declspec(thread) uint32_t g_esi;
extern __declspec(thread) uint32_t g_edi;
extern __declspec(thread) uint32_t g_ebp;
extern __declspec(thread) uint32_t g_seh_ebp;
extern ptrdiff_t g_xbox_mem_offset;

static __forceinline uint32_t *manual_mem32(uint32_t va)
{
    return (uint32_t *)((uintptr_t)g_xbox_mem_offset + va);
}

static __forceinline uint8_t *manual_mem8(uint32_t va)
{
    return (uint8_t *)((uintptr_t)g_xbox_mem_offset + va);
}

/* TEMP: targeted "this"-pointer ICALL watch, see recomp_types.h's
 * RECOMP_ICALL_SAFE macro. Set from recomp_manual.c wrappers once the
 * object of interest is identified at runtime; 0 disables the watch. */
volatile uint32_t g_icall_watch_this = 0x0025E5B0u;  /* TEMP: watching D3D device object for the sub_00254FC0-area crash */
volatile uint32_t g_icall_watch_this2;
int g_manual_transplant_icall_trace = 0;  /* TEMP: trace every ICALL inside the transplanted functions below */
void recomp_icall_watch_log(uint32_t this_ptr, uint32_t target, uint32_t line)
{
    static volatile long s_count;
    long n = InterlockedIncrement(&s_count);
    if (n <= 60)
        DAH2_TRACE_FPRINTF(stderr, "[ICALL-WATCH] #%ld this=0x%08X target=0x%08X macro_line=%u esp=0x%08X\n",
                n, this_ptr, target, line, g_esp);
}

/* ── Focused generated-function tracing ───────────────────── */

void recomp_trace_enter(const char *name, uint32_t va)
{
    uint32_t guest_return = (g_esp >= 0x10000u && g_esp < 0x01000000u)
        ? *manual_mem32(g_esp) : 0;
    DAH2_TRACE_FPRINTF(stderr, "[TRACE] -> %s (0x%08X) ret=%08X esp=%08X eax=%08X ebx=%08X esi=%08X edi=%08X\n",
            name, va, guest_return, g_esp, g_eax, g_ebx, g_esi, g_edi);
    fflush(stderr);
}

void recomp_trace_exit(const char *name, uint32_t va)
{
    DAH2_TRACE_FPRINTF(stderr, "[TRACE] <- %s (0x%08X) esp=%08X eax=%08X ebx=%08X esi=%08X edi=%08X\n",
            name, va, g_esp, g_eax, g_ebx, g_esi, g_edi);
    fflush(stderr);
}

void recomp_trace_esp(const char *name, const char *tag)
{
    DAH2_TRACE_FPRINTF(stderr, "[TRACE]    %s %s esp=%08X eax=%08X ebx=%08X esi=%08X edi=%08X\n",
            name, tag, g_esp, g_eax, g_ebx, g_esi, g_edi);
    fflush(stderr);
}

/* ── Manual function overrides ─────────────────────────────── */

/*
 * Return a function pointer to override the given Xbox VA, or NULL
 * to fall through to the auto-generated dispatch table.
 *
 * This is called on every indirect call (RECOMP_ICALL) and every
 * direct call through the dispatch table, so keep it fast. A chain
 * of if-statements on uint32_t compiles to a simple comparison
 * sequence; for large override tables, consider a sorted array
 * with binary search.
 *
 * Examples of common override patterns:
 *
 *   // Trace wrapper: log entry/exit around the generated function
 *   extern void sub_00012345(void);
 *   static void traced_sub_00012345(void) {
 *       DAH2_TRACE_FPRINTF(stderr, "[TRACE] sub_00012345 entered, eax=0x%08X\n", g_eax);
 *       sub_00012345();
 *       DAH2_TRACE_FPRINTF(stderr, "[TRACE] sub_00012345 returned, eax=0x%08X\n", g_eax);
 *   }
 *
 *   // Stub: skip a function entirely (return 0 in eax)
 *   static void stub_00067890(void) {
 *       g_eax = 0;
 *   }
 *
 *   // Fix: replace a broken lifted function with correct C
 *   static void fixed_sub_000ABCDE(void) {
 *       // Read arguments from stack/registers per calling convention
 *       uint32_t arg1 = g_ecx;
 *       uint32_t arg2 = MEM32(g_esp + 4);
 *       // ... correct implementation ...
 *       g_eax = result;
 *   }
 */
static void init_dsound_00265785(void) { *manual_mem32(0x00280358) = 0x0027FC78; g_esp += 4; }
static void init_dsound_00265790(void) { *manual_mem32(0x00280354) = 0x0027FC7C; g_esp += 4; }
static void init_dsound_00268750(void) { *manual_mem32(0x00280400) = 0x0027FC80; g_esp += 4; }
static void init_dsound_0026875B(void) { *manual_mem32(0x002803FC) = 0x0027FC84; g_esp += 4; }

/* Retail 0x001593F4..0x00159414 is the result-write tail of the render
 * object's sub_001593A0 dispatcher, not a separate no-argument function.
 * The generated unresolved stub omitted the store and popped only the return
 * address; retail RET 0x10 also consumes the dispatcher's four arguments. */
void sub_001593F4(void)
{
    g_edx = *manual_mem32(g_ecx + 0x1680u);
    g_ecx = (g_ecx + 0x4C3u) & 0xFFFFFFFCu;
    g_ecx = *manual_mem32(g_ecx + g_edx * 4u);
    g_edx = *manual_mem32(g_esp + 8u);
    *manual_mem32(g_ecx + g_eax * 4u + 0x444u) = g_edx;
    g_esp += 20u; /* ret 0x10 */
}

/* Retail 0x000F360B..0x000F3616 is the shared epilogue of sub_000F3470.
 * Its empty-array branch reached an unresolved stub, leaking the 0x188-byte
 * local frame plus four saved registers (0x198 bytes) into frame setup. */
void sub_000F360B(void)
{
    g_edi = *manual_mem32(g_esp); g_esp += 4u;
    g_esi = *manual_mem32(g_esp); g_esp += 4u;
    g_ebp = *manual_mem32(g_esp); g_esp += 4u;
    g_seh_ebp = g_ebp; /* restored frame for translator-split continuations */
    g_ebx = *manual_mem32(g_esp); g_esp += 4u;
    g_esp += 0x188u;
    g_esp += 4u; /* ret */
}

/* Retail 0x000F4A60..0x000F4A92: find a pointer in an inline array and
 * publish the iterator (or end) through arg1. The old lift stopped before
 * its loop and both result-store/RET8 tails. Render state-19 cleanup uses
 * this iterator in an erase/memmove, so a missing store corrupts guest RAM. */
void sub_000F4A60(void)
{
    g_eax = (g_ecx + 7u) & 0xFFFFFFFCu;
    g_ecx = *manual_mem32(g_ecx);
    g_edx = g_eax + g_ecx * 4u;
    g_ecx = g_eax;
    if (g_ecx != g_edx) {
        g_eax = *manual_mem32(g_esp + 8u);
        while (*manual_mem32(g_ecx) != g_eax) {
            g_ecx += 4u;
            if (g_ecx == g_edx)
                break;
        }
    }
    g_eax = *manual_mem32(g_esp + 4u);
    *manual_mem32(g_eax) = g_ecx;
    g_esp += 12u; /* ret 8 */
}

/* sub_000F78B0 is the vtable+0x48 render-event dispatcher.  When it receives
 * the 4BED1273 "frame complete" event it calls sub_001564E0, which sets
 * MEM32(manager+0x14) bit 0 (the frame-loop exit bit) whenever the pending
 * render buffer queue is empty.  On real Xbox hardware that bit is only set
 * asynchronously by the GPU after the render queue drains; our synchronous
 * bridge never has a pending buffer ready at this point, so the bit fires
 * immediately and kills the frame loop after 14 frames.
 *
 * The fix: call the original dispatcher, then clear the exit bit and restore
 * the current render-object pointer so the frame loop keeps running. */
extern void sub_000F78B0(void);

static void override_sub_000F78B0(void)
{
    uint32_t esp_in   = g_esp;
    uint32_t outer    = (esp_in >= 0x10000u && esp_in < 0x37FFFFFFu)
                        ? *manual_mem32(esp_in + 4) : 0u;
    uint32_t manager  = g_ecx;
    uint32_t current_saved = (manager >= 0x10000u && manager < 0x38000000u)
                              ? *manual_mem32(manager + 0x7E18) : 0u;

    sub_000F78B0();

    if (outer == 0x4BED1273u && manager >= 0x10000u && manager < 0x38000000u) {
        if (*manual_mem32(manager + 0x14) & 1u) {
            *manual_mem32(manager + 0x14) &= ~1u;
            /* Restore the current render object so the next 4BED1273 dispatch
             * calls sub_001587C0 with a valid object rather than spinning with
             * a null current pointer. */
            if (*manual_mem32(manager + 0x7E18) == 0u && current_saved != 0u)
                *manual_mem32(manager + 0x7E18) = current_saved;
            static unsigned suppress_count;
            if (++suppress_count <= 8)
                DAH2_TRACE_FPRINTF(stderr,
                    "[FRAME-CAP] suppressed exit-bit manager=%08X current=%08X (#%u)\n",
                    manager, current_saved, suppress_count);
        }
    }

    /* Retail is thiscall with two stack arguments (ret 8).  Keep the frame
       callback from accumulating a four-byte leak when a translated nested
       event handler returns through a detector-split continuation. */
    g_esp = esp_in + 12u;
}

extern void sub_001A7110(void);
extern void sub_001A7160(void);
static void trace_heap_alloc(void)
{
    uint32_t sp = g_esp, si = g_esi, di = g_edi, bx = g_ebx;
    uint32_t size = *manual_mem32(sp + 4);
    sub_001A7110();
    if (g_esp != sp + 12 || g_esi != si || g_edi != di || g_ebx != bx)
        DAH2_TRACE_FPRINTF(stderr, "[HEAP-ABI] alloc size=%u sp=%08X->%08X esi=%08X->%08X edi=%08X->%08X ebx=%08X->%08X\n", size, sp, g_esp, si, g_esi, di, g_edi, bx, g_ebx);
}
static void trace_heap_free(void)
{
    uint32_t sp = g_esp, si = g_esi, di = g_edi, bx = g_ebx;
    uint32_t address = *manual_mem32(sp + 4);
    sub_001A7160();
    if (g_esp != sp + 8 || g_esi != si || g_edi != di || g_ebx != bx)
        DAH2_TRACE_FPRINTF(stderr, "[HEAP-ABI] free address=%08X sp=%08X->%08X esi=%08X->%08X edi=%08X->%08X ebx=%08X->%08X\n", address, sp, g_esp, si, g_esi, di, g_edi, bx, g_ebx);
}

/* sub_0008F860 tail-calls sub_0008F7B0 when the event tag matches 0xD2EB1B81.
 * sub_0008F7B0 does PUSH/POP esi around its body, but as a tail call the stack
 * layout is wrong (caller's event arg still present), so POP restores the event
 * address (0x0008F7FF) into esi instead of the caller's saved value.  The list
 * walker sub_0004D440 uses esi as the current-node pointer, so it then chases
 * garbage and eventually crashes when esi=0xFFFFFFFF.  Saving/restoring g_esi
 * around the call prevents the corruption entirely. */
extern void sub_0008F860(void);
static void safe_sub_0008F860(void)
{
    uint32_t saved_esi = g_esi;
    sub_0008F860();
    g_esi = saved_esi;
}

/* sub_0003C080 is a vtable event handler that runs its own inner list walk.
 * An inner callee has a missing esp-alloc prologue, so sub_0003C080's epilogue
 * POPs read from shifted stack positions, corrupting esi (current-node pointer),
 * edi (sentinel) and ebx (event ptr) in the outer list walker sub_0004D440.
 * The outer walker then chases garbage nodes until esi=0xFFFFFFFF → crash.
 * Saving/restoring all three registers and forcing correct esp consumption
 * (ret 4 = 8 bytes: return addr + 1 caller-pushed arg) prevents the corruption. */
extern void sub_0003C080(void);
static void safe_sub_0003C080(void)
{
    uint32_t saved_esi = g_esi;
    uint32_t saved_edi = g_edi;
    uint32_t saved_ebx = g_ebx;
    uint32_t expected_esp = g_esp + 8;  /* ret 4 */
    sub_0003C080();
    g_esp = expected_esp;
    g_esi = saved_esi;
    g_edi = saved_edi;
    g_ebx = saved_ebx;
}

/* sub_00035970 is a vtable event dispatch that uses the same sub_0004D440
 * list-walk pattern as sub_0003C080.  Its inner callees (sub_00035040,
 * sub_00115F60) leave a combined 24-byte esp leak, corrupting the walker's
 * esi (current-node) and edi (sentinel) registers.  Save/restore + esp fix. */
extern void sub_00035970(void);
static void safe_sub_00035970(void)
{
    uint32_t saved_esi = g_esi;
    uint32_t saved_edi = g_edi;
    uint32_t saved_ebx = g_ebx;
    uint32_t expected_esp = g_esp + 8;  /* ret 4 */
    sub_00035970();
    g_esp = expected_esp;
    g_esi = saved_esi;
    g_edi = saved_edi;
    g_ebx = saved_ebx;
}

/* sub_00161E50 is a hash-table lookup/insert helper (factory registration path):
 * cdecl, 1 stack arg (key), returns the found/created node in eax, "ret 4".
 * Retail disassembly (push ecx/esi/edi at entry; pop edi, mov eax,esi, pop esi,
 * pop ecx, ret 4 at the epilogue) fully restores the caller's ecx/esi/edi and
 * returns its result only via eax.
 *
 * It is called by NAME at 31 sites across the generated sources (not
 * dispatched via ICALL), so recomp_lookup_manual cannot intercept it -- this
 * definition instead relies on /FORCE:MULTIPLE (recomp_manual.obj is linked
 * before every recomp_gen*.obj) to replace the generated symbol everywhere.
 *
 * Root cause of the bug being fixed: the conditional inner virtual dispatch
 * (retail 0x161E75: `call [edx+4]` on the looked-up node, taken whenever the
 * hash lookup misses/creates) reaches a callee that does not fully preserve
 * esi/edi/ebx the way the fixed thiscall ABI guarantees. On real hardware
 * every callee at that vtable slot is required to leave esi/edi/ebx intact;
 * ours does not, so this function's own epilogue pops end up reading the
 * wrong stack slots and hand a garbage edi (observed as the literal return
 * address 0x161E7D) back to the caller. That garbage edi then propagates into
 * sub_0011C8B0's notify-list walk (edi+0x58/+0x60 read as a bogus array),
 * producing a null list entry whose "vtable+8" dispatch fails against ICALL
 * VA 0x2AE888 (an SEH scope-table sentinel) in an unbounded per-frame loop.
 *
 * Fix: reimplement this function directly (rather than wrap it), and harden
 * only the risky inner virtual dispatch by saving/restoring esi/edi/ebx and
 * forcing the correct ret-4 stack delta around it, exactly as retail's ABI
 * contract requires. sub_00161D80 (the hash lookup itself) is unmodified and
 * called exactly as retail does. */
extern void sub_00161D80(void);

void sub_00161E50(void)
{
    uint32_t saved_ecx = g_ecx;
    uint32_t saved_esi = g_esi;
    uint32_t saved_edi = g_edi;
    uint32_t saved_ebx = g_ebx;

    uint32_t key = *manual_mem32(g_esp + 4);  /* caller's single stack arg */

    /* Scratch out-parameter byte for sub_00161D80, matching retail's local
     * flag slot (lea eax,[esp+0xb]); a full dword is used instead of the
     * retail sub-dword offset since only the byte's value matters here. */
    g_esp -= 4;
    uint32_t flag_addr = g_esp;
    *manual_mem8(flag_addr) = 0;

    /* sub_00161D80(key, &flag) -- cdecl, callee cleans up (ret 8). Push
     * order matches retail: &flag first (farther from retaddr), key last
     * (closest to retaddr / first dword the callee reads). ecx carries the
     * manager/"this" pointer straight through, exactly as retail leaves it
     * untouched from the caller. */
    g_esp -= 4; *manual_mem32(g_esp) = flag_addr;
    g_esp -= 4; *manual_mem32(g_esp) = key;
    g_ecx = saved_ecx;
    g_esp -= 4; *manual_mem32(g_esp) = 0x00161E67u;
    sub_00161D80();

    uint32_t node = g_eax;
    uint8_t flag = *manual_mem8(flag_addr);
    g_esp += 4;  /* release our scratch flag slot */

    {
        static volatile long s_lookup_count;
        long n = InterlockedIncrement(&s_lookup_count);
        if (n <= 60)
            DAH2_TRACE_FPRINTF(stderr, "[LOOKUP] tid=%lu #%ld key=0x%08X node=0x%08X flag=%u callsite=0x%08X\n",
                    (unsigned long)GetCurrentThreadId(), n, key, node, flag, *manual_mem32(g_esp));
    }

    if (flag == 0 && node != 0) {
        uint32_t vtbl = *manual_mem32(node);
        uint32_t target = *manual_mem32(vtbl + 4);
        if (target) {
            static volatile long s_dispatch_count;
            long dn = InterlockedIncrement(&s_dispatch_count);
            if (dn <= 40)
                DAH2_TRACE_FPRINTF(stderr, "[DISPATCH] tid=%lu #%ld key=0x%08X node=0x%08X vtbl=0x%08X target=0x%08X\n",
                        (unsigned long)GetCurrentThreadId(), dn, key, node, vtbl, target);
            uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
            uint32_t call_esp = g_esp;
            g_esp -= 4; *manual_mem32(g_esp) = key;          /* arg */
            g_ecx = node;                                     /* this */
            g_esp -= 4; *manual_mem32(g_esp) = 0x00161E7Du;   /* fake retaddr */
            recomp_func_t fn = recomp_lookup_manual(target);
            if (!fn) fn = recomp_lookup(target);
            if (fn) fn();
            /* Force the correct ret-4 stack delta and fully restore
             * esi/edi/ebx regardless of the callee's actual behaviour --
             * retail's fixed thiscall ABI at this vtable slot guarantees
             * both, and the whole point of this override is to enforce
             * that guarantee even when the callee itself does not. */
            g_esp = call_esp;
            g_esi = protect_esi;
            g_edi = protect_edi;
            g_ebx = protect_ebx;
        }
    }

    g_eax = node;
    g_ecx = saved_ecx;
    g_esi = saved_esi;
    g_edi = saved_edi;
    g_ebx = saved_ebx;
    g_esp += 8;  /* ret 4: pop retaddr (4) + caller's single stack arg (4) */
}

/* sub_00162110 is a factory constructor not in the generated dispatch table
 * (reachable only via the factory data slot for type key E3554C44).
 * Decoded from XBE bytes at file offset 0x152110:
 *   - reads singleton at 0x003155EC; calls sub_00018030 to init if null
 *   - ECX = object, EAX = *object, MEM32(0x3155EC) = EAX
 *   - tail-calls sub_0015D000 (cdecl, no args, ret 0)
 * Calling convention: cdecl, 0 params, ret 0 */
extern void sub_00018030(void);
extern void sub_0015D000(void);

static void manual_sub_00162110(void)
{
    uint32_t obj = *manual_mem32(0x3155EC);
    if (!obj) {
        g_ecx = 0x3155EC;
        g_esp -= 4; *manual_mem32(g_esp) = 0x00162123u;
        sub_00018030();
        obj = *manual_mem32(0x3155EC);
    }
    g_ecx = obj;
    g_eax = *manual_mem32(obj);
    *manual_mem32(0x3155EC) = g_eax;
    g_esp -= 4; *manual_mem32(g_esp) = 0x00162136u;
    sub_0015D000();
    /* sub_0015D000 does ret 0 (esp+=4), consuming the fake return addr */
    g_esp += 4; /* this function is cdecl ret 0 */
}

/* sub_00155210 is the renderer-listener notify thunk.  It pushes 2 args (edx
 * and the constant 0x1AE7CEFD) before the inner RECOMP_ICALL, but the inner
 * vtable target does ret 0 (no arg cleanup).  Sub_00155210's own "esp += 8;
 * return" epilogue was written for ret 4 and doesn't compensate, so the
 * NOTIFY iterator sees esp drop by 8 per call.  The delta=-120 event=0 case
 * shows a deeper corruption that causes multi-second stalls between frames.
 * Forcing g_esp to entry + 8 (what the correct ret 4 should produce) repairs
 * the accumulation without affecting sub_00155210's functional side effects. */
extern void sub_00155210(void);
static void safe_sub_00155210(void)
{
    uint32_t expected_esp = g_esp + 8;  /* ret 4: return addr + 1 caller arg */
    sub_00155210();
    g_esp = expected_esp;
}

/* sub_001C7FB9 is the Xbox CRT Small Block Heap (SBH) allocator.
 * It expects a pre-initialized SBH region whose per-segment structures
 * (size-class bitmaps, free-list sentinels) are never set up in the recomp
 * because the Xbox CRT initialization code relies on kernel callbacks that
 * do not exist on PC.  The inner allocator (sub_000FEAAD) therefore always
 * returns NULL, and the OOM retry callback at MEM32(0x323DB8) keeps returning
 * non-zero (claiming it freed something), so the SBH spin loop never exits.
 *
 * Fix: redirect every SBH alloc through xbox_HeapAlloc, which uses our own
 * bump-pointer Xbox-VA heap and always succeeds for reasonable sizes.
 *
 * Stack on entry (cdecl, ret 8):
 *   esp+0  return address
 *   esp+4  arg1 – SBH heap-descriptor pointer (ignored; may be 0)
 *   esp+8  arg2 – requested byte count */
extern uint32_t xbox_HeapAlloc(uint32_t size, uint32_t alignment);

static void override_sub_001C7FB9(void)
{
    uint32_t size = *manual_mem32(g_esp + 8);
    if (size == 0) size = 1;
    size = (size + 15u) & ~15u;  /* SBH always rounds up to 16 */
    g_eax = xbox_HeapAlloc(size, 16u);
    static unsigned sbh_count;
    if (++sbh_count <= 8)
        DAH2_TRACE_FPRINTF(stderr, "[SBH-BYPASS] #%u size=%u → 0x%08X\n",
                sbh_count, size, g_eax);
    g_esp += 12;  /* ret 8: return addr + 2 args */
}

/* sub_0015D190 — correct replacement linked via /FORCE:MULTIPLE.
 *
 * The generated version (recomp_0009.c) has two ICALL sites that each push
 * one esi argument and expect the callee to do RETN 4 (stdcall cleanup), but
 * the actual vtable entries do RETN 0 (cdecl).  The missing esp compensation
 * leaks 4 bytes per ICALL; combined with one level of recursion the total leak
 * per call is 16 bytes.  This version saves esp around each ICALL and restores
 * it unconditionally, so the leak is neutralised regardless of callee ABI.
 *
 * recomp_manual.obj is listed before recomp_0009.obj in dah2_recomp.vcxproj,
 * so with /FORCE:MULTIPLE the linker picks this definition. */
extern void sub_00164C50(void);
extern void sub_0013C1A0(void);

void sub_0015D190(void)
{
    /* Prologue: PUSH esi, PUSH edi */
    g_esp -= 4; *manual_mem32(g_esp) = g_esi;
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_esi = g_ecx;

    g_esp -= 4; *manual_mem32(g_esp) = 0x0015D199u;
    sub_00164C50();

    g_edx = g_esi + 0x60u;
    g_ecx = g_esi + 0xA0u;
    g_esp -= 4; *manual_mem32(g_esp) = 0x0015D1A7u;
    sub_0013C1A0();

    /* Traverse child linked list at esi+0xC, siblings via +0x40 */
    g_edi = *manual_mem32(g_esi + 0x0Cu);
    while (g_edi != 0) {
        g_ecx = g_edi;
        g_esp -= 4; *manual_mem32(g_esp) = 0x0015D1B7u;
        sub_0015D190();
        g_edi = *manual_mem32(g_edi + 0x40u);
    }

    /* ICALL vtable+0x1C on object at esi+0xE8, arg=esi */
    g_eax = *manual_mem32(g_esi + 0xE8u);
    if (g_eax) {
        uint32_t esp0 = g_esp;
        g_ecx = g_eax;
        uint32_t vtbl = *manual_mem32(g_ecx);
        uint32_t target = *manual_mem32(vtbl + 0x1Cu);
        g_esp -= 4; *manual_mem32(g_esp) = g_esi;
        g_esp -= 4; *manual_mem32(g_esp) = 0x0015D1D0u;
        if (target) {
            recomp_func_t fn = recomp_lookup_manual(target);
            if (!fn) fn = recomp_lookup(target);
            if (fn) fn();
        }
        g_esp = esp0;  /* restore esp: callee does RETN 0, not RETN 4 */
    }

    /* ICALL vtable+0x10 on object at esi+0xEC, arg=esi */
    g_eax = *manual_mem32(g_esi + 0xECu);
    if (g_eax) {
        uint32_t esp0 = g_esp;
        g_ecx = g_eax;
        uint32_t vtbl = *manual_mem32(g_ecx);
        uint32_t target = *manual_mem32(vtbl + 0x10u);
        g_esp -= 4; *manual_mem32(g_esp) = g_esi;
        g_esp -= 4; *manual_mem32(g_esp) = 0x0015D1E2u;
        if (target) {
            recomp_func_t fn = recomp_lookup_manual(target);
            if (!fn) fn = recomp_lookup(target);
            if (fn) fn();
        }
        g_esp = esp0;
    }

    /* Epilogue: POP edi, POP esi, ret 0 */
    g_edi = *manual_mem32(g_esp); g_esp += 4;
    g_esi = *manual_mem32(g_esp); g_esp += 4;
    g_esp += 4;  /* pop return address */
}

static void safe_sub_0015D190(void)
{
    /* Dispatch wrapper: sub_0015D190 is now correctly implemented above, so
     * the save/restore here is a no-op guard for the ICALL path. */
    uint32_t saved_esi = g_esi, saved_edi = g_edi, saved_ebx = g_ebx;
    uint32_t expected_esp = g_esp + 4;
    sub_0015D190();
    g_esp = expected_esp;
    g_esi = saved_esi; g_edi = saved_edi; g_ebx = saved_ebx;
}

extern void sub_00157460(void);
extern void sub_0010E310(void);
extern recomp_func_t recomp_lookup_kernel(uint32_t xbox_va);
void recomp_icall_fail_log(uint32_t va);  /* defined later in this file */

/* sub_002117C0 is the script VM's "invoke native/script callback" dispatcher
 * (the [SCRIPT-CALL]/[SCRIPT-RETURN] trace site, retail 0x2117F9: `call
 * dword ptr [ebx]`). Retail fully preserves the caller's edi across the call
 * (push edi at entry, pop at exit; MEM32(esi+0x10) is saved/restored via a
 * local scratch value, not a real register). The indirect target varies by
 * script opcode/callback, and at least one of them does not preserve
 * esi/edi/ebx per the fixed calling convention -- observed corrupting the
 * caller (sub_00211810): edi ends up holding this function's own return
 * address literal (0x2117FD) and esi is zeroed, which then propagates into
 * a null-object dispatch several frames further down (sub_002119D0 ->
 * sub_002180E0, ICALL against garbage VA 0x00100000).
 *
 * Full replacement via /FORCE:MULTIPLE; sub_002115F0 is called unmodified,
 * exactly as retail does. Only the SCRIPT-CALL indirect dispatch is
 * hardened with esi/edi/ebx save-restore. */
extern void sub_002115F0(void);
extern __declspec(thread) uint32_t g_dah2_lua_context_hint;

void sub_002117C0(void)
{
    static uint32_t callback_1018_count;
    uint32_t saved_edi = g_edi;
    uint32_t scratch_ebp = *manual_mem32(g_esi + 0x10);  /* retail: ebp = MEM32(esi+0x10) */

    g_edi = (uint32_t)(int32_t)(int16_t)(*(volatile uint16_t *)manual_mem8(g_ebx + 0xE));
    g_edx = g_edi + 0x14;
    g_ecx = g_esi;
    *manual_mem32(g_esi + 0x10) = g_eax;
    g_esp -= 4; *manual_mem32(g_esp) = 0x002117D6u;
    sub_002115F0();

    if ((int32_t)g_edi > 0) {
        uint32_t src = g_ebx + 0x10;
        while (g_edi != 0) {
            uint32_t dst = *manual_mem32(g_esi);
            *manual_mem32(dst)     = *manual_mem32(src);
            *manual_mem32(dst + 4) = *manual_mem32(src + 4);
            *manual_mem32(g_esi) = dst + 8;
            src += 8;
            g_edi--;
        }
    }

    g_ecx = g_esi;
    /* This /FORCE:MULTIPLE override is the implementation that actually wins
     * the link. Publish the VM state here, at the real callback boundary, so
     * Lua's error/throw helpers can recover ECX after a translated callback
     * violates the original Xbox thiscall contract. */
    g_dah2_lua_context_hint = g_esi;
    {
        uint32_t protect_esi = g_esi, protect_ebx = g_ebx;
        uint32_t icall_esp = g_esp;
        uint32_t icall_target = *manual_mem32(g_ebx);
        uint32_t callback_ordinal = 0;
        if (icall_target == 0x001018D0u) callback_ordinal = ++callback_1018_count;
        if (icall_target == 0x001018D0u || icall_target == 0x00124DC0u) {
            DAH2_TRACE_FPRINTF(stderr,
                    "[SCRIPT-CALL] target=%08X ordinal=%u ax=%08X cx=%08X dx=%08X "
                    "bx=%08X sp=%08X bp=%08X si=%08X di=%08X "
                    "top=%08X s0=%08X s1=%08X s2=%08X s3=%08X\n",
                    icall_target, callback_ordinal, g_eax, g_ecx, g_edx, g_ebx, g_esp,
                    g_ebp, g_esi, g_edi, *manual_mem32(protect_esi),
                    *manual_mem32(g_esp), *manual_mem32(g_esp + 4),
                    *manual_mem32(g_esp + 8), *manual_mem32(g_esp + 12));
            if (icall_target == 0x001018D0u && callback_ordinal >= 8u) {
                uint32_t top = *manual_mem32(protect_esi);
                DAH2_TRACE_FPRINTF(stderr,
                        "[SCRIPT-STATE] ordinal=%u state0=%08X state4=%08X state8=%08X "
                        "stateC=%08X state10=%08X state14=%08X state18=%08X state1C=%08X "
                        "v9=%08X/%08X v8=%08X/%08X v7=%08X/%08X v6=%08X/%08X "
                        "v5=%08X/%08X v4=%08X/%08X v3=%08X/%08X v2=%08X/%08X v1=%08X/%08X\n",
                        callback_ordinal,
                        *manual_mem32(protect_esi + 0x00), *manual_mem32(protect_esi + 0x04),
                        *manual_mem32(protect_esi + 0x08), *manual_mem32(protect_esi + 0x0C),
                        *manual_mem32(protect_esi + 0x10), *manual_mem32(protect_esi + 0x14),
                        *manual_mem32(protect_esi + 0x18), *manual_mem32(protect_esi + 0x1C),
                        *manual_mem32(top - 72), *manual_mem32(top - 68),
                        *manual_mem32(top - 64), *manual_mem32(top - 60),
                        *manual_mem32(top - 56), *manual_mem32(top - 52),
                        *manual_mem32(top - 48), *manual_mem32(top - 44),
                        *manual_mem32(top - 40), *manual_mem32(top - 36),
                        *manual_mem32(top - 32), *manual_mem32(top - 28),
                        *manual_mem32(top - 24), *manual_mem32(top - 20),
                        *manual_mem32(top - 16), *manual_mem32(top - 12),
                        *manual_mem32(top - 8), *manual_mem32(top - 4));
                if (callback_ordinal == 9u) {
                    DAH2_TRACE_FPRINTF(stderr,
                            "[SCRIPT-GUEST-STACK] "
                            "w00=%08X w01=%08X w02=%08X w03=%08X w04=%08X w05=%08X w06=%08X w07=%08X "
                            "w08=%08X w09=%08X w10=%08X w11=%08X w12=%08X w13=%08X w14=%08X w15=%08X "
                            "w16=%08X w17=%08X w18=%08X w19=%08X w20=%08X w21=%08X w22=%08X w23=%08X "
                            "w24=%08X w25=%08X w26=%08X w27=%08X w28=%08X w29=%08X w30=%08X w31=%08X\n",
                            *manual_mem32(g_esp+0), *manual_mem32(g_esp+4), *manual_mem32(g_esp+8), *manual_mem32(g_esp+12),
                            *manual_mem32(g_esp+16), *manual_mem32(g_esp+20), *manual_mem32(g_esp+24), *manual_mem32(g_esp+28),
                            *manual_mem32(g_esp+32), *manual_mem32(g_esp+36), *manual_mem32(g_esp+40), *manual_mem32(g_esp+44),
                            *manual_mem32(g_esp+48), *manual_mem32(g_esp+52), *manual_mem32(g_esp+56), *manual_mem32(g_esp+60),
                            *manual_mem32(g_esp+64), *manual_mem32(g_esp+68), *manual_mem32(g_esp+72), *manual_mem32(g_esp+76),
                            *manual_mem32(g_esp+80), *manual_mem32(g_esp+84), *manual_mem32(g_esp+88), *manual_mem32(g_esp+92),
                            *manual_mem32(g_esp+96), *manual_mem32(g_esp+100), *manual_mem32(g_esp+104), *manual_mem32(g_esp+108),
                            *manual_mem32(g_esp+112), *manual_mem32(g_esp+116), *manual_mem32(g_esp+120), *manual_mem32(g_esp+124));
                }
            }
        }
        g_esp -= 4; *manual_mem32(g_esp) = 0x002117FDu;
        recomp_func_t fn = recomp_lookup_manual(icall_target);
        if (!fn) fn = recomp_lookup(icall_target);
        if (fn) fn();
        else { recomp_icall_fail_log(icall_target); g_esp = icall_esp; g_eax = 0; }
        if (icall_target == 0x001018D0u || icall_target == 0x00124DC0u) {
            DAH2_TRACE_FPRINTF(stderr,
                    "[SCRIPT-RETURN] target=%08X ax=%08X cx=%08X dx=%08X "
                    "bx=%08X sp=%08X bp=%08X si=%08X di=%08X top=%08X\n",
                    icall_target, g_eax, g_ecx, g_edx, g_ebx, g_esp,
                    g_ebp, g_esi, g_edi, *manual_mem32(protect_esi));
        }
        /* Force the correct stack delta and fully restore esi/ebx regardless
         * of the callee's actual behaviour -- retail's fixed ABI at this
         * dispatch point guarantees both. */
        g_esp = icall_esp;
        g_esi = protect_esi;
        g_ebx = protect_ebx;
    }

    g_eax = g_eax << 3;
    g_ecx = g_eax;
    g_eax = *manual_mem32(g_esi);
    g_edi = saved_edi;
    *manual_mem32(g_esi + 0x10) = scratch_ebp;
    g_eax = g_eax - g_ecx;
    g_esp += 4;  /* ret: pop caller's pushed return-address literal */
}

/* sub_00161D80 — resource-factory lookup, full replacement via /FORCE:MULTIPLE.
 *
 * The generated version crashes when both factory lookups return the "not found"
 * sentinel 0xA00FA00F: it tries to read MEM32(sentinel+4) = MEM32(0xA00FA013),
 * which is an unmapped Xbox VA → access violation.
 *
 * This happens because the resource at esi has MEM32(esi)==0 (type field zero:
 * uninitialized object freshly allocated but not yet constructed).  Both the
 * hash-by-identity lookup and the fallback hash-by-type lookup return the
 * sentinel, and the code uses the sentinel as a vtable pointer.
 *
 * Two guards added:
 *   1. type == 0  (before first lookup): skip everything, return NULL
 *   2. result2 == sentinel (after second lookup): skip ICALL, return NULL
 *
 * Stack layout on entry (2 params, ret 8 equivalent):
 *   [esp+0]  simulated return addr (pushed by caller via PUSH32)
 *   [esp+4]  arg1 = resource ptr (Xbox VA of resource descriptor)
 *   [esp+8]  arg2 = found_flag_ptr (Xbox VA of BYTE flag)
 *
 * Full success path is preserved so normal resource registration still works. */
extern void sub_00165870(void);
extern void sub_001658F0(void);
extern void sub_001C0B20(void);

void sub_00161D80(void)
{
    /* Prologue: save ecx, ebx, esi */
    g_esp -= 4; *manual_mem32(g_esp) = g_ecx;   /* [esp+0C after edi push] = temp output1 */
    g_esp -= 4; *manual_mem32(g_esp) = g_ebx;
    g_esp -= 4; *manual_mem32(g_esp) = g_esi;
    /* esp = S-12
     *   [esp+0C] = return_addr
     *   [esp+10] = arg1 = resource (also key slot for 1st call; result slot for 2nd)
     *   [esp+14] = arg2 = found_flag_ptr (overwritten with type for 2nd call) */

    g_esi = *manual_mem32(g_esp + 0x10);  /* resource ptr */
    g_ebx = g_ecx;                         /* manager */

    /* NULL check */
    if (g_esi == 0) {
        g_esi = *manual_mem32(g_esp); g_esp += 4;
        g_eax = 0;
        g_ebx = *manual_mem32(g_esp); g_esp += 4;
        g_ecx = *manual_mem32(g_esp); g_esp += 4;
        g_esp += 12;
        return;
    }

    /* GUARD 0: resource pointer outside mapped Xbox memory.
     * Physical-mirror window covers 0x80000000-0x87FFFFFF (128MB).
     * Pointers beyond 0x88000000 are truncated Win32 host addresses that were
     * never placed in the contig region; dereferencing them faults. */
    if (g_esi >= 0x88000000u) {
        uint32_t ffp0 = *manual_mem32(g_esp + 0x14);
        if (ffp0) *((uint8_t *)((uintptr_t)g_xbox_mem_offset + ffp0)) = 0;
        g_esi = *manual_mem32(g_esp); g_esp += 4;
        g_eax = 0;
        g_ebx = *manual_mem32(g_esp); g_esp += 4;
        g_ecx = *manual_mem32(g_esp); g_esp += 4;
        g_esp += 12;
        return;
    }

    /* GUARD 1: type == 0 → resource uninitialized, factory lookup will always fail */
    if (*manual_mem32(g_esi) == 0) {
        uint32_t ffp = *manual_mem32(g_esp + 0x14);
        if (ffp) *((uint8_t *)((uintptr_t)g_xbox_mem_offset + ffp)) = 0;
        g_esi = *manual_mem32(g_esp); g_esp += 4;
        g_eax = 0;
        g_ebx = *manual_mem32(g_esp); g_esp += 4;
        g_ecx = *manual_mem32(g_esp); g_esp += 4;
        g_esp += 12;
        return;
    }

    /* Push edi */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    /* esp = S-16
     *   [esp+00] = saved_edi
     *   [esp+04] = saved_esi
     *   [esp+08] = saved_ebx
     *   [esp+0C] = saved_ecx  ← used as temp result slot for first lookup
     *   [esp+10] = return_addr
     *   [esp+14] = arg1 = resource (key for 1st, result for 2nd)
     *   [esp+18] = arg2 = found_flag_ptr (overwritten with type for 2nd) */
    g_edi = g_ebx + 0x10;  /* hash-by-identity table */

    /* === First lookup: is this resource already in the identity cache? === */
    /* sub_00165870(ecx=hash_table, arg1=&result_slot, arg2=&key_slot)
     * reads key from *arg2, writes result to *arg1 */
    {
        uint32_t key_addr    = g_esp + 0x14;  /* S+4: resource ptr lives here */
        g_esp -= 4; *manual_mem32(g_esp) = key_addr;
        uint32_t result_addr = g_esp + 0x10;  /* S-20+16 = S-4: saved_ecx slot */
        g_esp -= 4; *manual_mem32(g_esp) = result_addr;
        g_ecx = g_edi;
        *manual_mem32(g_esp + 0x1C) = g_esi;  /* refresh key slot */
        g_esp -= 4; *manual_mem32(g_esp) = 0x00161DAEu;
        sub_00165870();   /* ret 8: esp returns to S-16 */
    }

    uint32_t result1 = *manual_mem32(g_esp + 0x0C);  /* result at saved_ecx slot */

    if (result1 != 0xA00FA00Fu) {
        /* Found: bump refcount, return resource object */
        uint32_t ffp = *manual_mem32(g_esp + 0x18);
        *((uint8_t *)((uintptr_t)g_xbox_mem_offset + ffp)) = 1;
        uint32_t node4 = *manual_mem32(result1 + 4);
        *((uint16_t *)((uintptr_t)g_xbox_mem_offset + node4 + 8)) += 1;
        g_eax = *manual_mem32(node4);
        g_edi = *manual_mem32(g_esp); g_esp += 4;
        g_esi = *manual_mem32(g_esp); g_esp += 4;
        g_ebx = *manual_mem32(g_esp); g_esp += 4;
        g_ecx = *manual_mem32(g_esp); g_esp += 4;
        g_esp += 12;
        return;
    }

    /* === Not cached: look up factory by resource type === */
    {
        uint32_t ffp2 = *manual_mem32(g_esp + 0x18);
        *((uint8_t *)((uintptr_t)g_xbox_mem_offset + ffp2)) = 0;  /* found = false */
        uint32_t rtype = *manual_mem32(g_esi);  /* MEM32(resource) = type */

        if (rtype == 0) {
            /* GUARD 2a: type still 0 (shouldn't happen after GUARD 1, but be safe) */
            g_ebx = 0;
        } else {
            *manual_mem32(g_esp + 0x18) = rtype;  /* overwrite arg2 slot with type key */

            /* Second lookup: find factory entry by type */
            {
                uint32_t key_addr2    = g_esp + 0x18;  /* S+8: type key */
                g_esp -= 4; *manual_mem32(g_esp) = key_addr2;
                uint32_t result_addr2 = g_esp + 0x18;  /* S-20+24 = S+4: arg1 slot as result */
                g_esp -= 4; *manual_mem32(g_esp) = result_addr2;
                g_ecx = g_ebx;  /* manager */
                g_esp -= 4; *manual_mem32(g_esp) = 0x00161DF1u;
                sub_00165870();  /* ret 8: esp returns to S-16 */
            }

            uint32_t result2 = *manual_mem32(g_esp + 0x14);  /* [S+4] = factory entry */

            /* GUARD 2b: factory not registered for this type */
            if (result2 == 0xA00FA00Fu) {
                g_ebx = 0;
            } else {
                /* Factory found: call it to create the resource object.
                 * Factory constructors are resolved dynamically by resource
                 * type, and at least one of them does not fully preserve
                 * esi/edi/ebx the way the fixed calling convention requires
                 * (observed corrupting edi here, which then propagates up
                 * through sub_00161E50 into sub_0011C8B0's notify-list walk
                 * and eventually a failed ICALL against VA 0x2AE888, an SEH
                 * scope-table sentinel, in an unbounded per-frame loop).
                 * Save/restore esi/edi/ebx unconditionally around the call
                 * so a misbehaving factory can't leak into the caller. */
                uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
                uint32_t _icall_esp = g_esp;
                uint32_t _icall_target = *manual_mem32(result2 + 4);
                g_esp -= 4; *manual_mem32(g_esp) = 0x00161DF8u;
                recomp_func_t fn = recomp_lookup_manual(_icall_target);
                if (!fn) fn = recomp_lookup(_icall_target);
                if (!fn) fn = recomp_lookup_kernel(_icall_target);
                if (fn) fn();
                else { recomp_icall_fail_log(_icall_target); g_esp = _icall_esp; g_eax = 0; }
                g_esi = protect_esi;
                g_edi = protect_edi;
                g_ebx = protect_ebx;

                g_ebx = g_eax;  /* created object (or 0) */

                if (g_ebx != 0) {
                    /* Link new object into manager's resource list */
                    g_eax = *manual_mem32(g_esi + 4);
                    *manual_mem32(g_ebx + 4) = g_eax;
                    g_eax = *manual_mem32(0x315668);
                    g_edx = *manual_mem32(g_eax);
                    g_ecx = g_eax;
                    g_edx++;
                    *manual_mem32(g_eax) = g_edx;
                    g_eax = *manual_mem32(g_ecx + 0x14);
                    g_edx = *manual_mem32(g_eax);
                    *manual_mem32(g_ecx + 0x14) = g_edx;
                    *manual_mem32(g_eax + 4) = g_esi;
                    *((uint16_t *)((uintptr_t)g_xbox_mem_offset + g_eax + 8)) = 0;
                    *manual_mem32(g_eax) = g_ebx;
                    *((uint16_t *)((uintptr_t)g_xbox_mem_offset + g_eax + 8)) += 1;

                    /* Insert into hash-by-identity table:
                     * sub_001658F0(ecx=edi, arg1=hash_key) → slot index
                     * sub_001C0B20(ecx=edi, arg1=slot, arg2=&out_slot, arg3=node) */
                    uint32_t node = g_eax;
                    g_ecx = *manual_mem32(g_edi);
                    g_esp -= 4; *manual_mem32(g_esp) = node;     /* push node. esp=S-20 */
                    uint32_t out_slot_addr = g_esp + 0x1C;        /* S-20+28 = S+8 */
                    g_ecx = g_ecx & g_esi;                        /* hash_key */
                    g_esp -= 4; *manual_mem32(g_esp) = out_slot_addr;  /* push &out_slot. esp=S-24 */
                    g_esp -= 4; *manual_mem32(g_esp) = g_ecx;         /* push hash_key. esp=S-28 */
                    g_ecx = g_edi;
                    *manual_mem32(g_esp + 0x24) = g_esi;          /* MEM32(S+8) = resource */
                    g_esp -= 4; *manual_mem32(g_esp) = 0x00161E3Du;
                    sub_001658F0();  /* ret 4: esp = S-24 */

                    g_esp -= 4; *manual_mem32(g_esp) = g_eax;     /* push slot result. esp=S-28 */
                    g_ecx = g_edi;
                    g_esp -= 4; *manual_mem32(g_esp) = 0x00161E45u;
                    sub_001C0B20();  /* ret 12: esp = S-16 */
                }
            }
        }
    }

    /* Epilogue (esp = S-16) */
    g_edi = *manual_mem32(g_esp); g_esp += 4;
    g_esi = *manual_mem32(g_esp); g_esp += 4;
    g_eax = g_ebx;
    g_ebx = *manual_mem32(g_esp); g_esp += 4;
    g_ecx = *manual_mem32(g_esp); g_esp += 4;
    g_esp += 12;  /* consume return_addr + 2 args */
}

/* sub_000F96E0 — guard against invalid arg pointer, /FORCE:MULTIPLE replacement.
 *
 * sub_0015FF70 pushes ecx as the argument before calling this function. At
 * certain points during startup ecx holds a small count or return-code value
 * (e.g. 2) rather than a valid Xbox object pointer. The vtable[2] target reads
 * MEM32(arg - 4), which when arg = 2 produces MEM32(0xFFFFFFFE) → AV crash.
 *
 * Fix: skip the ICALL when arg < 0x10000 (below XBOX_BASE_ADDRESS, cannot be
 * a valid game object). When arg is valid, dispatch normally with an esp-save
 * so callee ABI differences do not corrupt the frame.
 *
 * Calling convention: cdecl, ret 0. Stack on entry:
 *   [esp+0]  return address (pushed by caller via PUSH32)
 *   [esp+4]  arg (the ecx pushed by sub_0015FF70 before the call)
 */
extern void sub_00139850(void);

void sub_000F96E0(void)
{
    g_esp -= 4; *manual_mem32(g_esp) = 0x000F96E5u;
    sub_00139850();
    /* eax = MEM32(MEM32(0x2C9640) + 0xFC) = subsystem manager singleton */

    uint32_t arg = *manual_mem32(g_esp + 4);

    if (arg < 0x10000u) {
        static unsigned s_f96e0_guard;
        if (++s_f96e0_guard <= 8)
            DAH2_TRACE_FPRINTF(stderr,
                "[F96E0-GUARD] skipped vtable[2] call: bad arg=0x%08X eax=0x%08X (#%u)\n",
                arg, g_eax, s_f96e0_guard);
        g_esp += 4;  /* ret 0: pop sub_000F96E0's return address */
        return;
    }

    uint32_t vtbl   = *manual_mem32(g_eax);
    uint32_t target = *manual_mem32(vtbl + 8);  /* vtable[2] at offset 8 */

    uint32_t saved_esp = g_esp;
    g_esp -= 4; *manual_mem32(g_esp) = arg;
    g_ecx = g_eax;
    g_esp -= 4; *manual_mem32(g_esp) = 0x000F96F1u;

    if (target >= 0x00400000u && target < 0xFE000000u) {
        recomp_func_t fn = recomp_lookup_manual(target);
        if (!fn) fn = recomp_lookup(target);
        if (fn) fn();
    }
    g_esp = saved_esp;  /* restore: callee ABI (ret 0 vs ret 4) varies */
    g_esp += 4;         /* ret 0: pop sub_000F96E0's return address */
}

/* TEMP: sub_0015FF70 (per-resource loader, reached only via ICALL -- no
 * direct-name callers found) does six unconditional factory lookups; three
 * of them (see the "Factory-miss key trace" note in
 * diagnostics/menu_recovery_2026-09-20.md) return node==0 because their key
 * fields read as 0, yet retail never null-checks there -- meaning on real
 * hardware those keys are never 0. Tracing entry here to see how many times
 * this loader actually runs per boot and whether its descriptor pointer
 * (the single stack arg) is sane across calls, before deciding whether the
 * bug is inside this function or in whatever populates/passes the
 * descriptor. Pure trace: does not alter behavior. */
extern void sub_0015FF70(void);
static void traced_sub_0015FF70(void)
{
    static volatile long s_call_count;
    uint32_t desc = *manual_mem32(g_esp + 4);
    uint32_t manager = g_ecx;
    long n = InterlockedIncrement(&s_call_count);
    if (n <= 24) {
        DAH2_TRACE_FPRINTF(stderr, "[RESOURCE-LOAD] tid=%lu call #%ld desc=%08X ecx=%08X esp=%08X retsite=%08X\n",
                (unsigned long)GetCurrentThreadId(), n, desc, g_ecx, g_esp, *manual_mem32(g_esp));
        DAH2_TRACE_FPRINTF(stderr, "  desc[0..9]=%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
                *manual_mem32(desc+0), *manual_mem32(desc+4), *manual_mem32(desc+8),
                *manual_mem32(desc+0xC), *manual_mem32(desc+0x10), *manual_mem32(desc+0x14),
                *manual_mem32(desc+0x18), *manual_mem32(desc+0x1C), *manual_mem32(desc+0x20),
                *manual_mem32(desc+0x24));
        if (g_esp >= 0x10000u && g_esp < 0x04000000u) {
            DAH2_TRACE_FPRINTF(stderr, "  stack[0..7]=%08X %08X %08X %08X %08X %08X %08X %08X\n",
                    *manual_mem32(g_esp+0), *manual_mem32(g_esp+4), *manual_mem32(g_esp+8),
                    *manual_mem32(g_esp+0xC), *manual_mem32(g_esp+0x10), *manual_mem32(g_esp+0x14),
                    *manual_mem32(g_esp+0x18), *manual_mem32(g_esp+0x1C));
        }
    }
    sub_0015FF70();
    if (n <= 24) {
        uint32_t root = *manual_mem32(manager + 8);
        uint32_t child = root ? *manual_mem32(root + 0x0C) : 0;
        uint32_t grid = *manual_mem32(manager + 0x44);
        DAH2_TRACE_FPRINTF(stderr,
                "[RESOURCE-LOAD] return #%ld manager=%08X root=%08X child=%08X grid=%08X dims=%u,%u\n",
                n, manager, root, child, grid,
                grid ? *manual_mem32(grid + 8) : 0,
                grid ? *manual_mem32(grid + 0x0C) : 0);
        for (unsigned i = 0; child && i < 16; ++i) {
            DAH2_TRACE_FPRINTF(stderr,
                    "  scene-child[%u]=%08X parent=%08X child=%08X sibling=%08X payload=%08X\n",
                    i, child, *manual_mem32(child + 8), *manual_mem32(child + 0x0C),
                    *manual_mem32(child + 0x40), *manual_mem32(child + 0xE8));
            child = *manual_mem32(child + 0x40);
        }
    }
}

/* TEMP: sub_001602D0 is a tiny vtable method (`MEM32(ecx+0x30) &= ~0x20;
 * ret;`) that a crash's native RVA resolved close to (see "Reliable crash
 * symbolication" note in diagnostics/menu_recovery_2026-09-20.md), but the
 * crash dump's own register snapshot didn't cleanly confirm this is really
 * the faulting call (ecx didn't match the fault math). Tracing entry here
 * to get ecx's ACTUAL value at call time, not a post-hoc VEH snapshot that
 * may be stale. Pure trace: does not alter behavior. */
extern void sub_001602D0(void);
static void traced_sub_001602D0(void)
{
    static unsigned s_call_count;
    if (++s_call_count <= 32)
        DAH2_TRACE_FPRINTF(stderr, "[VT-0x30-CLEAR] call #%u ecx=%08X esp=%08X\n",
                s_call_count, g_ecx, g_esp);
    sub_001602D0();
}

/* TEMP: sub_0015D130 is the vtable+4 callee sub_00161E50 dispatches to on a
 * successful factory lookup (thiscall/1 stack-arg "descriptor"; populates
 * esi+0xE8 -- the exact field sub_0015FF70's block 5 crash dereferences --
 * via ITS OWN sub_00161E50 lookup at descriptor+0x14, and also forwards the
 * same descriptor into sub_001603D0). Tracing entry/exit to find where this
 * descriptor originates and what actually lands in esi+0xE8. Pure trace:
 * does not alter behavior. */
extern void sub_0015D130(void);
static void traced_sub_0015D130(void)
{
    static volatile long s_call_count;
    unsigned n = (unsigned)InterlockedIncrement(&s_call_count);
    uint32_t desc = *manual_mem32(g_esp + 4);
    uint32_t this_obj = g_ecx;
    DWORD tid = GetCurrentThreadId();
    if (n <= 24)
        DAH2_TRACE_FPRINTF(stderr, "[SUBOBJ-0130] tid=%lu call #%u this=%08X desc=%08X desc[0x14]=%08X desc[0x18]=%08X\n",
                (unsigned long)tid, n, this_obj, desc, *manual_mem32(desc+0x14), *manual_mem32(desc+0x18));
    sub_0015D130();
    uint32_t populated_subobj = *manual_mem32(this_obj+0xE8);
    if (n <= 24)
        DAH2_TRACE_FPRINTF(stderr, "[SUBOBJ-0130] tid=%lu call #%u returned eax=%08X this[0xE8]=%08X\n",
                (unsigned long)tid, n, g_eax, populated_subobj);
    /* TEMP: arm the ICALL "this"-pointer watch (see recomp_types.h) on the
     * first successfully populated sub-object, to catch the vtable+0x1C
     * target that sub_0015FF70's blocks 1-5 repeatedly dispatch to on it. */
    if (populated_subobj != 0 && g_icall_watch_this == 0) {
        g_icall_watch_this = populated_subobj;
        g_icall_watch_this2 = this_obj;  /* the "node" itself, for the inner nested dispatch */
    }
}

/* TEMP: sub_00132D40 is the per-node callback in sub_0012B710's (state
 * 2->3 menu/UI transition) internal linked-list walk over object+0xC8 --
 * see the "New frontier: frame presentation stalls after ~8 frames" note
 * in diagnostics/menu_recovery_2026-09-20.md. Counting invocations to
 * determine whether that list is abnormally large/cyclic (this function is
 * called once per node) vs. genuinely small -- distinguishes "slow but
 * finite" from "corrupted/infinite list" without needing to fully
 * replace the more complex sub_0012B5A0/sub_0012B710 themselves. Full
 * replacement via /FORCE:MULTIPLE since it's called by name; body is a
 * verbatim, low-risk transplant of the original (7 instructions, no
 * calls) with a counter added. */
static volatile long g_node_walk_count_132D40;
void sub_00132D40(void)
{
    long n = InterlockedIncrement(&g_node_walk_count_132D40);
    if (n <= 20 || (n % 1000) == 0)
        DAH2_TRACE_FPRINTF(stderr, "[NODE-WALK-132D40] count=%ld ecx=0x%08X\n", n, g_ecx);
    g_eax = 1;
    *(volatile uint16_t *)manual_mem8(g_ecx + 0xC0) = 1;
    *(volatile uint16_t *)manual_mem8(g_ecx + 0xBE) = 1;
    *(volatile uint16_t *)manual_mem8(g_ecx + 0xBC) = 1;
    *(volatile uint16_t *)manual_mem8(g_ecx + 0xC2) = 0;
    *manual_mem32(g_ecx + 0xC8) = *manual_mem32(g_ecx + 0xC8) & 0xFFFFFFFBu;
    g_esp += 4;  /* ret 0 */
}

/* TEMP: sub_00132CD0 is the ACTUAL per-node callback in sub_0012B5A0's
 * (state 1->2) list walk over object+0xC8 -- the loop actually reached
 * (sub_0012B710/sub_00132D40 above turned out to never run at all: state
 * never advances past 1). See the "Correction: the thread explosion is a
 * benign NVIDIA driver side effect" note in
 * diagnostics/menu_recovery_2026-09-20.md.
 *
 * Full replacement via /FORCE:MULTIPLE (called by name). Two internal
 * ICALLs (retail 0x132D08 vtable+0x88, and 0x132D2E vtable+8), both
 * hardened with esi/edi/ebx save-restore around them -- same defensive
 * pattern as every other override this session, and directly relevant
 * here since a misbehaving callee corrupting `edi` (the list "next"
 * pointer in the caller, sub_0012B5A0) would be indistinguishable from a
 * genuinely cyclic list without this protection.
 *
 * The two calls share one transient stack-local "event" object built by
 * sub_00115E40 (sets local[0]=vtable 0x2AFD20, local[4]=0xBEEFED9E), whose
 * `local+4` field is then verified-per-retail-disassembly to be
 * overwritten to 0x2AFD20 again (a second, unrelated temporary reusing the
 * same scratch slot -- retail writes through the just-pushed pointer
 * before the call executes) and passed by address to the second ICALL.
 * Replicated faithfully via a locally-owned scratch dword rather than
 * retail's exact stack byte offsets, since nothing else reads this
 * transient value by a hardcoded address. */
extern void sub_00115E40(void);
static volatile long g_node_walk_count_132CD0;
void sub_00132CD0(void)
{
    uint32_t arg = *manual_mem32(g_esp + 4);  /* single cdecl stack arg */
    uint32_t obj = g_ecx;                      /* retail: esi = ecx */

    long n = InterlockedIncrement(&g_node_walk_count_132CD0);
    if (n <= 20 || (n % 1000) == 0)
        DAH2_TRACE_FPRINTF(stderr, "[NODE-WALK-132CD0] count=%ld obj=0x%08X arg=0x%08X\n", n, obj, arg);

    *(volatile uint16_t *)manual_mem8(obj + 0xC0) = 1;
    *(volatile uint16_t *)manual_mem8(obj + 0xBE) = 1;
    *(volatile uint16_t *)manual_mem8(obj + 0xBC) = 1;
    *(volatile uint16_t *)manual_mem8(obj + 0xC2) = 0;
    *manual_mem32(obj + 0xC8) = *manual_mem32(obj + 0xC8) | 4;
    *manual_mem32(obj + 0xC4) = arg;

    /* First ICALL: obj's own vtable+0x88, arg2=0 */
    {
        uint32_t vtbl = *manual_mem32(obj);
        uint32_t target = *manual_mem32(vtbl + 0x88);
        if (target) {
            uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
            uint32_t call_esp = g_esp;
            g_esp -= 4; *manual_mem32(g_esp) = 0;              /* arg2 */
            g_ecx = obj;                                        /* this */
            g_esp -= 4; *manual_mem32(g_esp) = 0x00132D14u;    /* fake retaddr */
            recomp_func_t fn = recomp_lookup_manual(target);
            if (!fn) fn = recomp_lookup(target);
            if (fn) fn();
            else recomp_icall_fail_log(target);
            g_esp = call_esp;
            g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
        }
    }

    /* Transient local "event" object (8 bytes: local_evt[0] and
     * local_evt+4, both written by sub_00115E40 -- matches retail's own
     * 8-byte prologue allocation for this exact purpose), then second
     * ICALL on obj's own vtable+8, passing &local by address. */
    g_esp -= 8;
    uint32_t local_evt = g_esp;
    g_ecx = local_evt;
    g_esp -= 4; *manual_mem32(g_esp) = 0xBEEFED9Eu;
    g_esp -= 4; *manual_mem32(g_esp) = 0x00132D22u;
    sub_00115E40();  /* ret 4: sets local_evt=0x2AFD20, local_evt+4=0xBEEFED9E; restores g_esp to local_evt */
    /* retail passes &(local_evt+4) as the 2nd call's arg, then overwrites
     * that exact slot to 0x2AFD20 (replacing the "type" tag written above)
     * before the call executes -- reusing the same scratch dword for a
     * second, unrelated temporary value. */
    *manual_mem32(local_evt + 4) = 0x2AFD20u;

    {
        uint32_t vtbl = *manual_mem32(obj);
        uint32_t target = *manual_mem32(vtbl + 8);
        if (target) {
            uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
            uint32_t call_esp = g_esp;
            g_esp -= 4; *manual_mem32(g_esp) = local_evt + 4; /* arg: &local+4 */
            g_ecx = obj;                                        /* this */
            g_esp -= 4; *manual_mem32(g_esp) = 0x00132D36u;
            recomp_func_t fn = recomp_lookup_manual(target);
            if (!fn) fn = recomp_lookup(target);
            if (fn) fn();
            else recomp_icall_fail_log(target);
            g_esp = call_esp;
            g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
        }
    }
    g_esp += 8;  /* release local_evt scratch slot (8 bytes) */

    g_esp += 8;  /* ret 4: retaddr(4) + caller's single stack arg(4) */
}

/* TEMP: sub_00012820 is the per-node callback in sub_000C4C80's walk over
 * the GLOBAL list at guest VA 0x2F1F84 -- a DIFFERENT, outer list from the
 * per-instance object+0xC8 one sub_00132CD0 belongs to. sub_0012B5A0
 * (proven stuck via RVA sampling) is reached through a tail-call chain
 * from this outer walk's per-node dispatch, so counting THIS function's
 * invocations answers whether the outer list is what's driving the stall
 * (huge/cyclic) rather than the inner one (which sub_00132CD0 already
 * showed gets zero hits). See "the thread explosion is a benign NVIDIA
 * driver side effect" / node-walk notes in
 * diagnostics/menu_recovery_2026-09-20.md.
 *
 * Full replacement via /FORCE:MULTIPLE (called by name). This function's
 * own logic (one bounded, fixed 4-step field check/ICALL, no loop of its
 * own) is transcribed VERBATIM from the generated body -- not simplified
 * -- specifically to avoid another stack-math mistake like this session's
 * earlier sub_00161E50 slip: it is part of a multi-function TAIL-CALL
 * chain (ends by calling sub_0001283E without popping its own three
 * pushed registers first, matching retail's shared-prologue tail-call
 * pattern), so the exact PUSH32 sequence and unconsumed stack state going
 * into that final call must match retail exactly, or every function
 * further down the chain (which are all untouched, real generated code)
 * would desync. Only the counter/print at the very top is new. */
extern void sub_0001283E(void);
extern __declspec(thread) uint32_t g_seh_ebp;
static volatile long g_node_walk_count_12820;
void sub_00012820(void)
{
    /* ebp is NOT a persistent global in this runtime model (see recomp_
     * types.h's "Register model" note) -- every generated frameless
     * function's `ebp = g_ebp;` line is dead code immediately overwritten
     * by `ebp = g_seh_ebp;`. Only g_seh_ebp carries state across this
     * tail-call chain; ebp itself is a plain local here, matching retail. */
    uint32_t ebp = g_seh_ebp;

    long n = InterlockedIncrement(&g_node_walk_count_12820);
    if (n <= 20 || (n % 1000) == 0)
        DAH2_TRACE_FPRINTF(stderr, "[NODE-WALK-12820] count=%ld ecx=0x%08X\n", n, g_ecx);

    g_esp -= 4; *manual_mem32(g_esp) = ebp;     /* PUSH32(esp, ebp) */
    g_esp -= 4; *manual_mem32(g_esp) = g_esi;   /* PUSH32(esp, esi) */
    g_esi = g_ecx;
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;   /* PUSH32(esp, edi) */
    g_edi = g_esi + 0x48;
    ebp = 4;
    g_ecx = *manual_mem32(g_edi);
    if (g_ecx != 0) {
        g_eax = *manual_mem32(g_ecx);
        uint32_t target = *manual_mem32(g_eax + 0x5C);
        if (target) {
            uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
            uint32_t call_esp = g_esp;
            g_esp -= 4; *manual_mem32(g_esp) = 0x0001283Bu;  /* fake retaddr */
            recomp_func_t fn = recomp_lookup_manual(target);
            if (!fn) fn = recomp_lookup(target);
            if (fn) fn();
            else recomp_icall_fail_log(target);
            g_esp = call_esp;
            g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
        }
    }
    g_edi = g_edi + 4;

    /* Tail-call chain continuation: sub_0001283E expects ebp/esi/edi
     * already pushed above (unconsumed) and g_seh_ebp=4 (the iteration
     * counter), exactly as retail leaves it. No retaddr push here --
     * matches retail's real tail-call semantics (reuses the return
     * address already on the stack from sub_00012820's own caller). */
    g_seh_ebp = ebp;
    sub_0001283E();
}

/* TEMP: sub_00012820's own outer-list walk (sub_000C4C80) got zero hits
 * too -- meaning it, and thus its tail-called sub_0012B5A0, must be being
 * invoked repeatedly by something even further up the call chain.
 * sub_000C4C80 has no direct-name callers (ICALL-dispatched only, unlike
 * the two functions above), so a lightweight recomp_lookup_manual trace
 * wrapper suffices here -- no risky full-body transplant needed. Pure
 * trace: does not alter behavior. */
extern void sub_000C4C80(void);
static volatile long g_call_count_C4C80;
static void traced_sub_000C4C80(void)
{
    long n = InterlockedIncrement(&g_call_count_C4C80);
    if (n <= 20 || (n % 1000) == 0)
        DAH2_TRACE_FPRINTF(stderr, "[CALL-C4C80] count=%ld ecx=0x%08X retaddr=0x%08X\n",
                n, g_ecx, *manual_mem32(g_esp));
    sub_000C4C80();
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_0012B5A0 itself. RVA
 * sampling (now trustworthy with /OPT:NOICF) proves a thread spins
 * continuously inside this exact function's compiled range for 10+
 * seconds right after Present() stops at frame 45 and shell.dir finishes
 * parsing -- yet sub_00132CD0 (this function's OWN internal node-walk
 * callback, called only when entry state==1) shows ZERO hits in that same
 * window. That means the tight loop IS the early-exit path: entry check
 * `MEM32(ecx+0x128) != 1` is true every single call, so the function does
 * nothing but pop/return, over and over, at whatever polling rate its
 * (not yet identified) caller uses. This transplant is a byte-for-byte
 * transcription of the generated body (verified against
 * src/recomp/gen/recomp_0007.c:80691-80844) with one addition: a
 * throttled log of the entry object pointer + entry state value, to
 * confirm what state is actually stuck at and whether it's always the
 * same object. Reachable both by name (tail-called from
 * src/recomp/gen/recomp_0005.c:2005) and via ICALL/vtable dispatch
 * (recomp_dispatch.c's table entry resolves here too under
 * /FORCE:MULTIPLE), so redefining the symbol outright (rather than a
 * lookup-only trace) is required to see every call site. Pure
 * instrumentation -- logic is unchanged from retail/generated. */
extern void sub_00160940(void);
extern void sub_00122E50(void);
extern void sub_0012B1C0(void);
extern void sub_001AF050(void);
extern void sub_001AF120(void);
extern void sub_0015E260(void);
extern void sub_0013B3A0(void);
extern void sub_001AC600(void);
static volatile long g_call_count_B5A0;
void sub_0012B5A0(void)
{
    uint32_t ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame (ebp is not a persistent global) */

    g_esp -= 0x10;
    g_esp -= 4; *manual_mem32(g_esp) = g_esi;   /* PUSH32(esp, esi) */
    g_esi = g_ecx;

    {
        uint32_t state = *manual_mem32(g_esi + 0x128);
        long n = InterlockedIncrement(&g_call_count_B5A0);
        if (n <= 30 || (n % 500) == 0)
            DAH2_TRACE_FPRINTF(stderr, "[CALL-B5A0] count=%ld obj=0x%08X state=0x%08X\n", n, g_esi, state);
        if (state != 1) goto ret_early;
    }

    /* loc_0012B5B3 */
    g_eax = *manual_mem32(0x2CA6A0);
    g_ecx = *manual_mem32(g_eax + 0xEC);
    g_edx = *manual_mem32(g_ecx + 0x24);
    g_eax = *manual_mem32(g_edx + 0xE8);
    g_esp -= 4; *manual_mem32(g_esp) = g_ebx;   /* PUSH32(esp, ebx) */
    g_esp -= 4; *manual_mem32(g_esp) = ebp;     /* PUSH32(esp, ebp) */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;   /* PUSH32(esp, edi) */
    g_esp -= 4; *manual_mem32(g_esp) = g_eax;   /* PUSH32(esp, eax) */
    g_ecx = g_esi + 4;
    g_esp -= 4; *manual_mem32(g_esp) = 0x0012B5D3u;
    sub_00160940();

    /* loc_0012B5D3 */
    g_ecx = g_esp + 0x14;
    *(volatile uint8_t *)manual_mem8(g_esi + 0xB8) = 1;
    g_esp -= 4; *manual_mem32(g_esp) = g_ecx;   /* PUSH32(esp, ecx) */
    g_ecx = *manual_mem32(0x30FE00);
    ebp = 2;
    *manual_mem32(g_esp + 0x1C) = 4;
    *manual_mem32(g_esp + 0x18) = 0x2B0F14;
    *manual_mem32(g_esp + 0x20) = ebp;
    g_esp -= 4; *manual_mem32(g_esp) = 0x0012B603u;
    sub_00122E50();

    /* loc_0012B603 */
    g_esp -= 4; *manual_mem32(g_esp) = 0x2B0F1C;
    g_ecx = g_esi;
    *manual_mem32(g_esi + 0x120) = 0;
    *manual_mem32(g_esi + 0x128) = ebp;
    g_esp -= 4; *manual_mem32(g_esp) = 0x0012B61Fu;
    sub_0012B1C0();

    /* loc_0012B61F */
    if (g_eax != 0) {
        /* loc_0012B623 */
        g_edx = *manual_mem32(0x30FE20);
        g_ecx = *manual_mem32(g_edx + 4);
        g_esp -= 4; *manual_mem32(g_esp) = 0;
        g_esp -= 4; *manual_mem32(g_esp) = g_eax;
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B634u;
        sub_001AF050();

        /* loc_0012B634 */
        g_eax = *manual_mem32(0x30FE20);
        g_ecx = *manual_mem32(g_eax + 4);
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B641u;
        sub_001AF120();
    }

    /* loc_0012B641 */
    g_edi = *manual_mem32(g_esi + 0xC8);
    g_ebx = g_esi + 0xC8;
    if (g_edi != g_ebx) {
        do {
            /* loc_0012B651 */
            g_ecx = *manual_mem32(0x30FDE4);
            g_edx = *manual_mem32(g_ecx + 0x3050);
            g_eax = *manual_mem32(g_edx);
            ebp = *manual_mem32(g_edi + 8);
            g_edx = *manual_mem32(ebp + 0x28);
            g_ecx = *manual_mem32(g_eax + 8);
            g_edx = *manual_mem32(g_edx);
            g_eax = *manual_mem32(g_ecx);
            {
                uint32_t _icall_esp = g_esp;
                g_esp -= 4; *manual_mem32(g_esp) = 0;
                g_esp -= 4; *manual_mem32(g_esp) = g_edx;
                uint32_t _icall_target = *manual_mem32(g_eax + 0x10);
                g_esp -= 4; *manual_mem32(g_esp) = 0x0012B672u;
                if (_icall_target >= 0x00400000 && _icall_target < 0xFE000000) {
                    g_esp = _icall_esp; g_eax = 0;
                } else {
                    uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
                    recomp_func_t fn = recomp_lookup_manual(_icall_target);
                    if (!fn) fn = recomp_lookup(_icall_target);
                    if (!fn) fn = recomp_lookup_kernel(_icall_target);
                    if (fn) fn();
                    else { recomp_icall_fail_log(_icall_target); g_esp = _icall_esp; g_eax = 0; }
                    g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
                }
            }

            /* loc_0012B672 */
            g_esp -= 4; *manual_mem32(g_esp) = 0;
            g_ecx = ebp;
            g_esp -= 4; *manual_mem32(g_esp) = 0x0012B67Bu;
            sub_00132CD0();

            /* loc_0012B67B */
            g_edi = *manual_mem32(g_edi);
        } while (g_edi != g_ebx);

        /* loc_0012B681 */
        ebp = 2;
    }

    /* loc_0012B686 */
    g_eax = *manual_mem32(0x30FDE4);
    *(volatile uint8_t *)manual_mem8(g_eax + 0x303D) = 1;
    g_edi = *manual_mem32(g_esi + 0x124);
    g_edi = g_edi | ebp;
    *manual_mem32(g_esi + 0x124) = g_edi;
    g_ecx = *manual_mem32(0x2CA6A0);
    g_edx = *manual_mem32(g_ecx + 0x1F0);
    g_eax = g_edi;
    g_edi = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, edi) */
    ebp   = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, ebp) */
    g_ebx = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, ebx) */

    if (g_edx != 0) {
        /* loc_0012B6D4 */
        g_eax = g_eax & 0xFFFFFFFBu;
    } else {
        /* loc_0012B6B5 */
        g_esp -= 4; *manual_mem32(g_esp) = 1;
        g_edx = g_esp + 8;
        g_esp -= 4; *manual_mem32(g_esp) = g_edx;
        *manual_mem32(g_esp + 0xC) = 0;
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B6C9u;
        sub_0015E260();

        g_eax = *manual_mem32(g_esi + 0x124);
        g_eax = g_eax | 4;
    }

    /* loc_0012B6D7 */
    g_ecx = g_esi + 0xDC;
    g_edx = 0;
    *manual_mem32(g_esi + 0x124) = g_eax;
    g_esp -= 4; *manual_mem32(g_esp) = 0x0012B6EAu;
    sub_0013B3A0();

    /* loc_0012B6EA */
    if (g_eax == 0xCE96FF83u) {
        /* loc_0012B6F1 */
        *manual_mem32(g_esi + 0x124) = *manual_mem32(g_esi + 0x124) | 0x10;
        g_ecx = *manual_mem32(0x31FF18);
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B703u;
        sub_001AC600();
    }

ret_early:
    /* loc_0012B703 */
    g_esi = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, esi) */
    g_esp = g_esp + 0x10;
    g_esp += 4; return; /* ret */
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_0012B710, sub_0012B5A0's
 * sibling (state 2->3 transition). After redefining sub_0012B5A0 above and
 * rebuilding, the linker relocated the whole binary and live RVA sampling
 * (map file re-derived fresh, /OPT:NOICF still in effect) now resolves the
 * still-spinning thread to THIS function's range instead -- while
 * sub_0012B5A0's own trace shows zero calls, and this function's OWN
 * per-node callback (sub_00132D40, already instrumented above) also shows
 * zero calls, meaning if it's really being invoked it must be taking its
 * own early-exit path (entry state==3) or hitting an empty object+0xC8
 * list. Same rationale as sub_0012B5A0: redefine outright (by-name AND
 * ICALL reachable) with a throttled entry log, byte-for-byte transcribed
 * from src/recomp/gen/recomp_0007.c:80853-81021. Pure instrumentation. */
extern void sub_00121C20(void);
extern void sub_001AC5C0(void);
static volatile long g_call_count_B710;
void sub_0012B710(void)
{
    uint32_t ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame */

    g_esp -= 0x10;
    g_esp -= 4; *manual_mem32(g_esp) = g_esi;   /* PUSH32(esp, esi) */
    g_esi = g_ecx;
    g_eax = *manual_mem32(g_esi + 0x128);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;   /* PUSH32(esp, edi) */
    g_edi = 3;

    {
        long n = InterlockedIncrement(&g_call_count_B710);
        if (n <= 30 || (n % 500) == 0)
            DAH2_TRACE_FPRINTF(stderr, "[CALL-B710] count=%ld obj=0x%08X state=0x%08X\n", n, g_esi, g_eax);
    }

    if (g_eax == g_edi) goto ret_early_b710; /* state == 3: nothing to do */

    /* loc_0012B72A */
    g_ecx = *manual_mem32(0x30FE00);
    g_esp -= 4; *manual_mem32(g_esp) = ebp;      /* PUSH32(esp, ebp) */
    g_eax = g_esp + 0x10;
    g_esp -= 4; *manual_mem32(g_esp) = g_eax;    /* PUSH32(esp, eax) */
    *manual_mem32(g_esp + 0x18) = 4;
    *manual_mem32(g_esp + 0x14) = 0x2B0F14;
    *manual_mem32(g_esp + 0x1C) = 5;
    g_esp -= 4; *manual_mem32(g_esp) = 0x0012B753u;
    sub_00122E50();

    /* loc_0012B753 */
    ebp = g_esi + 0xC8;
    *manual_mem32(g_esi + 0x128) = g_edi;   /* state = 3 */
    g_edi = *manual_mem32(ebp);
    if (g_edi != ebp) {
        do {
            /* loc_0012B766 */
            g_ecx = *manual_mem32(g_edi + 8);
            g_esp -= 4; *manual_mem32(g_esp) = 0x0012B76Eu;
            sub_00132D40();

            /* loc_0012B76E */
            g_edi = *manual_mem32(g_edi);
        } while (g_edi != ebp);
    }

    /* loc_0012B774 */
    g_esp -= 4; *manual_mem32(g_esp) = 0x2B0F24;
    g_ecx = g_esi;
    g_esp -= 4; *manual_mem32(g_esp) = 0x0012B780u;
    sub_0012B1C0();

    /* loc_0012B780 */
    if (g_eax != 0) {
        /* loc_0012B784 */
        g_ecx = *manual_mem32(0x30FE20);
        g_ecx = *manual_mem32(g_ecx + 4);
        g_esp -= 4; *manual_mem32(g_esp) = 0;
        g_esp -= 4; *manual_mem32(g_esp) = g_eax;
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B795u;
        sub_001AF050();

        /* loc_0012B795 */
        g_edx = *manual_mem32(0x30FE20);
        g_ecx = *manual_mem32(g_edx + 4);
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B7A3u;
        sub_001AF120();
    }

    /* loc_0012B7A3 */
    g_edi = g_esi + 0x12C;
    ebp = 0xA;

    /* loc_0012B7B0: fixed 10-iteration loop */
    do {
        g_eax = *manual_mem32(g_edi + 4);
        if (g_eax != 0) {
            /* loc_0012B7B7 */
            g_eax = *manual_mem32(g_edi);
            g_ecx = g_edi;
            {
                uint32_t _icall_esp = g_esp;
                uint32_t _icall_target = *manual_mem32(g_eax + 0x10);
                g_esp -= 4; *manual_mem32(g_esp) = 0x0012B7BEu;
                if (_icall_target >= 0x00400000 && _icall_target < 0xFE000000) {
                    g_esp = _icall_esp; g_eax = 0;
                } else {
                    uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
                    recomp_func_t fn = recomp_lookup_manual(_icall_target);
                    if (!fn) fn = recomp_lookup(_icall_target);
                    if (!fn) fn = recomp_lookup_kernel(_icall_target);
                    if (fn) fn();
                    else { recomp_icall_fail_log(_icall_target); g_esp = _icall_esp; g_eax = 0; }
                    g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
                }
            }
        }
        /* loc_0012B7BE */
        g_edi = g_edi + 0xC;
        ebp--;
    } while (ebp != 0);

    /* loc_0012B7C4 */
    {
        uint8_t flagbyte = *(volatile uint8_t *)manual_mem8(g_esi + 0x124);
        ebp = *manual_mem32(g_esp); g_esp += 4;  /* POP32(esp, ebp) */
        if ((flagbyte & 1) != 0) {
            /* loc_0012B7CE */
            g_ecx = *manual_mem32(0x30FDF8);
            g_esp -= 4; *manual_mem32(g_esp) = 0x0012B7D9u;
            sub_00121C20();

            /* loc_0012B7D9 */
            *manual_mem32(g_esi + 0x124) = *manual_mem32(g_esi + 0x124) & 0xFFFFFFFEu;
        }
    }

    /* loc_0012B7E0 */
    if ((*(volatile uint8_t *)manual_mem8(g_esi + 0x124) & 2) != 0) {
        /* loc_0012B7E9 */
        g_ecx = *manual_mem32(0x30FDE4);
        *(volatile uint8_t *)manual_mem8(g_ecx + 0x303D) = 0;
    }

    /* loc_0012B7F6 */
    if ((*(volatile uint8_t *)manual_mem8(g_esi + 0x124) & 4) != 0) {
        /* loc_0012B7FF */
        g_ecx = *manual_mem32(0x2CA6A0);
        g_esp -= 4; *manual_mem32(g_esp) = 0;
        g_edx = g_esp + 0xC;
        g_esp -= 4; *manual_mem32(g_esp) = g_edx;
        *manual_mem32(g_esp + 0x10) = 0;
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B819u;
        sub_0015E260();

        /* loc_0012B819 */
        *manual_mem32(g_esi + 0x124) = *manual_mem32(g_esi + 0x124) & 0xFFFFFFFBu;
    }

    /* loc_0012B820 */
    if ((*(volatile uint8_t *)manual_mem8(g_esi + 0xB8)) != 0) {
        /* loc_0012B82A */
        g_ecx = *manual_mem32(0x2CA6A0);
        g_edx = *manual_mem32(g_ecx + 0xEC);
        g_eax = g_esi + 4;
        g_esp -= 4; *manual_mem32(g_esp) = g_eax;
        g_eax = *manual_mem32(g_edx + 0x24);
        g_ecx = *manual_mem32(g_eax + 0xE8);
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B848u;
        sub_00160940();

        /* loc_0012B848 */
        *(volatile uint8_t *)manual_mem8(g_esi + 0xB8) = 0;
    }

    /* loc_0012B84F */
    if ((*(volatile uint8_t *)manual_mem8(g_esi + 0x124) & 0x10) != 0) {
        /* loc_0012B858 */
        g_ecx = *manual_mem32(0x31FF18);
        g_esp -= 4; *manual_mem32(g_esp) = 0x0012B863u;
        sub_001AC5C0();
    }

    /* loc_0012B863 */
    *manual_mem32(g_esi + 0x124) = *manual_mem32(g_esi + 0x124) & 0xFFFFFFEFu;

ret_early_b710:
    /* loc_0012B86A */
    g_edi = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, edi) */
    g_esi = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, esi) */
    g_esp = g_esp + 0x10;
    g_esp += 4; return; /* ret */
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_000F7C50, with every
 * by-name call it makes bracketed by enter/return prints. Chased here via
 * the [CALL-F2720] trace (sub_000F2720, itself confirmed to return
 * cleanly with an empty loop): its caller sub_00115520 also returns
 * cleanly (calls only the trivial one-instruction sub_000310E0 after the
 * ICALL), and sub_00115520's own caller is THIS function, at retaddr
 * 0x000F7CA8 (src/recomp/gen/recomp_0006.c:45016). After that point
 * sub_000F7C50 branches on MEM8(esi+0x303C): nonzero takes a short path
 * (loc_000F7CB2) but zero -- the expected case on this, the very first
 * pass, since [CALL-F2720] has only ever logged count=1 -- takes the
 * "first-time setup" path at loc_000F7CF1, sequentially by-name-calling 9
 * subsystem-init functions, then both branches converge at loc_000F7D5C
 * for 9 more calls. No further [CALL-ABI]/[LIST-*]/[EVENT-BUFFER] log
 * lines and no ICALL-total growth appear anywhere after [CALL-F2720]
 * RETURNED in probe captures, meaning the hang is a genuine native loop
 * inside one of these ~18 calls (not reachable via any dynamic-dispatch
 * mechanism already instrumented). Byte-for-byte transcription from
 * src/recomp/gen/recomp_0006.c:44964-45150; only the added prints change
 * behavior (none) -- pure instrumentation to identify which single call
 * never returns. */
extern void sub_00115200(void);
extern void sub_001046A0(void);
extern void sub_00115B10(void);
extern void sub_00016920(void);
extern void sub_00115460(void);
extern void sub_00115520(void);
extern void sub_0014CE80(void);
extern void sub_00069F30(void);
extern void sub_000F3C90(void);
extern void sub_000F36C0(void);
extern void sub_00121B40(void);
extern void sub_0012D910(void);
extern void sub_000F98A0(void);
extern void sub_000E5930(void);
extern void sub_000F6460(void);
extern void sub_0012C9A0(void);
extern void sub_00115030(void);
extern void sub_00115560(void);
extern void sub_001150B0(void);
extern void sub_000F7330(void);
extern void sub_00102090(void);
extern void sub_000C9530(void);
extern void sub_00115120(void);
extern void sub_001152B0(void);

#define F7C50_CALL(name, return_va) do { \
    DAH2_TRACE_FPRINTF(stderr, "[F7C50] -> " #name " ebx=0x%08X esi=0x%08X edi=0x%08X esp=0x%08X\n", g_ebx, g_esi, g_edi, g_esp); \
    g_esp -= 4; *manual_mem32(g_esp) = (return_va); \
    name(); \
    DAH2_TRACE_FPRINTF(stderr, "[F7C50] <- " #name " ok ebx=0x%08X esi=0x%08X edi=0x%08X esp=0x%08X\n", g_ebx, g_esi, g_edi, g_esp); \
} while (0)

/* TEMP: full /FORCE:MULTIPLE transplant of sub_0012C9A0, the function
 * sub_000F7C50's trace pinpointed as the one that enters and never
 * returns ([F7C50] -> sub_0012C9A0 logged, no matching <- ever). Its body
 * is a linked-list walk over ecx+8 (loop while esi != ebx, ebx=ecx+8 the
 * sentinel) that per-node calls sub_0012B870 and either just advances
 * (esi=MEM32(esi)) or unlinks the node and optionally ICALLs before
 * advancing -- structurally identical in shape to the object+0xC8 list
 * walks already investigated in sub_0012B5A0/sub_0012B710, so a cyclic or
 * never-terminating list here is a strong suspect. Instrumented with a
 * per-iteration counter/log and enter+exit prints around both the
 * by-name call to sub_0012B870 and the inner ICALL, to distinguish "loops
 * an enormous/infinite number of times" from "gets stuck inside a single
 * nested call". Byte-for-byte transcription of
 * src/recomp/gen/recomp_0007.c:83521-83601. */
extern void sub_0012B870(void);
static volatile long g_call_count_C9A0;
void sub_0012C9A0(void)
{
    uint32_t ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame */
    uint32_t ebx, esi, edi;
    long n = InterlockedIncrement(&g_call_count_C9A0);
    long iter = 0;

    g_esp -= 4; *manual_mem32(g_esp) = g_ebx;   /* PUSH32(esp, ebx) */
    ebx = g_ecx + 8;
    g_esp -= 4; *manual_mem32(g_esp) = g_esi;   /* PUSH32(esp, esi) */
    esi = *manual_mem32(ebx);

    DAH2_TRACE_FPRINTF(stderr, "[C9A0] ENTER count=%ld ecx=0x%08X ebx(sentinel)=0x%08X esi(head)=0x%08X\n",
            n, g_ecx, ebx, esi);

    if (esi != ebx) {
        g_esp -= 4; *manual_mem32(g_esp) = ebp;   /* PUSH32(esp, ebp) */
        g_esp -= 4; *manual_mem32(g_esp) = g_edi; /* PUSH32(esp, edi) */
        ebp = 0;

        do {
            iter++;
            if (iter <= 30 || (iter % 1000) == 0)
                DAH2_TRACE_FPRINTF(stderr, "[C9A0] iter=%ld esi=0x%08X ebx=0x%08X\n", iter, esi, ebx);
            if (iter == 200000) {
                DAH2_TRACE_FPRINTF(stderr, "[C9A0] *** RUNAWAY: 200000 iterations, aborting instrumentation loop print spam ***\n");
            }

            /* loc_0012C9B0 */
            g_eax = *manual_mem32(g_esp + 0x14);
            g_ecx = *manual_mem32(esi + 8);
            g_esp -= 4; *manual_mem32(g_esp) = g_eax;
            DAH2_TRACE_FPRINTF(stderr, "[C9A0] -> sub_0012B870 esi=0x%08X\n", esi);
            g_esp -= 4; *manual_mem32(g_esp) = 0x0012C9BDu;
            sub_0012B870();
            DAH2_TRACE_FPRINTF(stderr, "[C9A0] <- sub_0012B870 ok al=0x%02X\n", g_eax & 0xFF);

            /* loc_0012C9BD */
            if ((g_eax & 0xFF) != 0) {
                /* loc_0012C9C1 */
                esi = *manual_mem32(esi);
            } else {
                /* loc_0012C9C5 */
                g_ecx = *manual_mem32(esi + 8);
                edi = *manual_mem32(esi);
                g_eax = *manual_mem32(esi + 4);
                *manual_mem32(g_eax) = edi;
                *manual_mem32(edi + 4) = g_eax;
                *manual_mem32(esi) = ebp;
                *manual_mem32(esi + 4) = ebp;
                *manual_mem32(esi + 8) = ebp;
                g_edx = *manual_mem32(ebx + 0x10);
                g_edx--;
                *manual_mem32(ebx + 0x10) = g_edx;
                if (g_ecx != ebp) {
                    /* loc_0012C9E5 */
                    g_edx = *manual_mem32(g_ecx);
                    uint32_t _icall_esp = g_esp;
                    g_esp -= 4; *manual_mem32(g_esp) = 1;
                    uint32_t _icall_target = *manual_mem32(g_edx);
                    g_esp -= 4; *manual_mem32(g_esp) = 0x0012C9EBu;
                    DAH2_TRACE_FPRINTF(stderr, "[C9A0] -> ICALL target=0x%08X\n", _icall_target);
                    if (_icall_target >= 0x00400000 && _icall_target < 0xFE000000) {
                        g_esp = _icall_esp; g_eax = 0;
                    } else {
                        uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
                        recomp_func_t fn = recomp_lookup_manual(_icall_target);
                        if (!fn) fn = recomp_lookup(_icall_target);
                        if (!fn) fn = recomp_lookup_kernel(_icall_target);
                        if (fn) fn();
                        else { recomp_icall_fail_log(_icall_target); g_esp = _icall_esp; g_eax = 0; }
                        g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
                    }
                    DAH2_TRACE_FPRINTF(stderr, "[C9A0] <- ICALL ok\n");
                }
                /* loc_0012C9EB */
                esi = edi;
            }
            /* loc_0012C9ED */
        } while (esi != ebx);

        /* loc_0012C9F1 */
        g_edi = *manual_mem32(g_esp); g_esp += 4;  /* POP32(esp, edi) */
        ebp   = *manual_mem32(g_esp); g_esp += 4;  /* POP32(esp, ebp) */
    }

    /* loc_0012C9F3 */
    g_esi = *manual_mem32(g_esp); g_esp += 4;  /* POP32(esp, esi) */
    g_ebx = *manual_mem32(g_esp); g_esp += 4;  /* POP32(esp, ebx) */
    DAH2_TRACE_FPRINTF(stderr, "[C9A0] EXIT count=%ld total_iters=%ld\n", n, iter);
    g_esp += 8; return; /* 0x0012C9F5: ret 4 (return address + argument) */
}

void sub_000F7C50(void)
{
    uint32_t ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame */

    DAH2_TRACE_FPRINTF(stderr, "[F7C50] ENTER ecx=0x%08X\n", g_ecx);

    g_esp -= 0xC;
    g_eax = *manual_mem32(g_esp + 0x10);
    g_esp -= 4; *manual_mem32(g_esp) = g_ebx;   /* PUSH32(esp, ebx) */
    g_esp -= 4; *manual_mem32(g_esp) = g_esi;   /* PUSH32(esp, esi) */
    g_esi = *manual_mem32(0x30FDE4);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;   /* PUSH32(esp, edi) */
    g_ebx = g_ecx;   /* ebx = ecx: real register, must stay visible to every nested call */
    g_esp -= 4; *manual_mem32(g_esp) = g_eax;   /* PUSH32(esp, eax) */
    g_ecx = g_esi;
    F7C50_CALL(sub_00115200, 0x000F7C6Au);

    /* loc_000F7C6A */
    g_ecx = *manual_mem32(g_esi + 0x10);
    *manual_mem32(g_esp + 0x1C) = g_ecx;
    F7C50_CALL(sub_001046A0, 0x000F7C76u);

    /* loc_000F7C76 */
    g_edi = *manual_mem32(g_esp + 0x1C);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    F7C50_CALL(sub_00115B10, 0x000F7C82u);

    /* loc_000F7C82 */
    if (*(volatile uint8_t *)manual_mem8(g_esi + 0x303C) == 0) {
        /* loc_000F7C8C */
        g_ecx = *manual_mem32(0x307308);
        g_esp -= 4; *manual_mem32(g_esp) = g_edi;
        F7C50_CALL(sub_00016920, 0x000F7C98u);
    }

    /* loc_000F7C98 */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    {
        uint32_t call_sp = g_esp;
        uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
        F7C50_CALL(sub_00115460, 0x000F7CA0u);
        /* One stdcall argument was already pushed. The generated descendant
         * chain can miss its real epilogue and leak 0x94 bytes while replacing
         * ESI with a scratch-stack address; retail returns at call_sp+4 with
         * all three nonvolatile registers intact. */
        g_esp = call_sp + 4;
        g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
    }

    /* loc_000F7CA0 */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    {
        uint32_t call_sp = g_esp;
        uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
        F7C50_CALL(sub_00115520, 0x000F7CA8u);
        g_esp = call_sp + 4;
        g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
    }

    /* loc_000F7CA8 */
    if (*(volatile uint8_t *)manual_mem8(g_esi + 0x303C) != 0) {
        /* loc_000F7CB2 */
        if (*manual_mem32(g_esi + 8) == 1) {
            /* loc_000F7CBC */
            g_esp -= 4; *manual_mem32(g_esp) = ebp;
            ebp = *manual_mem32(0x2F2120);
            g_esp -= 4; *manual_mem32(g_esp) = 0xD2EB1B81u;
            g_ecx = g_esp + 0x14;
            F7C50_CALL(sub_00115E40, 0x000F7CD1u);

            /* loc_000F7CD1 */
            g_edx = *manual_mem32(g_esp + 0x20);
            g_ecx = g_esp + 0x10;
            *manual_mem32(g_esp + 0x10) = 0x2AFD20;
            *manual_mem32(g_esp + 0x18) = g_edx;
            g_eax = *manual_mem32(ebp);
            {
                uint32_t _icall_esp = g_esp;
                g_esp -= 4; *manual_mem32(g_esp) = g_ecx;
                uint32_t this_obj = ebp;
                uint32_t _icall_target = *manual_mem32(g_eax + 8);
                g_esp -= 4; *manual_mem32(g_esp) = 0x000F7CEEu;
                DAH2_TRACE_FPRINTF(stderr, "[F7C50] -> ICALL target=0x%08X\n", _icall_target);
                if (_icall_target >= 0x00400000 && _icall_target < 0xFE000000) {
                    g_esp = _icall_esp; g_eax = 0;
                } else {
                    uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
                    g_ecx = this_obj;
                    recomp_func_t fn = recomp_lookup_manual(_icall_target);
                    if (!fn) fn = recomp_lookup(_icall_target);
                    if (!fn) fn = recomp_lookup_kernel(_icall_target);
                    if (fn) fn();
                    else { recomp_icall_fail_log(_icall_target); g_esp = _icall_esp; g_eax = 0; }
                    g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
                }
                DAH2_TRACE_FPRINTF(stderr, "[F7C50] <- ICALL ok\n");
            }

            /* loc_000F7CEE */
            ebp = *manual_mem32(g_esp); g_esp += 4;  /* POP32(esp, ebp) */
        }
        goto loc_000F7D5C_b;
    }

    /* loc_000F7CF1: first-time setup path */
    g_ecx = *manual_mem32(0x3149EC);
    F7C50_CALL(sub_0014CE80, 0x000F7CFCu);

    /* loc_000F7CFC */
    g_ecx = *manual_mem32(0x2F210C);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_00069F30, 0x000F7D08u);

    /* loc_000F7D08 */
    g_ecx = *manual_mem32(0x307300);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_000F3C90, 0x000F7D14u);

    /* loc_000F7D14 */
    g_ecx = *manual_mem32(0x3072FC);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_000F36C0, 0x000F7D20u);

    /* loc_000F7D20 */
    g_ecx = *manual_mem32(0x30FDF8);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_00121B40, 0x000F7D2Cu);

    /* loc_000F7D2C */
    g_ecx = *manual_mem32(0x30FE38);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_0012D910, 0x000F7D38u);

    /* loc_000F7D38 */
    g_ecx = *manual_mem32(0x30F164);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_000F98A0, 0x000F7D44u);

    /* loc_000F7D44 */
    g_ecx = *manual_mem32(0x3072E8);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    /* sub_000E5930 is a translator-split fragment of a much larger retail
     * function (its own generated body tail-jmps/falls through into
     * sub_000E5A0D, sub_000E5AD2/AE6/AED, sub_000E5B23, ... including
     * RECOMP_ITAIL indirect tail jumps) -- confirmed via direct tracing
     * that it does not reliably restore ebx before finally returning here
     * (observed: entry ebx=0x812142D0, the correct outer "this", changes
     * to an unrelated object pointer like 0x812A1660 by return, causing
     * the very next call, sub_0012C9A0, to receive ecx=MEM32(ebx+0x10)=0
     * from the wrong object and walk garbage memory). Root cause is deep
     * in the translator's function-splitting (its true epilogue, wherever
     * that chain actually ends, doesn't match this fragment's real stack
     * frame), too risky to fix by rewriting that whole chain -- protecting
     * ebx/esi/edi around just this one known-buggy call site is the same
     * defensive pattern used throughout this project for misbehaving
     * callees. See diagnostics/menu_recovery_2026-09-20.md. */
    { uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
      F7C50_CALL(sub_000E5930, 0x000F7D50u);
      g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx; }

    /* loc_000F7D50 */
    g_ecx = *manual_mem32(0x307308);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_000F6460, 0x000F7D5Cu);

loc_000F7D5C_b:
    /* loc_000F7D5C: convergence point of both branches */
    DAH2_TRACE_FPRINTF(stderr, "[F7C50] pre-C9A0 g_ebx=0x%08X (expect 0x812142D0-ish 'this'), MEM32(ebx+0x10)=0x%08X\n",
            g_ebx, *manual_mem32(g_ebx + 0x10));
    g_ecx = *manual_mem32(g_ebx + 0x10);
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_0012C9A0, 0x000F7D65u);

    /* loc_000F7D65 */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    F7C50_CALL(sub_00115030, 0x000F7D6Du);

    /* loc_000F7D6D */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    /* Same translator-split-fragment issue as sub_000E5930 above: observed
     * ebx corrupted from the correct "this" (0x812142D0) to a code-address-
     * looking value (0x0011569D) across this call. Same defensive fix. */
    { uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
      F7C50_CALL(sub_00115560, 0x000F7D75u);
      g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx; }

    /* loc_000F7D75 */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    {
        uint32_t call_sp = g_esp;
        uint32_t protect_esi = g_esi, protect_edi = g_edi, protect_ebx = g_ebx;
        F7C50_CALL(sub_001150B0, 0x000F7D7Du);
        /* sub_001150B0 is another translator-split function. Its damaged
         * descendant path intermittently returns 0x30 bytes below the retail
         * stdcall boundary and leaves ESI pointing into its scratch frame.
         * Retail consumes the one argument and preserves nonvolatile regs. */
        g_esp = call_sp + 4;
        g_esi = protect_esi; g_edi = protect_edi; g_ebx = protect_ebx;
    }

    /* loc_000F7D7D */
    g_ecx = *manual_mem32(0x307310);
    F7C50_CALL(sub_000F7330, 0x000F7D88u);

    /* loc_000F7D88 */
    F7C50_CALL(sub_00102090, 0x000F7D8Du);

    /* loc_000F7D8D */
    g_eax = *manual_mem32(g_esi + 8);
    g_ecx = *manual_mem32(0x307100);
    g_edx = 0;
    g_edx = (g_edx & 0xFFFFFF00u) | *(volatile uint8_t *)manual_mem8(g_esi + 0x303C);
    g_esp -= 4; *manual_mem32(g_esp) = g_edx;
    g_esp -= 4; *manual_mem32(g_esp) = g_eax;
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    F7C50_CALL(sub_000C9530, 0x000F7DA6u);

    /* loc_000F7DA6 */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    F7C50_CALL(sub_00115120, 0x000F7DAEu);

    /* loc_000F7DAE */
    g_esp -= 4; *manual_mem32(g_esp) = g_edi;
    g_ecx = g_esi;
    F7C50_CALL(sub_001152B0, 0x000F7DB6u);

    /* loc_000F7DB6 */
    g_edi = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, edi) */
    g_esi = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, esi) */
    g_ebx = *manual_mem32(g_esp); g_esp += 4;   /* POP32(esp, ebx) */
    g_esp = g_esp + 0xC;
    DAH2_TRACE_FPRINTF(stderr, "[F7C50] EXIT ok\n");
    g_esp += 8; return; /* ret 4 */
}

/* TEMP: sub_000F2720 is dispatched via vtable+0xC on the global object at
 * guest VA 0x31D990, right after the last two known EVENT-BUFFER checks
 * that immediately precede the stall (see diagnostics/menu_recovery_
 * 2026-09-20.md, "Present() heartbeat" and "0x31D990 dispatch" notes). Its
 * body computes esi = MEM32(0x2C9CD0)+MEM32(0x2C9CC8) (the same global
 * "event arena" pair sub_001152D0 uses) and loops `MEM32(esi)` times,
 * dispatching up to 3 virtual calls per 0x48-byte record. If that count is
 * corrupted/huge this is exactly the kind of loop that would look like a
 * hang without ever technically failing to terminate. Tracing entry
 * (before its own sub_0013E4A0/sub_000227F0 setup calls run) and, more
 * importantly, the computed loop count right after, via a raw memory
 * peek. Registered via recomp_lookup_manual (ICALL-dispatched, confirmed
 * no direct-name callers). Pure trace: does not alter behavior. */
extern void sub_000F2720(void);
static volatile long g_call_count_F2720;
static void traced_sub_000F2720(void)
{
    long n = InterlockedIncrement(&g_call_count_F2720);
    uint32_t pre_offset = *manual_mem32(0x2C9CD0);
    uint32_t arena_base = *manual_mem32(0x2C9CC8);
    uint32_t esi_guess = pre_offset + arena_base;
    DAH2_TRACE_FPRINTF(stderr, "[CALL-F2720] count=%ld ecx=0x%08X pre_count_at_esi=0x%08X (esi_guess=0x%08X)\n",
            n, g_ecx, *manual_mem32(esi_guess), esi_guess);
    sub_000F2720();
    DAH2_TRACE_FPRINTF(stderr, "[CALL-F2720] count=%ld RETURNED\n", n);
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_0015E740, reached on the
 * very first frame-setup pass via sub_000F7C50 -> sub_00115120 ->
 * sub_0015ECA0 -> ... -> sub_0015C170 -> sub_0015E740. Confirmed via the
 * g_icall_watch_this mechanism (watching object 0x00315330, seen
 * consistently in every crash of this exact shape) that at loc_0015EB7B
 * this function dispatches MEM32(MEM32(esi)+0x58) -- and MEM32(esi) (the
 * object's OWN vtable pointer) is itself garbage on this first pass
 * (echoes its own address: reading vtable+0x58 literally yields
 * 0x04000058), because the object hasn't been fully constructed yet.
 * RECOMP_ICALL_SAFE correctly treats that as an unresolvable garbage
 * target and gracefully returns eax=0 -- but retail's own code has NO
 * check for that at loc_0015EB83, and unconditionally continues
 * `ecx = MEM32(eax+0x90); eax = MEM32(ecx); ...; ICALL MEM32(eax+0x34)`,
 * walking further garbage until it dereferences something in the
 * reserved 0xFE000000+ region and crashes (matches the observed access
 * violation at Xbox VA ~0xFE2B3920..0xFE2C3920, eax=0x3F800000, ecx=0,
 * edx=0). Fix: this function already has its OWN precedent for skipping
 * straight to its early-exit epilogue (loc_0015EC88) under a different
 * not-ready condition (the original loc_0015EB6B check) -- so detecting
 * a garbage vtable up front and taking that same skip, instead of the
 * unguarded dereference chain, is the minimal, in-character fix. This is
 * a construction-order/uninitialized-object issue in the underlying game
 * logic (a separate, deeper question); skipping this optional visual
 * setup for the one pass where the object isn't ready yet (matching how
 * the function's own existing early-exit already treats other not-ready
 * conditions) is safe.
 *
 * Locally aliases bare register names to the g_-prefixed globals (exactly
 * as recomp_types.h does for generated .c files under
 * RECOMP_GENERATED_CODE) so the body below is a near-verbatim
 * transcription of src/recomp/gen/recomp_0009.c:41368-41804, minimizing
 * transcription risk for this float/XMM-heavy function. Only the guard at
 * loc_0015EB7B changes behavior. */
#ifndef RECOMP_XMM_DEFINED
#define RECOMP_XMM_DEFINED
typedef union RecompXmm {
    float    f[4];
    double   d[2];
    uint32_t u[4];
    int32_t  i[4];
    uint64_t q[2];
} RecompXmm;
#endif
extern __declspec(thread) RecompXmm g_xmm0, g_xmm1, g_xmm2, g_xmm3;

static __forceinline RecompXmm manual_xmm_zero(void) { RecompXmm r; r.q[0] = 0; r.q[1] = 0; return r; }
static __forceinline RecompXmm manual_xmm_scalar(float v) { RecompXmm r = manual_xmm_zero(); r.f[0] = v; return r; }
static __forceinline float *manual_memf(uint32_t va) { return (float *)((uintptr_t)g_xbox_mem_offset + va); }

#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define esp g_esp
#define ebx g_ebx
#define esi g_esi
#define edi g_edi
#define xmm0 g_xmm0
#define xmm1 g_xmm1
#define xmm2 g_xmm2
#define xmm3 g_xmm3
#define XMM_ZERO() manual_xmm_zero()
#define XMM_SCALAR(v) manual_xmm_scalar(v)
#define MEM32(addr) (*manual_mem32(addr))
#define MEM8(addr) (*manual_mem8(addr))
#define MEMF(addr) (*manual_memf(addr))
#define PUSH32(sp, val) do { sp -= 4; *manual_mem32(sp) = (uint32_t)(val); } while (0)
#define POP32(sp, dst) do { dst = *manual_mem32(sp); sp += 4; } while (0)
#define CMP_EQ(a, b) ((a) == (b))
#define CMP_NE(a, b) ((a) != (b))
#define CMP_LE(a, b) ((int32_t)(a) <= (int32_t)(b))
#define CMP_L(a, b) ((int32_t)(a) < (int32_t)(b))
#define CMP_BE(a, b) ((uint32_t)(a) <= (uint32_t)(b))
#define CMP_B(a, b) ((uint32_t)(a) < (uint32_t)(b))
#define TEST_Z(a, b) (((a) & (b)) == 0)
#define TEST_NZ(a, b) (((a) & (b)) != 0)
#define LO8(r) ((uint8_t)((r) & 0xFF))
#define HI8(r) ((uint8_t)(((r) >> 8) & 0xFF))
#define SET_LO8(r, v) ((r) = ((r) & 0xFFFFFF00u) | ((uint32_t)(uint8_t)(v)))
extern int g_manual_transplant_icall_trace;
#define RECOMP_ICALL_SAFE(target, saved_esp) do { \
    if (g_manual_transplant_icall_trace) \
        DAH2_TRACE_FPRINTF(stderr, "[TRANSPLANT-ICALL] line=%d target=0x%08X ecx=0x%08X\n", __LINE__, (target), g_ecx); \
    if ((target) >= 0x00400000u && (target) < 0xFE000000u) { \
        if (g_manual_transplant_icall_trace) \
            DAH2_TRACE_FPRINTF(stderr, "[TRANSPLANT-ICALL] line=%d GARBAGE, skipped\n", __LINE__); \
        g_esp = (saved_esp); g_eax = 0; \
    } else { \
        uint32_t _pe = g_esi, _pd = g_edi, _pb = g_ebx; \
        recomp_func_t _fn = recomp_lookup_manual(target); \
        if (!_fn) _fn = recomp_lookup(target); \
        if (!_fn) _fn = recomp_lookup_kernel(target); \
        if (_fn) _fn(); \
        else { recomp_icall_fail_log(target); g_esp = (saved_esp); g_eax = 0; } \
        g_esi = _pe; g_edi = _pd; g_ebx = _pb; \
        if (g_manual_transplant_icall_trace) \
            DAH2_TRACE_FPRINTF(stderr, "[TRANSPLANT-ICALL] line=%d returned ok\n", __LINE__); \
    } \
} while (0)

/* DAH2_INPUT_REPLAY_BEGIN
 * DAH1-style logical controller replay at the retail XInputGetState boundary.
 * It is enabled only for an explicitly hidden diagnostic run. No host input
 * device is queried, and the ordinary generated XPP path remains unchanged. */
typedef struct Dah2InputEvent {
    unsigned start, duration, buttons;
    unsigned analog[8];
    int sticks[4];
} Dah2InputEvent;

#define DAH2_INPUT_HANDLE_BASE 0xDA220000u
static int g_dah2_input_reported;

extern void sub_00296301(void);
extern void sub_000FAFD5(void);
extern void sub_00297D9A(void);
extern void sub_00297A06(void);

static int dah2_hidden_input_enabled(void)
{
    const char *hidden = getenv("DAH2_TEST_WINDOW_HIDDEN");
    const char *script = getenv("DAH2_INPUT_SCRIPT");
    return hidden && strcmp(hidden, "1") == 0 && script && *script;
}

static void dah2_scripted_xinput_get_state(void)
{
    static Dah2InputEvent events[128];
    static unsigned event_count, poll, packet;
    static unsigned char previous_payload[18];
    static int loaded, have_previous;
    unsigned char state[22] = {0};
    uint32_t output = MEM32(esp + 8u);
    unsigned i;

    if (!loaded) {
        const char *path = getenv("DAH2_INPUT_SCRIPT");
        FILE *file = path ? fopen(path, "r") : NULL;
        loaded = 1;
        if (!file) {
            fprintf(stderr, "[DAH2-INPUT] cannot read hidden input schedule; neutral pad only\n");
        } else {
            char line[256];
            while (fgets(line, sizeof(line), file)) {
                Dah2InputEvent event = {0};
                char extra;
                char *cursor = line;
                int fields;
                while (*cursor == ' ' || *cursor == '\t') ++cursor;
                if (!*cursor || *cursor == '#' || *cursor == '\r' || *cursor == '\n') continue;
                fields = sscanf(cursor,
                    "%u %u %x %u %u %d %d %d %d %u %u %u %u %u %u %c",
                    &event.start, &event.duration, &event.buttons,
                    &event.analog[0], &event.analog[1],
                    &event.sticks[0], &event.sticks[1],
                    &event.sticks[2], &event.sticks[3],
                    &event.analog[2], &event.analog[3],
                    &event.analog[4], &event.analog[5],
                    &event.analog[6], &event.analog[7], &extra);
                if (event_count >= 128u || (fields != 9 && fields != 15) ||
                    !event.duration || event.start > 1000000u || event.duration > 100000u ||
                    event.buttons > 0xFFFFu ||
                    event.analog[0] > 255u || event.analog[1] > 255u ||
                    event.analog[2] > 255u || event.analog[3] > 255u ||
                    event.analog[4] > 255u || event.analog[5] > 255u ||
                    event.analog[6] > 255u || event.analog[7] > 255u ||
                    event.sticks[0] < -32768 || event.sticks[0] > 32767 ||
                    event.sticks[1] < -32768 || event.sticks[1] > 32767 ||
                    event.sticks[2] < -32768 || event.sticks[2] > 32767 ||
                    event.sticks[3] < -32768 || event.sticks[3] > 32767) {
                    event_count = 0;
                    fprintf(stderr, "[DAH2-INPUT] invalid schedule row; neutral pad only\n");
                    break;
                }
                events[event_count++] = event;
            }
            fclose(file);
            fprintf(stderr,
                "[DAH2-INPUT] loaded %u events; physical input disabled at retail boundary\n",
                event_count);
            fflush(stderr);
        }
    }

    for (i = 0; i < event_count; ++i) {
        const Dah2InputEvent *event = &events[i];
        uint16_t buttons;
        if (poll < event->start || poll - event->start >= event->duration) continue;
        memcpy(&buttons, state + 4, sizeof(buttons));
        buttons = (uint16_t)(buttons | event->buttons);
        memcpy(state + 4, &buttons, sizeof(buttons));
        for (unsigned channel = 0; channel < 8; ++channel)
            if (event->analog[channel]) state[6 + channel] = (unsigned char)event->analog[channel];
        for (unsigned axis = 0; axis < 4; ++axis)
            if (event->sticks[axis]) {
                int16_t value = (int16_t)event->sticks[axis];
                memcpy(state + 14 + axis * 2, &value, sizeof(value));
            }
    }
    if (!have_previous || memcmp(previous_payload, state + 4, sizeof(previous_payload)) != 0) {
        ++packet;
        memcpy(previous_payload, state + 4, sizeof(previous_payload));
        have_previous = 1;
        fprintf(stderr,
            "[DAH2-INPUT] poll=%u packet=%u buttons=%04X\n",
            poll, packet, (unsigned)(state[4] | ((unsigned)state[5] << 8)));
        fflush(stderr);
    }
    memcpy(state, &packet, sizeof(packet));
    if (output >= 0x10000u && output <= 0x08000000u - sizeof(state))
        memcpy(manual_mem8(output), state, sizeof(state));
    else
        fprintf(stderr, "[DAH2-INPUT] invalid output=%08X\n", output);
    ++poll;
    eax = 0;       /* ERROR_SUCCESS */
    esp += 12u;    /* ret 8 */
}

/* Match DAH1's retail-device lifecycle at the Xbox XPP boundary.  These
 * overrides exist because the game calls them directly, before GetState can
 * ever be reached.  Hidden parity runs expose one private neutral controller;
 * ordinary launches retain the generated Xbox-library behavior verbatim. */
void sub_002961C2(void)
{
    uint32_t ebp;
    if (dah2_hidden_input_enabled()) {
        uint32_t type = MEM32(esp + 4u);
        uint32_t port = MEM32(esp + 8u);
        uint32_t slot = MEM32(esp + 12u);
        uint32_t polling = MEM32(esp + 16u);
        if (port < 4u && slot == 0u) {
            eax = DAH2_INPUT_HANDLE_BASE + port;
            fprintf(stderr,
                "[DAH2-INPUT] XInputOpen type=%08X port=%u slot=%u polling=%08X handle=%08X\n",
                type, port, slot, polling, eax);
        } else {
            eax = 0;
            fprintf(stderr,
                "[DAH2-INPUT] XInputOpen rejected port=%u slot=%u polling=%08X\n",
                port, slot, polling);
        }
        fflush(stderr);
        esp += 20u; /* ret 16 */
        return;
    }

    PUSH32(esp, ebp);
    ebp = esp;
    g_ebp = ebp;
    PUSH32(esp, ecx);
    ecx = MEM32(ebp + 8u);
    MEM32(ebp - 4u) = 0;
    g_ebp = ebp;
    PUSH32(esp, 0x002961D2u);
    sub_00296301();
    if (eax == 0) {
        PUSH32(esp, 0x57u);
        g_ebp = ebp;
        PUSH32(esp, 0x002961DDu);
        sub_000FAFD5();
        eax = 0;
    } else {
        PUSH32(esp, esi);
        esi = MEM32(ebp + 0x14u);
        if (esi == 0) esi = MEM32(eax + 0x10u);
        edx = MEM32(ebp + 0xCu);
        if (MEM32(ebp + 0x10u) == 1u) edx += 0x10u;
        PUSH32(esp, esi);
        ecx = ebp - 4u;
        PUSH32(esp, ecx);
        ecx = eax;
        g_ebp = ebp;
        PUSH32(esp, 0x00296204u);
        sub_00297D9A();
        POP32(esp, esi);
        if (MEM32(ebp - 4u) == 0) {
            PUSH32(esp, eax);
            g_ebp = ebp;
            PUSH32(esp, 0x00296211u);
            sub_000FAFD5();
        }
        eax = MEM32(ebp - 4u);
    }
    esp = ebp;
    POP32(esp, ebp);
    esp += 20u; /* ret 16 */
}

void sub_00296218(void)
{
    if (dah2_hidden_input_enabled()) {
        uint32_t handle = MEM32(esp + 4u);
        uint32_t port = handle - DAH2_INPUT_HANDLE_BASE;
        if (port >= 4u)
            fprintf(stderr, "[DAH2-INPUT] XInputClose unknown handle=%08X\n", handle);
        fflush(stderr);
        esp += 8u; /* ret 4 */
        return;
    }
    ecx = MEM32(esp + 4u);
    PUSH32(esp, 0x00296221u);
    sub_00297A06();
    esp += 8u; /* ret 4 */
}

void sub_00296297(void)
{
    if (dah2_hidden_input_enabled()) {
        static int logged;
        uint32_t handle = MEM32(esp + 4u);
        uint32_t port = handle - DAH2_INPUT_HANDLE_BASE;
        eax = port < 4u ? 0u : 0x48Fu;
        if (!logged) {
            fprintf(stderr,
                "[DAH2-INPUT] XInputSetState handle=%08X vibration suppressed result=%08X\n",
                handle, eax);
            fflush(stderr);
            logged = 1;
        }
        esp += 12u; /* ret 8 */
        return;
    }

    ecx = MEM32(esp + 4u);
    eax = ecx + 0xA3u;
    edx = MEM32(eax);
    if ((MEM8(edx + 0x28u) & 0x20u) != 0) {
        eax = 0x57u;
    } else {
        edx = MEM32(esp + 8u);
        MEM8(edx + 0x40u) = 0;
        eax = MEM32(eax);
        eax = MEM32(eax + 0xCu);
        SET_LO8(eax, MEM8(eax));
        SET_LO8(eax, LO8(eax) + 2u);
        MEM8(edx + 0x41u) = LO8(eax);
        PUSH32(esp, 0x002962C7u);
        {
            extern void sub_00297A9A(void);
            sub_00297A9A();
        }
    }
    esp += 12u; /* ret 8 */
}

void sub_00296353(void)
{
    uint32_t saved_entry_esp, target;
    if (dah2_hidden_input_enabled()) {
        uint32_t type = MEM32(esp + 4u);
        g_dah2_input_reported = 1;
        eax = 1u;
        fprintf(stderr, "[DAH2-INPUT] XGetDevices type=%08X mask=00000001\n", type);
        fflush(stderr);
        esp += 8u; /* ret 4 */
        return;
    }

    saved_entry_esp = esp;
    PUSH32(esp, esi);
    target = MEM32(0x29B610u);
    PUSH32(esp, 0x0029635Au);
    RECOMP_ICALL_SAFE(target, saved_entry_esp);
    edx = MEM32(esp + 8u);
    esi = MEM32(edx);
    MEM32(edx + 4u) = 0;
    SET_LO8(ecx, LO8(eax));
    MEM32(edx + 8u) = esi;
    saved_entry_esp = esp;
    target = MEM32(0x29B60Cu);
    PUSH32(esp, 0x0029636Fu);
    RECOMP_ICALL_SAFE(target, saved_entry_esp);
    eax = esi;
    POP32(esp, esi);
    esp += 8u; /* ret 4 */
}

void sub_00296375(void)
{
    uint32_t ebp, saved_entry_esp, target;
    if (dah2_hidden_input_enabled()) {
        uint32_t type = MEM32(esp + 4u);
        uint32_t inserted_out = MEM32(esp + 8u);
        uint32_t removed_out = MEM32(esp + 12u);
        uint32_t inserted = g_dah2_input_reported ? 0u : 1u;
        g_dah2_input_reported = 1;
        MEM32(inserted_out) = inserted;
        MEM32(removed_out) = 0;
        eax = inserted != 0u;
        if (inserted)
            fprintf(stderr,
                "[DAH2-INPUT] XGetDeviceChanges type=%08X inserted=00000001\n",
                type);
        fflush(stderr);
        esp += 16u; /* ret 12 */
        return;
    }

    PUSH32(esp, ebp);
    ebp = esp;
    g_ebp = ebp;
    PUSH32(esp, esi);
    esi = MEM32(ebp + 8u);
    eax = 0;
    if (MEM32(esi + 4u) == 0) {
        ecx = MEM32(ebp + 0xCu);
        MEM32(ecx) = 0;
        ecx = MEM32(ebp + 0x10u);
        MEM32(ecx) = 0;
    } else {
        saved_entry_esp = esp;
        PUSH32(esp, ebx);
        PUSH32(esp, edi);
        target = MEM32(0x29B610u);
        PUSH32(esp, 0x00296397u);
        RECOMP_ICALL_SAFE(target, saved_entry_esp);
        ecx = ~MEM32(esi + 8u);
        ebx = MEM32(ebp + 0xCu);
        ecx &= MEM32(esi);
        MEM32(ebx) = ecx;
        edx = ~MEM32(esi);
        ecx = MEM32(ebp + 0x10u);
        edx &= MEM32(esi + 8u);
        MEM32(ecx) = edx;
        edi = MEM32(esi + 4u);
        edi &= MEM32(esi + 8u);
        edi &= MEM32(esi);
        edx |= edi;
        MEM32(ecx) = edx;
        MEM32(ebx) |= edi;
        ecx = MEM32(esi);
        MEM32(esi + 4u) = 0;
        MEM32(esi + 8u) = ecx;
        SET_LO8(ecx, LO8(eax));
        saved_entry_esp = esp;
        target = MEM32(0x29B60Cu);
        PUSH32(esp, 0x002963CEu);
        RECOMP_ICALL_SAFE(target, saved_entry_esp);
        eax = MEM32(ebx) | MEM32(MEM32(ebp + 0x10u));
        POP32(esp, edi);
        eax = eax != 0u;
        POP32(esp, ebx);
    }
    POP32(esp, esi);
    POP32(esp, ebp);
    esp += 16u; /* ret 12 */
}

/* Full retail fallback plus the opt-in logical adapter. This definition is
 * intentionally linked before the generated duplicate, like the other manual
 * translation repairs in this file. */
void sub_00296224(void)
{
    uint32_t saved_entry_esp, target;
    if (dah2_hidden_input_enabled()) {
        dah2_scripted_xinput_get_state();
        return;
    }

    saved_entry_esp = esp;
    PUSH32(esp, ebx);
    PUSH32(esp, esi);
    ebx = 0;
    target = MEM32(0x29B610u);
    PUSH32(esp, 0x0029622Eu);
    RECOMP_ICALL_SAFE(target, saved_entry_esp);

    edx = MEM32(esp + 0xCu);
    ecx = MEM32(edx + 0xA3u);
    if ((MEM8(ecx + 0x28u) & 0x10u) != 0) {
        esi = 0x57u;
    } else {
        ecx = MEM32(edx);
        if (!ecx || (MEM8(ecx + 4u) & 2u) == 0) ebx = 0x48Fu;
        ecx = MEM32(edx + 8u);
        PUSH32(esp, edi);
        edi = MEM32(esp + 0x14u);
        MEM32(edi) = ecx;
        MEM8(edx + 0xA2u) &= 0xEFu;
        ecx = MEM32(edx + 0xA3u);
        ecx = MEM32(ecx + 8u);
        ecx = (uint32_t)MEM8(ecx);
        esi = edx + 0x14u;
        {
            uint32_t bytes = ecx;
            edi += 4u;
            memcpy(manual_mem8(edi), manual_mem8(esi), bytes);
            esi += bytes;
            edi += bytes;
            ecx = 0;
        }
        esi = ebx;
        POP32(esp, edi);
    }

    SET_LO8(ecx, LO8(eax));
    saved_entry_esp = esp;
    target = MEM32(0x29B60Cu);
    PUSH32(esp, 0x00296290u);
    RECOMP_ICALL_SAFE(target, saved_entry_esp);
    eax = esi;
    POP32(esp, esi);
    POP32(esp, ebx);
    esp += 12u;
}
/* DAH2_INPUT_REPLAY_END */

/* Retail draw-record constructor, 0x0016E200..0x0016E3E6.  The generated
 * extent stopped at 0x0016E2DC, before the remaining packed fields and the
 * four register pops / RET 0x30.  Three live calls leaked 3 * 0x44 bytes.
 * Keep the instruction order (including partial-register writes), not a
 * stack-reset workaround, because source and destination may overlap. */
void sub_0016E200(void)
{
    uint32_t ebp = g_ebp;
    uint32_t target;
#define DRAW_MEM16(a) (*(uint16_t *)manual_mem8(a))
#define DRAW_SET16(r, v) ((r) = ((r) & 0xFFFF0000u) | (uint16_t)(v))
    PUSH32(esp, ebx);
    PUSH32(esp, ebp);
    PUSH32(esp, esi);
    PUSH32(esp, edi);
    eax = MEM32(esp + 0x14);
    edx = MEM32(esp + 0x18);
    MEM32(ecx) = eax;
    DRAW_SET16(eax, DRAW_MEM16(esp + 0x20));
    MEM32(ecx + 4) = edx;
    DRAW_SET16(edx, DRAW_MEM16(esp + 0x24));
    DRAW_MEM16(ecx + 8) = (uint16_t)eax;
    DRAW_SET16(eax, DRAW_MEM16(esp + 0x28));
    DRAW_MEM16(ecx + 0xA) = (uint16_t)edx;
    DRAW_SET16(edx, DRAW_MEM16(esp + 0x2C));
    DRAW_MEM16(ecx + 0xC) = (uint16_t)eax;
    DRAW_SET16(eax, DRAW_MEM16(esp + 0x30));
    DRAW_MEM16(ecx + 0xE) = (uint16_t)edx;
    DRAW_SET16(edx, DRAW_MEM16(esp + 0x34));
    DRAW_MEM16(ecx + 0x10) = (uint16_t)eax;
    DRAW_MEM16(ecx + 0x12) = (uint16_t)edx;
    ebx = MEM32(ecx + 0x44);
    esi = MEM32(esp + 0x1C);
    DRAW_SET16(eax, DRAW_MEM16(esi + 0x14));
    DRAW_MEM16(ecx + 0x14) = (uint16_t)eax;
    DRAW_SET16(edx, DRAW_MEM16(esi + 0x16));
    DRAW_MEM16(ecx + 0x16) = (uint16_t)edx;
    eax = MEM32(esi + 0x20);
    MEM32(ecx + 0x20) = eax;
    edx = MEM32(esi + 0x24);
    MEM32(ecx + 0x24) = edx;
    eax = MEM32(esi + 0x28);
    MEM32(ecx + 0x28) = eax;
    edx = MEM32(esi + 0x48);
    MEM32(ecx + 0x48) = edx;
    eax = MEM32(esi + 0x18);
    MEM32(ecx + 0x18) = eax;
    DRAW_SET16(edx, DRAW_MEM16(esi + 0x3C));
    eax = MEM32(esp + 0x40);
    DRAW_MEM16(ecx + 0x3C) = (uint16_t)edx;
    eax &= 0x3FF;
    edx = ((int32_t)eax < 0) ? 0xFFFFFFFFu : 0;
    edx |= ebx;
    MEM32(ecx + 0x44) = edx;
    edi = MEM32(ecx + 0x40);
    edi &= 0xFFFFFC00u;
    eax |= edi;
    MEM32(ecx + 0x40) = eax;
    ebp = MEM32(esi + 0x40);
    edi = MEM32(ecx + 0x40);
    eax ^= ebp;
    eax &= 0x3FFFFC00;
    edi ^= eax;
    ebx = 0;
    edx ^= ebx;
    MEM32(ecx + 0x44) = edx;
    MEM32(ecx + 0x40) = edi;
    eax = MEM32(esi + 0x40);
    ebp = MEM32(esi + 0x44);
    edx = edi;
    edx ^= eax;
    eax = MEM32(ecx + 0x44);
    edx &= 0xC0000000u;
    edi ^= edx;
    edx = MEM32(ecx + 0x44);
    eax ^= ebp;
    eax &= 7;
    edx ^= eax;
    MEM32(ecx + 0x44) = edx;
    SET_LO8(edx, MEM8(esp + 0x3C));
    ebp = MEM32(ecx + 0x44);
    SET_LO8(edx, LO8(edx) & 3);
    eax = LO8(edx);
    edx = ((int32_t)eax < 0) ? 0xFFFFFFFFu : 0;
    edx = 0;
    eax <<= 3;
    ebp &= 0xFFFFFFE7u;
    edx |= edi;
    eax |= ebp;
    MEM32(ecx + 0x40) = edi;
    MEM32(ecx + 0x40) = edx;
    MEM32(ecx + 0x44) = eax;
    eax = MEM8(esp + 0x38);
    ebp = MEM32(ecx + 0x44);
    edi = MEM32(ecx + 0x40);
    edx = ((int32_t)eax < 0) ? 0xFFFFFFFFu : 0;
    eax <<= 5;
    edx = 0;
    ebp &= 0xFFFFE01Fu;
    eax |= ebp;
    MEM32(ecx + 0x44) = eax;
    edx |= edi;
    MEM32(ecx + 0x40) = edx;
    eax = MEM32(esi + 0x2C);
    MEM32(ecx + 0x2C) = eax;
    edx = MEM32(esi + 0x30);
    MEM32(ecx + 0x30) = edx;
    eax = MEM32(esi + 0x34);
    MEM32(ecx + 0x34) = eax;
    edx = MEM32(esi + 0x38);
    MEM32(ecx + 0x38) = edx;
    edx = MEM32(ecx + 0x40);
    edi = MEM32(ecx + 0x44);
    eax = edx;
    ebp = edi;
    eax = ((eax >> 30) | (ebp << 2)) & 0x1F;
    if (eax == 1 || eax == 4) {
        xmm0 = XMM_SCALAR(MEMF(0x29B7A8));
        /* COMISS/JBE also skips adjustment when either value is NaN. */
        if (xmm0.f[0] > MEMF(ecx + 0x18)) {
            edx &= 0xBFFFFFFFu;
            edi &= 0xFFFFFFF9u;
            edx |= 0x80000000u;
            edi |= 1;
            MEM32(ecx + 0x40) = edx;
            MEM32(ecx + 0x44) = edi;
        }
    }
    eax = MEM32(ecx + 0x40);
    edi = MEM32(ecx + 0x44);
    edx = eax;
    ebp = edi;
    edx = ((edx >> 30) | (ebp << 2)) & 0x1F;
    if (edx <= 0xA) {
        edx = MEM8(edx + 0x16E3F8);
        target = MEM32(edx * 4 + 0x16E3E8);
        switch (target) {
        case 0x0016E3B0:
            eax &= 0xC00003FFu;
            MEM32(ecx + 0x40) = eax;
            MEM32(ecx + 0x44) = edi;
            /* fall through */
        case 0x0016E3BB:
            MEM8(ecx + 0x1C) = LO8(ebx);
            break;
        case 0x0016E3C0:
            eax &= 0xC00003FFu;
            MEM32(ecx + 0x40) = eax;
            MEM32(ecx + 0x44) = edi;
            /* fall through */
        case 0x0016E3CB:
            MEM8(ecx + 0x1C) = 2;
            break;
        default: {
            recomp_func_t fn = recomp_lookup_manual(target);
            if (!fn) fn = recomp_lookup(target);
            if (!fn) fn = recomp_lookup_kernel(target);
            g_ebp = ebp; g_seh_ebp = ebp;
            if (fn) fn(); else recomp_icall_fail_log(target);
            return; /* unexpected indirect tail: do not synthesize cleanup */
        }
        }
    }
    eax = MEM32(0x2CB8DC);
    if (MEM8(eax + 0x70) != LO8(ebx)) {
        SET_LO8(edx, MEM8(esi + 0x1C));
        MEM8(ecx + 0x1C) = LO8(edx);
    }
    POP32(esp, edi);
    POP32(esp, esi);
    POP32(esp, ebp);
    POP32(esp, ebx);
    esp += 52; /* ret 0x30: return address plus twelve arguments */
#undef DRAW_MEM16
#undef DRAW_SET16
}

/* Retail 0x0013B8F0..0x0013B900 copies sixteen dwords with REP MOVSD.
 * The old generated guard rejected mapped Xbox physical/heap addresses
 * (including live camera matrix 0x81255440) and zeroed the destination.
 * Preserve forward REP semantics, including overlapping input/output. */
void sub_0013B8F0(void)
{
    PUSH32(esp, esi);
    PUSH32(esp, edi);
    edi = ecx;
    ecx = 0x10;
    esi = edx;
    while (ecx != 0) {
        MEM32(edi) = MEM32(esi);
        esi += 4;
        edi += 4;
        ecx--;
    }
    POP32(esp, edi);
    POP32(esp, esi);
    esp += 4; /* ret */
}

extern __declspec(thread) RecompXmm g_xmm4, g_xmm5, g_xmm6, g_xmm7;
extern __declspec(thread) double g_fp_stack[8];
extern __declspec(thread) int g_fp_top;
extern void sub_0013B550(void);

/* Retail 0x001C6A27 is the x87 ceil helper used by sub_0013C410.
 * The generated CRT body loses its x87 return on the ordinary finite-number
 * path, so ceil(0.11547...) reaches sub_001C55FC as 0 instead of retail's 1.
 * Preserve the cdecl stack contract and return the result in the shared x87
 * stack model. */
void sub_001C6A27(void)
{
    uint64_t bits = (uint64_t)MEM32(g_esp + 4)
                  | ((uint64_t)MEM32(g_esp + 8) << 32);
    double input;
    memcpy(&input, &bits, sizeof(input));
    g_fp_top = (g_fp_top + 7) & 7;
    g_fp_stack[g_fp_top] = ceil(input);
    g_esp += 4; /* ret; caller removes the 8-byte argument */
}
/* Full retail 0x0015CD50..0x0015CE8B projection update. The old generated
 * function stopped at 15CD9A, while its no-camera branch reached the empty
 * 15CDB6 stub. Both lost ESI/ESP and omitted the projection outputs, letting
 * caller 15E740 write renderer matrices into the viewport object instead.
 * Keep retail SSE operation order and the shared x87 stack model, including
 * the real 13B550 trigonometric helper; this is not an ABI-reset workaround. */
void sub_0015CD50(void)
{
    #define fp_push(v) do { double _fp_value = (v); \
        g_fp_top = (g_fp_top + 7u) & 7u; \
        g_fp_stack[g_fp_top] = _fp_value; } while (0)
    #define fp_pop() (g_fp_top = (g_fp_top + 1u) & 7u)
    #define fp_top() g_fp_stack[g_fp_top]
    #define fp_st(i) g_fp_stack[(g_fp_top + (i)) & 7u]
    #define fp_st1() fp_st(1)

    xmm1 = XMM_SCALAR(MEMF(0x29B7A8));
    esp -= 8;
    PUSH32(esp, esi);
    esi = ecx;
    eax = MEM32(esi + 0x90);
    g_xmm5 = xmm1;
    if (eax != 0) {
        eax = MEM32(eax + 0xE8);
        fp_push(MEMF(0x29B7A8));
        fp_top() /= MEMF(eax + 0x2C);
        PUSH32(esp, ecx);
        fp_push(0.69314718055994530942);
        { double t = fp_top(); fp_top() = fp_st1(); fp_st1() = t; }
        { fp_st1() *= log2(fp_top()); fp_pop(); }
        fp_top() *= MEMF(0x2B3864);
        MEMF(esi + 0xA0) = (float)fp_top(); fp_pop();
        xmm0 = XMM_SCALAR(MEMF(eax + 0x28));
        xmm0.f[0] *= MEMF(0x29B720);
        MEMF(esp) = xmm0.f[0];
        PUSH32(esp, 0x0015CDA4u);
        sub_0013B550();
        MEMF(esp + 4) = (float)fp_top(); fp_pop();
        g_xmm5 = XMM_SCALAR(MEMF(esp + 4));
        xmm1 = XMM_SCALAR(MEMF(0x29B7A8));
    }

    /* 0x0015CDB6: common camera/no-camera projection path. */
    eax = MEM32(0x2CA6A0);
    xmm0 = XMM_SCALAR(MEMF(eax + 0x1EC));
    g_xmm4.f[0] = (float)(int32_t)MEM32(esi + 0x88);
    MEMF(esp + 8) = xmm0.f[0];
    xmm2 = g_xmm5;
    xmm2.f[0] *= MEMF(0x2A39D8);
    xmm0 = g_xmm4;
    xmm0.f[0] /= xmm2.f[0];
    MEMF(esp + 4) = xmm0.f[0];
    fp_push(MEMF(esp + 4));
    ecx = MEM32(eax + 0x228);
    fp_push(0.69314718055994530942);
    edx = MEM32(eax + 0x22C);
    { double t = fp_top(); fp_top() = fp_st1(); fp_st1() = t; }
    g_xmm6 = XMM_SCALAR(MEMF(eax + 0x1E8));
    xmm2.f[0] = (float)(int32_t)MEM32(esi + 0x8C);
    MEMF(esi + 0x98) = xmm0.f[0];
    xmm3.f[0] = (float)(int32_t)ecx;
    { fp_st1() *= log2(fp_top()); fp_pop(); }
    xmm0 = g_xmm4;
    xmm0.f[0] /= xmm3.f[0];
    g_xmm7 = xmm2;
    xmm3.f[0] = (float)(int32_t)edx;
    g_xmm7.f[0] /= xmm3.f[0];
    xmm0.f[0] /= g_xmm7.f[0];
    xmm3 = xmm0;
    xmm0.f[0] *= MEMF(esp + 8);
    xmm3.f[0] *= g_xmm6.f[0];
    xmm1.f[0] /= xmm3.f[0];
    xmm0.f[0] *= xmm1.f[0];
    xmm2.f[0] *= xmm3.f[0];
    xmm2.f[0] /= g_xmm4.f[0];
    xmm0.f[0] *= xmm2.f[0];
    xmm1.f[0] *= g_xmm5.f[0];
    xmm1.f[0] *= MEMF(esi + 0xB0);
    xmm0.f[0] *= g_xmm5.f[0];
    MEMF(esi + 0x94) = xmm2.f[0];
    MEMF(esi + 0xA4) = xmm0.f[0];
    MEMF(esi + 0xA8) = xmm1.f[0];
    fp_top() *= MEMF(0x2B3864);
    MEMF(esi + 0x9C) = (float)fp_top(); fp_pop();
    POP32(esp, esi);
    esp += 8;
    esp += 4; /* 0x0015CE8A: ret */

    #undef fp_push
    #undef fp_pop
    #undef fp_top
    #undef fp_st
    #undef fp_st1
}

void sub_0015E740(void)
{
    uint32_t ebp;
    int _flags = 0;
    uint32_t _fa = 0, _fb = 0;
    int32_t _fas = 0, _fbs = 0;
    (void)_flags; (void)_fa; (void)_fb; (void)_fas; (void)_fbs;
    ebp = g_seh_ebp; /* fpo_leaf: inherit caller's frame */

loc_0015E740: ;
    esp = esp - 0xD8;
    PUSH32(esp, ebx);
    ebx = MEM32(esp + 0xE0);
    _fa = (uint32_t)(MEM32(ebx)) & 0xFFFFFFFFu; _fb = (uint32_t)(0xFFFFFFFFu) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb);
    PUSH32(esp, ebp);
    PUSH32(esp, esi);
    PUSH32(esp, edi);
    esi = ecx;
    if (CMP_EQ(_fa, _fb)) goto loc_0015E760;

loc_0015E758: ;
    eax = MEM32(esi);
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, ebx);
    { uint32_t _icall_target = MEM32(eax + 0x58); PUSH32(esp, 0x0015E75Eu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015E75E: ;
    goto loc_0015E765;

loc_0015E760: ;
    edx = MEM32(esi);
    { uint32_t _icall_esp = g_esp;
    { uint32_t _icall_target = MEM32(edx + 0x5C); PUSH32(esp, 0x0015E765u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015E765: ;
    edi = eax;
    ecx = edi;
    PUSH32(esp, 0x0015E76Eu);
    sub_0015CD50();

/* loc_0015E76E */
    ecx = edi;
    PUSH32(esp, 0x0015E775u);
    sub_0015CE90();

/* loc_0015E775 */
    ecx = esi + 0x50;
    edx = edi;
    PUSH32(esp, 0x0015E77Fu);
    sub_0013B8F0();

/* loc_0015E77F */
    ecx = esi + 0x90;
    edx = edi + 0x40;
    PUSH32(esp, 0x0015E78Du);
    sub_0013B8F0();

/* loc_0015E78D */
    eax = MEM32(ebx);
    MEM32(esi + 0x52C) = eax;
    eax = MEM32(edi + 0x90);
    _fa = (uint32_t)(eax) & 0xFFFFFFFFu; _fb = (uint32_t)(eax) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb);
    if (TEST_Z(_fa, _fb)) goto loc_0015E8C0;

loc_0015E7A3: ;
    ebx = MEM32(eax + 0xE8);
    ecx = MEM32(ebx + 0x2C);
    xmm0 = XMM_SCALAR(MEMF(0x29B7A8));
    MEM32(esi + 0x104) = ecx;
    edx = MEM32(ebx + 0x30);
    xmm0.f[0] = xmm0.f[0] / MEMF(esi + 0x104);
    MEM32(esi + 0x108) = edx;
    MEMF(esi + 0x10C) = xmm0.f[0];
    ecx = MEM32(edi + 0x90);
    eax = MEM32(ecx);
    MEM32(esp + 0x14) = ebx;
    { uint32_t _icall_esp = g_esp;
    { uint32_t _icall_target = MEM32(eax + 0x34); PUSH32(esp, 0x0015E7E2u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015E7E2: ;
    ebp = MEM32(esi + 0x294);
    _fa = (uint32_t)(ebp) & 0xFFFFFFFFu; _fb = (uint32_t)(ebp) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb);
    MEM32(esp + 0x48) = eax;
    MEM32(esp + 0x10) = 0;
    if (CMP_LE(_fas & _fbs, 0)) goto loc_0015E8A6;

loc_0015E7FC: ;
    ebx = esi + 0x2A7;
    ebx = ebx & 0xFFFFFFF0u;
    goto loc_0015E810;

loc_0015E810: ;
    edx = MEM32(esp + 0x48);
    PUSH32(esp, ebx);
    ecx = esp + 0x80;
    PUSH32(esp, 0x0015E821u); sub_0013C0B0();

loc_0015E821: ;
    xmm0 = XMM_SCALAR(MEMF(esp + 0x7C));
    xmm1 = XMM_SCALAR(MEMF(0x29B7AC));
    if ((xmm0.f[0] < xmm1.f[0])) goto loc_0015E867;

loc_0015E834: ;
    xmm2 = XMM_SCALAR(MEMF(0x29B7A8));
    if ((xmm2.f[0] < xmm0.f[0])) goto loc_0015E867;

loc_0015E841: ;
    xmm0 = XMM_SCALAR(MEMF(esp + 0x80));
    if ((xmm0.f[0] < xmm1.f[0])) goto loc_0015E867;

loc_0015E84F: ;
    if ((xmm2.f[0] < xmm0.f[0])) goto loc_0015E867;

loc_0015E854: ;
    xmm0 = XMM_SCALAR(MEMF(esp + 0x84));
    if ((xmm0.f[0] < xmm1.f[0])) goto loc_0015E867;

loc_0015E862: ;
    if ((xmm2.f[0] >= xmm0.f[0])) goto loc_0015E879;

loc_0015E867: ;
    eax = MEM32(esp + 0x10);
    eax++;
    ebx = ebx + 0x50;
    _fa = (uint32_t)(eax) & 0xFFFFFFFFu; _fb = (uint32_t)(ebp) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb);
    MEM32(esp + 0x10) = eax;
    if (CMP_L(_fas, _fbs)) goto loc_0015E810;

loc_0015E877: ;
    goto loc_0015E8A2;

loc_0015E879: ;
    xmm1 = XMM_SCALAR(MEMF(ebx + 0x40));
    xmm0 = XMM_ZERO();
    if ((xmm1.f[0] <= xmm0.f[0])) goto loc_0015E88F;

loc_0015E886: ;
    ecx = MEM32(ebx + 0x40);
    MEM32(esi + 0x104) = ecx;

loc_0015E88F: ;
    xmm1 = XMM_SCALAR(MEMF(ebx + 0x44));
    if ((xmm1.f[0] <= xmm0.f[0])) goto loc_0015E8A2;

loc_0015E899: ;
    edx = MEM32(ebx + 0x44);
    MEM32(esi + 0x108) = edx;

loc_0015E8A2: ;
    ebx = MEM32(esp + 0x14);

loc_0015E8A6: ;
    xmm0 = XMM_SCALAR(MEMF(ebx + 0x28));
    xmm0.f[0] = xmm0.f[0] * MEMF(0x29B720);
    PUSH32(esp, ecx);
    MEMF(esp) = xmm0.f[0];
    PUSH32(esp, 0x0015E8BEu); sub_0013B550();

loc_0015E8BE: ;
    /* fstp st(0): FPU scratch pop, no persistent global state used elsewhere in this function */

loc_0015E8C0: ;
    eax = MEM32(edi + 0xA4);
    xmm2 = XMM_ZERO();
    MEM32(esi + 0xFC) = eax;
    ecx = MEM32(edi + 0xA8);
    MEM32(esi + 0x100) = ecx;
    edx = MEM32(edi + 0x98);
    xmm1 = XMM_SCALAR(MEMF(esi + 0x100));
    MEM32(esi + 0xF8) = edx;
    eax = MEM32(edi + 0x94);
    xmm0 = xmm2;
    xmm0.f[0] = xmm0.f[0] - MEMF(esi + 0xFC);
    MEMF(esp + 0x30) = xmm0.f[0];
    MEMF(esp + 0x18) = xmm0.f[0];
    xmm0 = xmm2;
    xmm0.f[0] = xmm0.f[0] - MEMF(esi + 0x100);
    xmm2 = XMM_SCALAR(MEMF(esi + 0xFC));
    MEMF(esp + 0x1C) = xmm0.f[0];
    MEMF(esp + 0x40) = xmm0.f[0];
    xmm0 = xmm2;
    ecx = esp + 0x18;
    MEMF(esp + 0x34) = xmm1.f[0];
    xmm1 = XMM_SCALAR(MEMF(0x29B7A8));
    MEMF(esp + 0x24) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esi + 0x100));
    PUSH32(esp, ecx);
    edx = esp + 0x34;
    ecx = esp + 0x50;
    MEM32(esi + 0xF4) = eax;
    MEMF(esp + 0x3C) = xmm1.f[0];
    MEMF(esp + 0x24) = xmm1.f[0];
    MEMF(esp + 0x40) = xmm2.f[0];
    MEMF(esp + 0x48) = xmm1.f[0];
    MEMF(esp + 0x2C) = xmm0.f[0];
    MEMF(esp + 0x30) = xmm1.f[0];
    PUSH32(esp, 0x0015E986u); sub_0013A330();

loc_0015E986: ;
    ecx = esp + 0x4C;
    PUSH32(esp, 0x0015E98Fu); sub_0013A2D0();

loc_0015E98F: ;
    edx = esp + 0x3C;
    PUSH32(esp, edx);
    edx = esp + 0x1C;
    ecx = esp + 0x5C;
    PUSH32(esp, 0x0015E9A1u); sub_0013A330();

loc_0015E9A1: ;
    ecx = esp + 0x58;
    PUSH32(esp, 0x0015E9AAu); sub_0013A2D0();

loc_0015E9AA: ;
    eax = esp + 0x24;
    PUSH32(esp, eax);
    edx = esp + 0x40;
    ecx = esp + 0x68;
    PUSH32(esp, 0x0015E9BCu); sub_0013A330();

loc_0015E9BC: ;
    ecx = esp + 0x64;
    PUSH32(esp, 0x0015E9C5u); sub_0013A2D0();

loc_0015E9C5: ;
    ecx = esp + 0x30;
    PUSH32(esp, ecx);
    edx = esp + 0x28;
    ecx = esp + 0x74;
    PUSH32(esp, 0x0015E9D7u); sub_0013A330();

loc_0015E9D7: ;
    ecx = esp + 0x70;
    PUSH32(esp, 0x0015E9E0u); sub_0013A2D0();

loc_0015E9E0: ;
    xmm0 = XMM_SCALAR(MEMF(esp + 0x4C));
    MEMF(esi + 0x188) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x58));
    MEMF(esi + 0x18C) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x64));
    MEMF(esi + 0x190) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x70));
    MEMF(esi + 0x194) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x50));
    MEMF(esi + 0x198) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x5C));
    MEMF(esi + 0x19C) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x68));
    MEMF(esi + 0x1A0) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x74));
    MEMF(esi + 0x1A4) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x54));
    MEMF(esi + 0x1A8) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x60));
    MEMF(esi + 0x1AC) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x6C));
    MEMF(esi + 0x1B0) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(esp + 0x78));
    edx = MEM32(esi + 0x104);
    PUSH32(esp, edx);
    edx = esp + 0x34;
    ecx = esp + 0x8C;
    MEMF(esi + 0x1B4) = xmm0.f[0];
    PUSH32(esp, 0x0015EA9Fu); sub_00139D10();

loc_0015EA9F: ;
    eax = MEM32(esi + 0x104);
    PUSH32(esp, eax);
    edx = esp + 0x1C;
    ecx = esp + 0x98;
    PUSH32(esp, 0x0015EAB6u); sub_00139D10();

loc_0015EAB6: ;
    ecx = MEM32(esi + 0x104);
    PUSH32(esp, ecx);
    edx = esp + 0x40;
    ecx = esp + 0xA4;
    PUSH32(esp, 0x0015EACDu); sub_00139D10();

loc_0015EACD: ;
    edx = MEM32(esi + 0x104);
    PUSH32(esp, edx);
    edx = esp + 0x28;
    ecx = esp + 0xB0;
    PUSH32(esp, 0x0015EAE4u); sub_00139D10();

loc_0015EAE4: ;
    eax = MEM32(esi + 0x108);
    PUSH32(esp, eax);
    edx = esp + 0x34;
    ecx = esp + 0xBC;
    PUSH32(esp, 0x0015EAFBu); sub_00139D10();

loc_0015EAFB: ;
    ecx = MEM32(esi + 0x108);
    PUSH32(esp, ecx);
    edx = esp + 0x1C;
    ecx = esp + 0xC8;
    PUSH32(esp, 0x0015EB12u); sub_00139D10();

loc_0015EB12: ;
    edx = MEM32(esi + 0x108);
    PUSH32(esp, edx);
    edx = esp + 0x40;
    ecx = esp + 0xD4;
    PUSH32(esp, 0x0015EB29u); sub_00139D10();

loc_0015EB29: ;
    eax = MEM32(esi + 0x108);
    PUSH32(esp, eax);
    edx = esp + 0x28;
    ecx = esp + 0xE0;
    PUSH32(esp, 0x0015EB40u); sub_00139D10();

loc_0015EB40: ;
    edi = esp + 0x88;
    ebx = esi + 0x110;
    ebp = 8;

loc_0015EB52: ;
    eax = esi + 0x90;
    PUSH32(esp, eax);
    edx = edi;
    ecx = ebx;
    PUSH32(esp, 0x0015EB62u); sub_0013C0B0();

loc_0015EB62: ;
    edi = edi + 0xC;
    ebx = ebx + 0xC;
    ebp--;
    if ((ebp != 0)) goto loc_0015EB52;

loc_0015EB6B: ;
    eax = MEM32(esp + 0xEC);
    _fa = (uint32_t)(MEM32(eax)) & 0xFFFFFFFFu; _fb = (uint32_t)(0xFFFFFFFFu) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb);
    if (CMP_EQ(_fa, _fb)) goto loc_0015EC88;

loc_0015EB7B: ;
    edx = MEM32(esi);
    /* SAFETY GUARD (see comment above this function): if the object's own
     * vtable is garbage (uninitialized-memory fill pattern, matches the
     * project-wide ICALL "garbage VA" range check), this object hasn't
     * been constructed yet -- skip straight to the safe early-exit
     * epilogue instead of the unguarded dereference chain below that
     * crashes on real hardware-invalid memory. */
    if (edx >= 0x00400000u && edx < 0xFE000000u) {
        static volatile long s_skip_count;
        long n = InterlockedIncrement(&s_skip_count);
        if (n <= 20 || (n % 500) == 0)
            DAH2_TRACE_FPRINTF(stderr, "[0015E740] SKIP: garbage vtable 0x%08X on object 0x%08X (count=%ld)\n",
                    edx, esi, n);
        goto loc_0015EC88;
    }
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, eax);
    ecx = esi;
    { uint32_t _icall_target = MEM32(edx + 0x58); PUSH32(esp, 0x0015EB83u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015EB83: ;
    /* SAFETY GUARD: `eax` here is whatever the icall just above returned
     * (a "this" pointer for some per-viewport/camera object, per retail).
     * If that call's target was garbage (already-guarded above) OR it
     * resolved to a real function that legitimately returned a null/not-
     * ready object, eax can be 0 or otherwise unsafe to dereference
     * through +0x90/+0xE8 and another vtable+0x34 call. Observed in
     * practice: the object's OWN vtable can look valid while the object
     * this call returns is still not ready, reproducing the identical
     * 0xFE2Bxxxx-range crash from a different angle. Same fix: bail to
     * the safe epilogue instead of walking further garbage. */
    if (eax == 0 || (eax >= 0x00400000u && eax < 0xFE000000u)) {
        static volatile long s_skip_count2;
        long n = InterlockedIncrement(&s_skip_count2);
        if (n <= 20 || (n % 500) == 0)
            DAH2_TRACE_FPRINTF(stderr, "[0015E740] SKIP2: bad object 0x%08X from vtable+0x58 on 0x%08X (count=%ld)\n",
                    eax, esi, n);
        goto loc_0015EC88;
    }
    ecx = MEM32(eax + 0x90);
    eax = MEM32(ecx);
    edi = MEM32(ecx + 0xE8);
    /* SAFETY GUARD: `eax` (from MEM32(ecx), a sub-object pointer) is read
     * as raw floats at loc_0015EB94 right after this icall returns,
     * independent of whether the icall target itself resolves -- if THIS
     * pointer is bad (0/garbage-range), no amount of the icall succeeding
     * prevents the crash below. Same bail-to-safe-epilogue fix. */
    if (eax == 0 || (eax >= 0x00400000u && eax < 0xFE000000u)) {
        static volatile long s_skip_count3;
        long n = InterlockedIncrement(&s_skip_count3);
        if (n <= 20 || (n % 500) == 0)
            DAH2_TRACE_FPRINTF(stderr, "[0015E740] SKIP3: bad sub-object 0x%08X (ecx+0x90) on 0x%08X (count=%ld)\n",
                    eax, esi, n);
        goto loc_0015EC88;
    }
    { uint32_t _icall_esp = g_esp;
    { uint32_t _icall_target = MEM32(eax + 0x34); PUSH32(esp, 0x0015EB94u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015EB94: ;
    xmm0 = XMM_SCALAR(MEMF(eax));
    xmm1 = XMM_SCALAR(MEMF(eax + 4));
    MEMF(esi + 0x174) = xmm1.f[0];
    xmm1 = XMM_ZERO();
    MEMF(esi + 0x170) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(edi + 0x24));
    xmm0.f[0] = xmm0.f[0] - MEMF(eax + 8);
    if ((xmm1.f[0] <= xmm0.f[0])) goto loc_0015EBE1;

loc_0015EBBF: ;
    xmm0 = XMM_SCALAR(MEMF(esi + 0x164));
    xmm1 = XMM_SCALAR(MEMF(esi + 0x168));
    xmm2 = XMM_SCALAR(MEMF(esi + 0x140));
    xmm3 = XMM_SCALAR(MEMF(esi + 0x144));
    goto loc_0015EC01;

loc_0015EBE1: ;
    xmm0 = XMM_SCALAR(MEMF(esi + 0x158));
    xmm1 = XMM_SCALAR(MEMF(esi + 0x15C));
    xmm2 = XMM_SCALAR(MEMF(esi + 0x14C));
    xmm3 = XMM_SCALAR(MEMF(esi + 0x150));

loc_0015EC01: ;
    MEMF(esi + 0x17C) = xmm1.f[0];
    MEMF(esi + 0x178) = xmm0.f[0];
    MEMF(esi + 0x180) = xmm2.f[0];
    MEMF(esi + 0x184) = xmm3.f[0];
    xmm1 = XMM_SCALAR(MEMF(edi + 0x3C));
    eax = MEM32(esi + 0x528);
    xmm0 = XMM_SCALAR(MEMF(eax * 4 + 0x2B3920));
    xmm1.f[0] = xmm1.f[0] / xmm0.f[0];
    MEMF(esi + 0x280) = xmm1.f[0];
    xmm1 = XMM_SCALAR(MEMF(edi + 0x3C));
    xmm1.f[0] = xmm1.f[0] / xmm0.f[0];
    MEMF(esi + 0x290) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(0x29B7A8));
    MEMF(esi + 0x288) = xmm1.f[0];
    xmm0.f[0] = xmm0.f[0] / MEMF(eax * 4 + 0x2B3928);
    xmm1 = xmm0;
    xmm1.f[0] = xmm1.f[0] * MEMF(edi + 0x40);
    MEMF(esi + 0x284) = xmm1.f[0];
    xmm0.f[0] = xmm0.f[0] * MEMF(edi + 0x40);
    MEMF(esi + 0x28C) = xmm0.f[0];

loc_0015EC88: ;
    POP32(esp, edi);
    POP32(esp, esi);
    POP32(esp, ebp);
    POP32(esp, ebx);
    esp = esp + 0xD8;
    esp += 8; return; /* ret 4 */
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_0015C170, sub_0015E740's
 * own caller and direct sibling in the same "object not ready" crash --
 * even after guarding sub_0015E740 above, the SAME crash signature
 * (esi=0x00315330, eax=0x3F800000, ecx=0, edx=0, fault VA ~0xFE2Bxxxx)
 * still occurred, because this function has its OWN unguarded pair of
 * vtable dispatches on the very same object: loc_0015C182 ICALLs
 * MEM32(esi)+0x5C into `eax`, then (whichever of loc_0015C18E/loc_0015C1E5
 * fires) loc_0015C1A3 unconditionally dereferences `MEM32(eax+0x80)`
 * through `+0x8C` -- if the object's vtable is garbage, that first ICALL
 * gracefully returns eax=0 and this chain walks near-null/garbage memory
 * exactly like the sub_0015E740 case. Same fix: detect the garbage vtable
 * once, up front, and skip straight to this function's own normal
 * epilogue (loc_0015C31D's tail) instead of touecmhing any of the
 * vtable-derived pointers -- consistent with "object not ready this frame,
 * skip its optional setup" rather than fabricating data. Byte-for-byte
 * transcription otherwise, from src/recomp/gen/recomp_0009.c:35962-36117,
 * reusing this same file's local register-alias/macro block above. */
void sub_0015C170(void)
{
    esp = esp - 8;
    PUSH32(esp, ebx);
    PUSH32(esp, esi);
    PUSH32(esp, edi);
    edi = MEM32(esp + 0x18);
    PUSH32(esp, edi);
    esi = ecx;

    {
        uint32_t vtbl = MEM32(esi);
        if (vtbl >= 0x00400000u && vtbl < 0xFE000000u) {
            static volatile long s_skip_count;
            long n = InterlockedIncrement(&s_skip_count);
            if (n <= 20 || (n % 500) == 0)
                DAH2_TRACE_FPRINTF(stderr, "[0015C170] SKIP: garbage vtable 0x%08X on object 0x%08X (count=%ld)\n",
                        vtbl, esi, n);
            POP32(esp, edi);
            POP32(esp, esi);
            POP32(esp, ebx);
            esp = esp + 8;
            esp += 8; return; /* ret 4 */
        }
    }

    PUSH32(esp, 0x0015C182u); sub_0015E740();

loc_0015C182: ;
    eax = MEM32(esi);
    ecx = esi;
    { uint32_t _icall_esp = g_esp;
    { uint32_t _icall_target = MEM32(eax + 0x5C); PUSH32(esp, 0x0015C189u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015C189: ;
    if (MEM32(edi) == 0xFFFFFFFFu) goto loc_0015C1E5;

loc_0015C18E: ;
    ecx = MEM32(0x2CB8DC);
    MEM8(ecx + 0x94) = 1;
    edx = MEM32(esi);
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, edi);
    ecx = esi;
    { uint32_t _icall_target = MEM32(edx + 0x58); PUSH32(esp, 0x0015C1A3u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015C1A3: ;
    edx = MEM32(eax + 0x80);
    xmm0 = XMM_ZERO();
    ecx = eax + 0xC0;
    MEM32(ecx) = edx;
    edx = MEM32(eax + 0x84);
    MEM32(ecx + 4) = edx;
    edx = MEM32(eax + 0x88);
    MEM32(ecx + 8) = edx;
    eax = MEM32(eax + 0x8C);
    MEMF(ecx + 0x10) = xmm0.f[0];
    xmm0 = XMM_SCALAR(MEMF(0x29B7A8));
    MEM32(ecx + 0xC) = eax;
    MEMF(ecx + 0x14) = xmm0.f[0];
    eax = ecx;
    goto loc_0015C1F1;

loc_0015C1E5: ;
    edx = MEM32(esi);
    ecx = esi;
    { uint32_t _icall_esp = g_esp;
    { uint32_t _icall_target = MEM32(edx + 0x5C); PUSH32(esp, 0x0015C1ECu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015C1EC: ;
    eax = eax + 0xC0;

loc_0015C1F1: ;
    ecx = MEM32(0x2CB8DC);
    SET_LO8(edx, MEM8(ecx + 0xA0));
    xmm0 = XMM_SCALAR(MEMF(0x2B1BAC));
    SET_LO8(edx, LO8(edx) + 1);
    MEM8(ecx + 0xA0) = LO8(edx);
    ecx = MEM32(0x2CB8DC);
    edi = MEM32(ecx + 0xD8);
    edx = MEM32(ecx + 0xD4);
    ebx = MEM32(ecx + 0xD8);
    edx = edi + edx * 4;
    edi = MEM32(ecx + 0xD4);
    MEM32(ebx + edi * 4) = 0x571FF221;
    edi = MEM32(ecx + 0xD4);
    ebx = MEM32(ecx + 0xD8);
    MEM32(ebx + edi * 4 + 4) = eax;
    eax = MEM32(ecx + 0xD4);
    edi = MEM32(ecx + 0xD8);
    MEMF(esp + 0x18) = xmm0.f[0];
    ebx = MEM32(esp + 0x18);
    MEM32(edi + eax * 4 + 8) = ebx;
    MEM32(ecx + 0xD4) = MEM32(ecx + 0xD4) + 3;
    ecx = MEM32(0x2CB8DC);
    edi = MEM32(ecx + 0xD4);
    eax = ecx + 0xD4;
    ecx = MEM32(ecx + 0xD8);
    MEM32(ecx + edi * 4) = 0x342BF109;
    MEM32(eax) = MEM32(eax) + 1;
    eax = MEM32(0x2CB8DC);
    PUSH32(esp, 0);
    ecx = esi + 0x6AC;
    MEM32(eax + 0x48) = edx;
    PUSH32(esp, ecx);
    ecx = MEM32(0x2CB8DC);
    PUSH32(esp, 0x0015C2A3u); sub_0016E410();

loc_0015C2A3: ;
    ecx = MEM32(0x2CB8DC);
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0x0015C2BAu); sub_0015B160();

loc_0015C2BA: ;
    edx = MEM32(0x2CB8DC);
    MEM32(edx + 0x48) = 0;
    xmm1 = XMM_SCALAR(MEMF(esi + 0x108));
    xmm1.f[0] = xmm1.f[0] - MEMF(esi + 0x104);
    xmm0 = XMM_SCALAR(MEMF(esi + 0x108));
    xmm0.f[0] = xmm0.f[0] / xmm1.f[0];
    xmm1 = XMM_SCALAR(MEMF(0x29B7A8));
    MEMF(esp + 0x10) = xmm0.f[0];
    xmm0 = xmm1;
    xmm0.f[0] = xmm0.f[0] / MEMF(esi + 0xFC);
    MEMF(esp + 0x18) = xmm0.f[0];
    xmm0 = xmm1;
    xmm0.f[0] = xmm0.f[0] / MEMF(esi + 0x100);
    edi = esi + 0x10;
    ecx = edi;
    MEMF(esp + 0xC) = xmm0.f[0];
    PUSH32(esp, 0x0015C31Du); sub_0013B890();

loc_0015C31D: ;
    xmm0 = XMM_ZERO();
    xmm2 = XMM_SCALAR(MEMF(esi + 0x104));
    xmm1 = xmm0;
    xmm1.f[0] = xmm1.f[0] - MEMF(esp + 0x18);
    MEMF(edi) = xmm1.f[0];
    xmm1 = XMM_SCALAR(MEMF(esp + 0xC));
    MEMF(esi + 0x24) = xmm1.f[0];
    xmm1 = XMM_SCALAR(MEMF(esp + 0x10));
    MEMF(esi + 0x38) = xmm1.f[0];
    xmm2.f[0] = xmm2.f[0] * xmm1.f[0];
    xmm1 = xmm0;
    xmm1.f[0] = xmm1.f[0] - xmm2.f[0];
    MEMF(esi + 0x48) = xmm1.f[0];
    xmm1 = XMM_SCALAR(MEMF(0x29B7A8));
    MEMF(esi + 0x3C) = xmm1.f[0];
    MEMF(esi + 0x4C) = xmm0.f[0];
    MEM32(esi + 0x65C) = 0x901;
    POP32(esp, edi);
    POP32(esp, esi);
    POP32(esp, ebx);
    esp = esp + 8;
    esp += 8; return; /* ret 4 */
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_0015ECA0, purely for
 * tracing -- this function loops over MEM32(esi+0x524) records on the
 * SAME "esi" object, dispatching up to several vtable calls per record
 * (offsets 0, 4, 0x58 on esi's own vtable, plus a couple through
 * MEM32(esi+0x278)'s vtable). The current crash (a genuinely different
 * signature than the sub_0015E740/sub_0015C170 "vtable echoes its own
 * address" pattern -- eax=0xD0F62928, not 0x04000xxx-shaped) happens
 * somewhere further down this exact chain (sub_00115120 ->
 * sub_0015ECA0 -> ...). No behavior changes here: every ICALL uses the
 * shared RECOMP_ICALL_SAFE macro above, which now logs target/ecx via
 * g_manual_transplant_icall_trace, letting the crash log show exactly
 * which numbered call site (by source line) was last attempted before
 * the crash. Byte-for-byte transcription from
 * src/recomp/gen/recomp_0009.c:41812-42024. */
void sub_0015ECA0(void)
{
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, ecx);
    PUSH32(esp, esi);
    esi = ecx;
    eax = MEM32(esi);
    PUSH32(esp, 0x2CA6BC);
    { uint32_t _icall_target = MEM32(eax); PUSH32(esp, 0x0015ECADu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015ECAD: ;
    eax = MEM32(esi + 0x278);
    if (eax != 0) {
        edx = MEM32(esi);
        { uint32_t _icall_esp = g_esp;
        PUSH32(esp, 0);
        ecx = esi;
        { uint32_t _icall_target = MEM32(edx + 4); PUSH32(esp, 0x0015ECC0u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
        }

    loc_0015ECC0: ;
        ecx = MEM32(esi + 0x278);
        eax = MEM32(ecx);
        { uint32_t _icall_esp = g_esp;
        PUSH32(esp, 0x2CA6BC);
        PUSH32(esp, 0);
        { uint32_t _icall_target = MEM32(eax); PUSH32(esp, 0x0015ECD1u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
        }
    }

loc_0015ECD1: ;
    eax = MEM32(esi + 0x524);
    MEM32(esp + 4) = 0;
    if (!CMP_BE(eax, 0)) {
        do {
        loc_0015ECE7: ;
            edx = MEM32(esi);
            eax = esp + 4;
            { uint32_t _icall_esp = g_esp;
            PUSH32(esp, eax);
            ecx = esi;
            { uint32_t _icall_target = MEM32(edx + 0x58); PUSH32(esp, 0x0015ECF3u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
            }

        loc_0015ECF3: ;
            ecx = MEM8(eax + 0xAC);
            if (LO8(ecx) != 0) {
                edx = MEM32(esi);
                eax = esp + 4;
                { uint32_t _icall_esp = g_esp;
                PUSH32(esp, eax);
                ecx = esi;
                { uint32_t _icall_target = MEM32(edx); PUSH32(esp, 0x0015ED0Cu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                }

            loc_0015ED0C: ;
                eax = MEM32(esi + 0x278);
                if (eax != 0) {
                    edx = MEM32(esi);
                    { uint32_t _icall_esp = g_esp;
                    PUSH32(esp, 1);
                    ecx = esi;
                    { uint32_t _icall_target = MEM32(edx + 4); PUSH32(esp, 0x0015ED1Fu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                    }

                loc_0015ED1F: ;
                    ecx = MEM32(esi + 0x278);
                    eax = MEM32(ecx);
                    edx = esp + 4;
                    { uint32_t _icall_esp = g_esp;
                    PUSH32(esp, edx);
                    PUSH32(esp, 0);
                    { uint32_t _icall_target = MEM32(eax); PUSH32(esp, 0x0015ED30u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                    }
                }

            loc_0015ED30: ;
                eax = MEM32(esi + 0xEC);
                if (eax != 0) {
                    eax = MEM32(esi);
                    ecx = esp + 4;
                    { uint32_t _icall_esp = g_esp;
                    PUSH32(esp, ecx);
                    ecx = esi;
                    { uint32_t _icall_target = MEM32(eax + 0x58); PUSH32(esp, 0x0015ED46u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                    }

                loc_0015ED46: ;
                    ecx = MEM8(eax + 0xAD);
                    if (LO8(ecx) != 0) {
                        edx = MEM32(esi);
                        { uint32_t _icall_esp = g_esp;
                        PUSH32(esp, 2);
                        ecx = esi;
                        { uint32_t _icall_target = MEM32(edx + 4); PUSH32(esp, 0x0015ED59u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                        }

                    loc_0015ED59: ;
                        ecx = MEM32(esi + 0xEC);
                        PUSH32(esp, 0x0015ED64u);
                        sub_00177FB0();
                    }
                }

            loc_0015ED64: ;
                ecx = MEM32(esi + 0x278);
                if (ecx != 0) {
                    eax = MEM32(ecx);
                    edx = esp + 4;
                    { uint32_t _icall_esp = g_esp;
                    PUSH32(esp, edx);
                    PUSH32(esp, 1);
                    { uint32_t _icall_target = MEM32(eax); PUSH32(esp, 0x0015ED79u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                    }
                }
            }

        loc_0015ED79: ;
            eax = MEM32(esi + 0x278);
            if (eax != 0) {
                eax = MEM32(esi);
                { uint32_t _icall_esp = g_esp;
                PUSH32(esp, 3);
                ecx = esi;
                { uint32_t _icall_target = MEM32(eax + 4); PUSH32(esp, 0x0015ED8Cu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                }

            loc_0015ED8C: ;
                ecx = MEM32(esi + 0x278);
                edx = MEM32(ecx);
                eax = esp + 4;
                { uint32_t _icall_esp = g_esp;
                PUSH32(esp, eax);
                PUSH32(esp, 2);
                { uint32_t _icall_target = MEM32(edx); PUSH32(esp, 0x0015ED9Du); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
                }
            }

        loc_0015ED9D: ;
            eax = MEM32(esp + 4);
            ecx = MEM32(esi + 0x524);
            eax++;
            MEM32(esp + 4) = eax;
        } while (CMP_B(eax, ecx));
    }

loc_0015EDB4: ;
    edx = MEM32(esi);
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, 0x2CA6BC);
    ecx = esi;
    { uint32_t _icall_target = MEM32(edx); PUSH32(esp, 0x0015EDBFu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
    }

loc_0015EDBF: ;
    eax = MEM32(esi + 0x278);
    if (eax != 0) {
        eax = MEM32(esi);
        { uint32_t _icall_esp = g_esp;
        PUSH32(esp, 4);
        ecx = esi;
        { uint32_t _icall_target = MEM32(eax + 4); PUSH32(esp, 0x0015EDD2u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
        }

    loc_0015EDD2: ;
        ecx = MEM32(esi + 0x278);
        edx = MEM32(ecx);
        { uint32_t _icall_esp = g_esp;
        PUSH32(esp, 0x2CA6BC);
        PUSH32(esp, 2);
        { uint32_t _icall_target = MEM32(edx); PUSH32(esp, 0x0015EDE3u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); }
        }
    }

loc_0015EDE3: ;
    MEM32(esi + 0xD4) = MEM32(esi + 0xD4) + 1;
    POP32(esp, esi);
    POP32(esp, ecx);
    esp += 4; return; /* ret */
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_001A7C80, purely for
 * tracing esi across its 4 by-name calls. Reached via the script VM's
 * SCRIPT-CALL dispatcher (sub_002117C0 above) with the correct
 * esi=8038E3B4 (the main Lua context), but by the time execution reaches
 * sub_002170A0 (the [LUA-INTERN] trace, several calls deeper) ecx is 0 --
 * meaning something in this call's descendants loses the context. No
 * behavior change: byte-for-byte transcription from
 * src/recomp/gen/recomp_0011.c:24738-24771, with an fprintf bracketing
 * each nested call. */
extern void sub_001AF400(void);
extern void sub_0013E8A0(void);
extern void sub_001A7920(void);
extern void sub_001AEEA0(void);
extern void sub_001A7FF0(void);
extern void sub_001A86E0(void);
extern void sub_001A84F0(void);

void sub_001A7C80(void)
{
    esp = esp - 0x108;
    PUSH32(esp, esi);
    PUSH32(esp, 1);
    esi = ecx;
    MEM8(esp + 0xC) = 0;
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] pre sub_001AF400 esi=0x%08X\n", esi);
    PUSH32(esp, 0x001A7C95u); sub_001AF400();
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] post sub_001AF400 esi=0x%08X eax=0x%08X\n", esi, eax);

loc_001A7C95: ;
    edx = esp + 8;
    ecx = eax;
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] pre sub_0013E8A0 esi=0x%08X ecx=0x%08X\n", esi, ecx);
    PUSH32(esp, 0x001A7CA0u); sub_0013E8A0();
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] post sub_0013E8A0 esi=0x%08X eax=0x%08X\n", esi, eax);

loc_001A7CA0: ;
    ecx = esp + 8;
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] pre sub_001A7920 esi=0x%08X ecx=0x%08X\n", esi, ecx);
    PUSH32(esp, 0x001A7CA9u); sub_001A7920();
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] post sub_001A7920 esi=0x%08X eax=0x%08X\n", esi, eax);

loc_001A7CA9: ;
    MEM8(esp + 4) = LO8(eax);
    eax = MEM32(esp + 4);
    PUSH32(esp, eax);
    ecx = esi;
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] pre sub_001AEEA0 esi=0x%08X ecx=0x%08X eax=0x%08X\n", esi, ecx, eax);
    PUSH32(esp, 0x001A7CB9u); sub_001AEEA0();
    DAH2_TRACE_FPRINTF(stderr, "[001A7C80] post sub_001AEEA0 esi=0x%08X eax=0x%08X\n", esi, eax);

loc_001A7CB9: ;
    eax = 1;
    POP32(esp, esi);
    esp = esp + 0x108;
    esp += 4; return; /* ret */
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_00252410, purely for
 * tracing. This is the "origin" caller (per the existing
 * MmAllocateContiguousMemoryEx kernel-bridge trace) of the ~2GB
 * allocation request that crashes the movie/Bink loader after frame 196.
 * It calls sub_000FB0A1 twice with a size-like value; the second call
 * passes `edi` (the return value of sub_002566D0, a 10-param buffer-sizing
 * helper) which is suspected to be garbage. No behavior change:
 * byte-for-byte transcription from src/recomp/gen/recomp_0014.c:14481-
 * 14566, with two fprintf calls added around the second sub_000FB0A1
 * call to see the actual `edi` value and the incoming format parameter. */
extern void sub_002566D0(void);
extern void sub_000FB0A1(void);
extern void sub_000FB141(void);
static volatile long g_call_count_252410;
void sub_00252410(void)
{
    long _n = InterlockedIncrement(&g_call_count_252410);
    int _trace = (_n <= 20 || (_n % 5000) == 0);
    PUSH32(esp, esi);
    PUSH32(esp, edi);
    edx = 0;
    eax = esp + 0x20;
    PUSH32(esp, eax);
    eax = MEM32(esp + 0x28);
    if (_trace)
        DAH2_TRACE_FPRINTF(stderr, "[00252410] #%ld ENTER format_param(MEM32(esp+0x28))=0x%08X\n", _n, eax);
    SET_LO8(edx, (CMP_EQ(eax, 4)) ? 1 : 0);
    ecx = esp + 0x28;
    PUSH32(esp, ecx);
    ecx = 0;
    SET_LO8(ecx, (CMP_EQ(eax, 5)) ? 1 : 0);
    eax = MEM32(esp + 0x20);
    PUSH32(esp, edx);
    edx = MEM32(esp + 0x2C);
    PUSH32(esp, ecx);
    ecx = MEM32(esp + 0x24);
    PUSH32(esp, 0);
    PUSH32(esp, edx);
    edx = MEM32(esp + 0x28);
    PUSH32(esp, eax);
    eax = MEM32(esp + 0x28);
    PUSH32(esp, ecx);
    PUSH32(esp, edx);
    PUSH32(esp, eax);
    PUSH32(esp, 0x00252452u);
    sub_002566D0();

loc_00252452: ;
    edi = eax;
    if (_trace)
        DAH2_TRACE_FPRINTF(stderr, "[00252410] #%ld post sub_002566D0 edi=0x%08X (=%u)\n", _n, edi, edi);
    if (TEST_Z(MEM32(esp + 0x1C), 0x10000)) {
        /* fallthrough */
    } else {
        MEM32(esp + 0x24) = MEM32(esp + 0x24) & 0xFFFFFFF7u;
    }

loc_00252463: ;
    PUSH32(esp, 0x64800000);
    PUSH32(esp, 0x14);
    PUSH32(esp, 0x0025246Fu);
    sub_000FB0A1();

loc_0025246F: ;
    esi = eax;
    if (esi != 0) {
        if (_trace)
            DAH2_TRACE_FPRINTF(stderr, "[00252410] #%ld pre 2nd sub_000FB0A1 edi=0x%08X\n", _n, edi);
        PUSH32(esp, 0xB7800000u);
        PUSH32(esp, edi);
        PUSH32(esp, 0x00252480u);
        sub_000FB0A1();
        if (_trace)
            DAH2_TRACE_FPRINTF(stderr, "[00252410] #%ld post 2nd sub_000FB0A1 eax=0x%08X\n", _n, eax);

    loc_00252480: ;
        if (eax != 0) {
            /* loc_00252496: allocation succeeded -- fill the descriptor
             * struct at esi and return it (NOT the common 0-return exit). */
            eax = eax & 0xFFFFFFF;
            MEM32(esi + 4) = eax;
            MEM32(esi) = 0x1040001;
            ecx = MEM32(esp + 0x24);
            MEM32(esi + 0xC) = ecx;
            edx = MEM32(esp + 0x20);
            POP32(esp, edi);
            MEM32(esi + 0x10) = edx;
            MEM32(esi + 8) = 0;
            eax = esi;
            POP32(esp, esi);
            esp += 32; return; /* ret 28 */
        }

        /* loc_00252484 */
        PUSH32(esp, 0x24800000);
        PUSH32(esp, esi);
        PUSH32(esp, 0x0025248Fu);
        sub_000FB141();
    }

loc_0025248F: ;
    POP32(esp, edi);
    eax = 0;
    POP32(esp, esi);
    esp += 32; return; /* ret 28 */
}

/* XPhysicalAlloc wrapper, verified against retail 000FCB03..000FCB46.
 * Both calls must push their real guest return address: the kernel bridge
 * consumes it before reading the five arguments, and the failure helper
 * consumes it in RET 4. Omitting it shifts every kernel argument and also
 * corrupts the caller's saved registers/stack by one dword per allocation.
 * This definition wins over the generated body via /FORCE:MULTIPLE. */
extern void sub_000FAFD5(void);
extern __declspec(thread) uint32_t g_ebp;
static volatile long g_call_count_FCB03;
void sub_000FCB03(void)
{
    uint32_t ebp = g_ebp;
    long _n = InterlockedIncrement(&g_call_count_FCB03);
    int _trace = (_n <= 20 || (_n % 50000) == 0);
    PUSH32(esp, ebp);
    ebp = esp;
    g_ebp = ebp;
    eax = MEM32(ebp + 0xC);
    ecx = MEM32(ebp + 8);
    if (_trace)
        DAH2_TRACE_FPRINTF(stderr, "[000FCB03] #%ld ENTER arg@ebp+0xC=0x%08X arg@ebp+8=0x%08X arg@ebp+0x10=0x%08X arg@ebp+0x14=0x%08X\n",
                _n, eax, ecx, MEM32(ebp + 0x10), MEM32(ebp + 0x14));
    if (eax == 0xFFFFFFFFu) {
        edx = 0;
        eax = eax | 0xFFFFFFFFu;
    } else {
        MEM32(ebp + 0x10) = MEM32(ebp + 0x10) & 0;
        edx = eax;
        eax = ecx + eax + (uint32_t)-1;
    }
    {
        uint32_t _icall_esp = g_esp;
        PUSH32(esp, esi);
        PUSH32(esp, MEM32(ebp + 0x14));
        PUSH32(esp, MEM32(ebp + 0x10));
        PUSH32(esp, eax);
        PUSH32(esp, edx);
        PUSH32(esp, ecx);
        uint32_t _icall_target = MEM32(0x29B5E0);
        PUSH32(esp, 0x000FCB32u);
        RECOMP_ICALL_SAFE(_icall_target, _icall_esp);
    }
    if (_trace)
        DAH2_TRACE_FPRINTF(stderr, "[000FCB03] #%ld post-icall eax=0x%08X\n", _n, eax);
    esi = eax;
    if (esi == 0) {
        PUSH32(esp, 8);
        g_ebp = ebp;
        PUSH32(esp, 0x000FCB3Fu);
        sub_000FAFD5();
    }
    eax = esi;
    POP32(esp, esi);
    POP32(esp, ebp);
    g_ebp = ebp;
    esp += 20; return; /* ret 16 */
}

/* Retail contiguous-capacity probe, verified against 001397F0..00139831.
 * The earlier transplant omitted all four allocation arguments and both
 * call return addresses, so it consumed its own caller's frame instead of
 * probing memory. Restore those instructions and retail's natural failure
 * termination; the old 64-iteration cap could truncate a valid search. */
extern void sub_000FCB73(void);
void sub_001397F0(void)
{
    long _iter = 0;
    PUSH32(esp, esi);
    PUSH32(esp, edi);
    edi = 0;

loc_001397F4: ;
    esi = 1;

loc_00139800: ;
    _iter++;
    PUSH32(esp, 4);
    PUSH32(esp, 0x1000);
    esi = esi + esi;
    PUSH32(esp, 0xFFFFFFFFu);
    eax = edi + esi;
    PUSH32(esp, eax);
    if (_iter <= 40)
        DAH2_TRACE_FPRINTF(stderr, "[001397F0] iter=%ld edi=0x%08X esi=0x%08X eax(size)=0x%08X\n", _iter, edi, esi, eax);
    PUSH32(esp, 0x00139814u);
    sub_000FCB03();

loc_00139814: ;
    if (eax != 0) {
        PUSH32(esp, eax);
        PUSH32(esp, 0x00139829u);
        sub_000FCB73();
        goto loc_00139800;
    }

    /* failure/backoff path */
    esi = esi >> 1;
    if (CMP_BE(esi, 1)) goto loc_0013982B;
    edi = edi + esi;
    goto loc_001397F4;

loc_0013982B: ;
    eax = edi + esi;
    POP32(esp, edi);
    POP32(esp, esi);
    esp += 4; return; /* ret */
}

/* TEMP: full /FORCE:MULTIPLE transplant of sub_001A7920, purely for
 * tracing -- pinpointed via sub_001A7C80's own trace as the exact call
 * that corrupts esi (0x8038E3B4 -> 0xFFFFFFFF) and, since esi is
 * restored via a plain stack POP32 at every one of this function's exit
 * points, the real cause must be a stack imbalance introduced by one of
 * its own nested by-name calls (sub_001A86E0/sub_001A7FF0/sub_001A84F0).
 * No behavior change: byte-for-byte transcription from
 * src/recomp/gen/recomp_0011.c:24076-24124, with fprintf around the
 * conditional dispatch to see exactly which path executes and what esp
 * looks like immediately before/after each nested call. */
void sub_001A7920(void)
{
    dah2_parity_checkpoint("title_update_entry", 0x1A7920u, g_ebp, 64);
    uint32_t esp_before_push_esi = esp;
    PUSH32(esp, esi);
    esi = ecx;
    DAH2_TRACE_FPRINTF(stderr, "[001A7920] ENTER MEM32(0x31D9BC)=%u esi=0x%08X esp_before=0x%08X esp_after_push=0x%08X\n",
            MEM32(0x31D9BC), esi, esp_before_push_esi, esp);

    if (MEM32(0x31D9BC) != 1) {
        DAH2_TRACE_FPRINTF(stderr, "[001A7920] pre sub_001A7FF0 esp=0x%08X\n", esp);
        PUSH32(esp, 0x001A7938u); sub_001A7FF0();
        DAH2_TRACE_FPRINTF(stderr, "[001A7920] post sub_001A7FF0 esp=0x%08X eax=0x%08X\n", esp, eax);
    } else {
        DAH2_TRACE_FPRINTF(stderr, "[001A7920] pre sub_001A86E0 esp=0x%08X\n", esp);
        PUSH32(esp, 0x001A7931u); sub_001A86E0();
        DAH2_TRACE_FPRINTF(stderr, "[001A7920] post sub_001A86E0 esp=0x%08X eax=0x%08X\n", esp, eax);
    }

    if (LO8(eax) == 0) {
        ecx = esi;
        DAH2_TRACE_FPRINTF(stderr, "[001A7920] pre sub_001A84F0 esp=0x%08X ecx=0x%08X\n", esp, ecx);
        PUSH32(esp, 0x001A7943u); sub_001A84F0();
        DAH2_TRACE_FPRINTF(stderr, "[001A7920] post sub_001A84F0 esp=0x%08X eax=0x%08X\n", esp, eax);
        if (LO8(eax) == 0) {
            SET_LO8(eax, 0);
            DAH2_TRACE_FPRINTF(stderr, "[001A7920] EXIT path A esp_before_pop=0x%08X\n", esp);
            POP32(esp, esi);
            DAH2_TRACE_FPRINTF(stderr, "[001A7920] EXIT path A esi_popped=0x%08X esp_after=0x%08X\n", esi, esp);
            esp += 4; return;
        }
    }

    dah2_parity_checkpoint("title_ready_commit", 0x1A794Bu, g_ebp, 256);
    MEM8(0x31D9B8) = MEM8(0x31D9B8) | 1;
    MEM32(0x31D9BC) = 2;
    SET_LO8(eax, 1);
    DAH2_TRACE_FPRINTF(stderr, "[001A7920] EXIT path B esp_before_pop=0x%08X\n", esp);
    POP32(esp, esi);
    DAH2_TRACE_FPRINTF(stderr, "[001A7920] EXIT path B esi_popped=0x%08X esp_after=0x%08X\n", esi, esp);
    esp += 4; return;
}

/* Retail title-surface removal callback recovered from 0x001A7E30-0x001A7EAF.
 * It is registered beside sub_001A7EB0 and removes the matching 16-byte
 * descriptor from the title renderer vector before releasing its surface. */
extern void sub_000D5A50(void);
extern void sub_001552D0(void);
void sub_001A7E30(void)
{
    int _flags = 0; /* fallback flag var */
    uint32_t _fa = 0, _fb = 0;
    int32_t _fas = 0, _fbs = 0;
    (void)_flags; (void)_fa; (void)_fb; (void)_fas; (void)_fbs;

loc_001A7E30: ;
    PUSH32(esp, esi);
    PUSH32(esp, 0x001A7E36u); sub_001552D0(); /* call 0x001552D0 */

loc_001A7E36: ;
    esi = eax;
    _fa = (uint32_t)(esi) & 0xFFFFFFFFu; _fb = (uint32_t)(esi) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb); /* test esi, esi (32-bit) */
    if (TEST_Z(_fa, _fb)) goto loc_001A7E4F; /* je: equal / zero */

loc_001A7E3C: ;
    eax = MEM32(esi);
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, 0xE60EE861u);
    ecx = esi;
    { uint32_t _icall_target = MEM32(eax); PUSH32(esp, 0x001A7E47u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); } /* indirect call */
    }

loc_001A7E47: ;
    _fa = (uint32_t)(LO8(eax)) & 0xFFu; _fb = (uint32_t)(LO8(eax)) & 0xFFu;
    _fas = (int32_t)(int8_t)(_fa); _fbs = (int32_t)(int8_t)(_fb); /* test LO8(eax), LO8(eax) (8-bit) */
    if (TEST_Z(_fa, _fb)) goto loc_001A7E4F; /* je: equal / zero */

loc_001A7E4B: ;
    eax = esi;
    goto loc_001A7E51;

loc_001A7E4F: ;
    eax = 0; /* xor self */

loc_001A7E51: ;
    eax = MEM32(eax + 0x7E18);
    ecx = MEM32(eax + 0x478);
    edx = MEM32(0x31D9D0);
    eax = 0x31D9D7;
    eax = eax & 0xFFFFFFFCu;
    edx = edx << 4;
    esi = edx + eax;
    _fa = (uint32_t)(eax) & 0xFFFFFFFFu; _fb = (uint32_t)(esi) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb); /* cmp eax, esi (32-bit) */
    if (CMP_EQ(_fa, _fb)) goto loc_001A7E8F; /* je: equal / zero */

loc_001A7E75: ;
    edx = MEM32(esp + 8);
    /* nop */

loc_001A7E80: ;
    _fa = (uint32_t)(MEM32(eax)) & 0xFFFFFFFFu; _fb = (uint32_t)(edx) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb); /* cmp MEM32(eax), edx (32-bit) */
    if (CMP_EQ(_fa, _fb)) goto loc_001A7E8D; /* je: equal / zero */

loc_001A7E84: ;
    eax = eax + 0x10;
    _fa = (uint32_t)(eax) & 0xFFFFFFFFu; _fb = (uint32_t)(esi) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb); /* cmp eax, esi (32-bit) */
    if (CMP_NE(_fa, _fb)) goto loc_001A7E80; /* jne: not equal / not zero */

loc_001A7E8B: ;
    goto loc_001A7E8F;

loc_001A7E8D: ;
    esi = eax;

loc_001A7E8F: ;
    eax = MEM32(ecx);
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, esi);
    { uint32_t _icall_target = MEM32(eax + 4); PUSH32(esp, 0x001A7E95u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); } /* indirect call */
    }

loc_001A7E95: ;
    PUSH32(esp, ecx);
    ecx = esp;
    eax = esi + 0x10;
    MEM32(ecx) = eax;
    PUSH32(esp, ecx);
    eax = esp;
    ecx = 0x31D9D0;
    MEM32(eax) = esi;
    PUSH32(esp, 0x001A7EACu); sub_000D5A50(); /* call 0x000D5A50 */

loc_001A7EAC: ;
    POP32(esp, esi);
    esp += 8; return; /* ret 4 */

}

/* Retail title-surface callback recovered from 0x001A7EB0-0x001A7F60.
 * Registered indirectly by sub_001A7F70; appends a 16-byte movie surface
 * descriptor to the title renderer vector at 0x31D9D0. */
extern void sub_001552D0(void);
extern void sub_00155860(void);
extern void sub_000D5940(void);
void sub_001A7EB0(void)
{
    int _flags = 0; /* fallback flag var */
    uint32_t _fa = 0, _fb = 0;
    int32_t _fas = 0, _fbs = 0;
    (void)_flags; (void)_fa; (void)_fb; (void)_fas; (void)_fbs;

loc_001A7EB0: ;
    esp = esp - 0x10;
    PUSH32(esp, esi);
    PUSH32(esp, edi);
    PUSH32(esp, 0x001A7EBAu); sub_001552D0(); /* call 0x001552D0 */

loc_001A7EBA: ;
    esi = eax;
    _fa = (uint32_t)(esi) & 0xFFFFFFFFu; _fb = (uint32_t)(esi) & 0xFFFFFFFFu;
    _fas = (int32_t)(int32_t)(_fa); _fbs = (int32_t)(int32_t)(_fb); /* test esi, esi (32-bit) */
    if (TEST_Z(_fa, _fb)) goto loc_001A7ED3; /* je: equal / zero */

loc_001A7EC0: ;
    eax = MEM32(esi);
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, 0xE60EE861u);
    ecx = esi;
    { uint32_t _icall_target = MEM32(eax); PUSH32(esp, 0x001A7ECBu); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); } /* indirect call */
    }

loc_001A7ECB: ;
    _fa = (uint32_t)(LO8(eax)) & 0xFFu; _fb = (uint32_t)(LO8(eax)) & 0xFFu;
    _fas = (int32_t)(int8_t)(_fa); _fbs = (int32_t)(int8_t)(_fb); /* test LO8(eax), LO8(eax) (8-bit) */
    if (TEST_Z(_fa, _fb)) goto loc_001A7ED3; /* je: equal / zero */

loc_001A7ECF: ;
    eax = esi;
    goto loc_001A7ED5;

loc_001A7ED3: ;
    eax = 0; /* xor self */

loc_001A7ED5: ;
    eax = MEM32(eax + 0x7E18);
    esi = MEM32(eax + 0x478);
    edi = MEM32(esp + 0x1C);
    PUSH32(esp, edi);
    ecx = esi;
    PUSH32(esp, 0x001A7EEDu); sub_00155860(); /* call 0x00155860 */

loc_001A7EED: ;
    _fa = (uint32_t)(LO8(eax)) & 0xFFu; _fb = (uint32_t)(LO8(eax)) & 0xFFu;
    _fas = (int32_t)(int8_t)(_fa); _fbs = (int32_t)(int8_t)(_fb); /* test LO8(eax), LO8(eax) (8-bit) */
    if (TEST_NZ(_fa, _fb)) goto loc_001A7EFB; /* jne: not equal / not zero */

loc_001A7EF1: ;
    eax = 0; /* xor self */
    POP32(esp, edi);
    POP32(esp, esi);
    esp = esp + 0x10;
    esp += 8; return; /* ret 4 */

loc_001A7EFB: ;
    edx = MEM32(esi);
    { uint32_t _icall_esp = g_esp;
    PUSH32(esp, edi);
    eax = esp + 0xC;
    PUSH32(esp, eax);
    ecx = esi;
    { uint32_t _icall_target = MEM32(edx); PUSH32(esp, 0x001A7F07u); RECOMP_ICALL_SAFE(_icall_target, _icall_esp); } /* indirect call */
    }

loc_001A7F07: ;
    eax = MEM32(0x31D9D0);
    PUSH32(esp, ecx);
    edi = 0x31D9D7;
    eax = eax << 4;
    ecx = esp;
    edi = edi & 0xFFFFFFFCu;
    eax = eax + edi;
    MEM32(ecx) = eax;
    PUSH32(esp, ecx);
    esi = eax;
    ecx = esp;
    eax = eax + 0x10;
    MEM32(ecx) = eax;
    esi = esi - edi;
    ecx = 0x31D9D0;
    esi = (uint32_t)((int32_t)esi >> 4);
    PUSH32(esp, 0x001A7F37u); sub_000D5940(); /* call 0x000D5940 */

loc_001A7F37: ;
    eax = MEM32(esp + 8);
    esi = esi << 4;
    esi = esi + edi;
    if ((esi == 0)) goto loc_001A7F59; /* je: equal / zero */

loc_001A7F42: ;
    ecx = MEM32(esp + 0xC);
    edx = MEM32(esp + 0x10);
    MEM32(esi) = eax;
    MEM32(esi + 4) = ecx;
    ecx = MEM32(esp + 0x14);
    MEM32(esi + 8) = edx;
    MEM32(esi + 0xC) = ecx;

loc_001A7F59: ;
    POP32(esp, edi);
    POP32(esp, esi);
    esp = esp + 0x10;
    esp += 8; return; /* ret 4 */

}

#undef eax
#undef ecx
#undef edx
#undef esp
#undef ebx
#undef esi
#undef edi
#undef xmm0
#undef xmm1
#undef xmm2
#undef xmm3
#undef XMM_ZERO
#undef XMM_SCALAR
#undef MEM32
#undef MEM8
#undef MEMF
#undef PUSH32
#undef POP32
#undef CMP_EQ
#undef CMP_NE
#undef CMP_LE
#undef CMP_L
#undef CMP_BE
#undef CMP_B
#undef TEST_Z
#undef TEST_NZ
#undef RECOMP_ICALL_SAFE
#undef LO8
#undef HI8
#undef SET_LO8

static __forceinline uint32_t manual_bink_mmx_clamp(uint16_t value)
{
    int32_t sum = (int16_t)value + 0x7F00;
    uint16_t saturated;
    if (sum > 32767) saturated = 0x7FFF;
    else if (sum < -32768) saturated = 0x8000;
    else saturated = (uint16_t)(int16_t)sum;
    return saturated > 0x7F00 ? saturated - 0x7F00 : 0;
}

/* The generated scalar recovery is bit-equivalent to the retail four-pixel
 * MMX converter, but repeatedly translates every guest address. Hoist those
 * translations once per two scanlines. This keeps the Xbox's 16-bit wrap and
 * saturation order while leaving enough time for a 29.97 fps Bink frame. */
void sub_0028DDC0(void)
{
    uint32_t groups = *manual_mem32(g_esp + 4);
    uint32_t dst0_va = *manual_mem32(0x336F90);
    uint32_t dst1_va = *manual_mem32(0x336F94);
    uint32_t y0_va = *manual_mem32(0x336F98);
    uint32_t y1_va = *manual_mem32(0x336F9C);
    uint32_t u_va = *manual_mem32(0x336FA0);
    uint32_t v_va = *manual_mem32(0x336FA4);
    uint32_t *dst0 = manual_mem32(dst0_va);
    uint32_t *dst1 = manual_mem32(dst1_va);
    const uint8_t *y0 = manual_mem8(y0_va);
    const uint8_t *y1 = manual_mem8(y1_va);
    const uint8_t *u = manual_mem8(u_va);
    const uint8_t *v = manual_mem8(v_va);
    const int16_t *y_scale = (const int16_t *)manual_mem8(0x2F1E40);
    const uint16_t *blue_table = (const uint16_t *)manual_mem8(0x337FB8);
    const uint16_t *green_u_table = (const uint16_t *)manual_mem8(0x3387B8);
    const uint16_t *green_v_table = (const uint16_t *)manual_mem8(0x3383B8);
    const uint16_t *red_table = (const uint16_t *)manual_mem8(0x338BB8);

    for (uint32_t group = 0; group < groups; ++group) {
        for (uint32_t lane = 0; lane < 4; ++lane) {
            uint32_t pair = lane >> 1;
            uint32_t half = lane & 1;
            uint32_t table_index = (uint32_t)u[pair] * 2 + half;
            uint32_t v_index = (uint32_t)v[pair] * 2 + half;
            uint16_t y0w = y0[lane] > 0x10 ? (uint16_t)(y0[lane] - 0x10) : 0;
            uint16_t y1w = y1[lane] > 0x10 ? (uint16_t)(y1[lane] - 0x10) : 0;
            int16_t y0term;
            int16_t y1term;
            uint16_t blue;
            uint16_t green;
            uint16_t red;

            y0w = (uint16_t)(y0w << 2);
            y1w = (uint16_t)(y1w << 2);
            y0term = (int16_t)(((int32_t)(int16_t)y0w * y_scale[lane]) >> 16);
            y1term = (int16_t)(((int32_t)(int16_t)y1w * y_scale[lane]) >> 16);

            blue = (uint16_t)(blue_table[table_index] + (uint16_t)y0term);
            green = (uint16_t)(green_u_table[table_index] + green_v_table[v_index]);
            green = (uint16_t)(green + (uint16_t)y0term);
            red = (uint16_t)(red_table[v_index] + (uint16_t)y0term);
            dst0[lane] = manual_bink_mmx_clamp(blue) |
                (manual_bink_mmx_clamp(green) << 8) |
                (manual_bink_mmx_clamp(red) << 16);

            blue = (uint16_t)(blue_table[table_index] + (uint16_t)y1term);
            green = (uint16_t)(green_u_table[table_index] + green_v_table[v_index]);
            green = (uint16_t)(green + (uint16_t)y1term);
            red = (uint16_t)(red_table[v_index] + (uint16_t)y1term);
            dst1[lane] = manual_bink_mmx_clamp(blue) |
                (manual_bink_mmx_clamp(green) << 8) |
                (manual_bink_mmx_clamp(red) << 16);
        }
        dst0 += 4; dst1 += 4;
        y0 += 4; y1 += 4;
        u += 2; v += 2;
    }

    *manual_mem32(0x336F90) = dst0_va + groups * 16;
    *manual_mem32(0x336F94) = dst1_va + groups * 16;
    *manual_mem32(0x336F98) = y0_va + groups * 4;
    *manual_mem32(0x336F9C) = y1_va + groups * 4;
    *manual_mem32(0x336FA0) = u_va + groups * 2;
    *manual_mem32(0x336FA4) = v_va + groups * 2;
    g_esp += 8;
}

/* Retail 0x223180..0x223223. The generated extent stopped at 0x223203,
 * before the last three constants, the four-vector copy, and the epilogue.
 * That left 0x2F1F90..0x2F1FCC zero and leaked 0x50 guest-stack bytes. */
void sub_00223180(void)
{
    g_esp -= 0x40;
    g_eax = g_esp;
    g_esp -= 4; *manual_mem32(g_esp) = g_eax;
    g_ecx = g_esp + 0x14;
    g_esp -= 4; *manual_mem32(g_esp) = g_ecx;
    g_edx = g_esp + 0x28;
    g_esp -= 4; *manual_mem32(g_esp) = g_edx;
    g_eax = g_esp + 0x3C;
    g_esp -= 4; *manual_mem32(g_esp) = g_eax;
    g_ecx = 0x2F1F90;
    *manual_mem32(g_esp + 0x10) = 0x41100000;
    *manual_mem32(g_esp + 0x14) = 0x40A00000;
    *manual_mem32(g_esp + 0x18) = 0x40C00000;
    *manual_mem32(g_esp + 0x1C) = 0x40800000;
    *manual_mem32(g_esp + 0x20) = 0x3F800000;
    *manual_mem32(g_esp + 0x24) = 0x3FC00000;
    *manual_mem32(g_esp + 0x28) = 0x3F000000;
    *manual_mem32(g_esp + 0x2C) = 0x3F800000;
    *manual_mem32(g_esp + 0x30) = 0x40400000;
    *manual_mem32(g_esp + 0x34) = 0x40000000;
    *manual_mem32(g_esp + 0x38) = 0x3FC00000;
    *manual_mem32(g_esp + 0x3C) = 0x40000000;
    *manual_mem32(g_esp + 0x40) = 0x41000000;
    *manual_mem32(g_esp + 0x44) = 0x40A00000;
    *manual_mem32(g_esp + 0x48) = 0x40400000;
    *manual_mem32(g_esp + 0x4C) = 0x40000000;
    g_esp -= 4; *manual_mem32(g_esp) = 0x00223220u;
    sub_000425A0();
    g_esp += 0x40;
    g_esp += 4;
}
recomp_func_t recomp_lookup_manual(uint32_t xbox_va)
{
    /*
     * TODO: Add your overrides here. Examples:
     *
     * if (xbox_va == 0x00012345) return traced_sub_00012345;
     * if (xbox_va == 0x00067890) return stub_00067890;
     * if (xbox_va == 0x000ABCDE) return fixed_sub_000ABCDE;
     */

    if (xbox_va == 0x001A7E30) return sub_001A7E30;
    if (xbox_va == 0x001A7EB0) return sub_001A7EB0;
    if (xbox_va == 0x002961C2) return sub_002961C2;
    if (xbox_va == 0x00296218) return sub_00296218;
    if (xbox_va == 0x00296224) return sub_00296224;
    if (xbox_va == 0x00296297) return sub_00296297;
    if (xbox_va == 0x00296353) return sub_00296353;
    if (xbox_va == 0x00296375) return sub_00296375;
    if (xbox_va == 0x0028DDC0) return sub_0028DDC0;
    if (xbox_va == 0x0015FF70) return traced_sub_0015FF70;
    if (xbox_va == 0x001602D0) return traced_sub_001602D0;
    if (xbox_va == 0x0015D130) return traced_sub_0015D130;
    if (xbox_va == 0x000C4C80) return traced_sub_000C4C80;
    if (xbox_va == 0x000F2720) return traced_sub_000F2720;
    if (xbox_va == 0x001C7FB9) return override_sub_001C7FB9;
    if (xbox_va == 0x001C6A27) return sub_001C6A27;
    if (xbox_va == 0x000F78B0) return override_sub_000F78B0;
    if (xbox_va == 0x0008F860) return safe_sub_0008F860;
    if (xbox_va == 0x0003C080) return safe_sub_0003C080;
    if (xbox_va == 0x00035970) return safe_sub_00035970;
    if (xbox_va == 0x00162110) return manual_sub_00162110;
    if (xbox_va == 0x00155210) return safe_sub_00155210;
    if (xbox_va == 0x0015D190) return safe_sub_0015D190;
    if (xbox_va == 0x00157460) return sub_00157460;
    if (xbox_va == 0x0010E310) return sub_0010E310;
    if (xbox_va == 0x001A7110) return trace_heap_alloc;
    if (xbox_va == 0x001A7160) return trace_heap_free;
    if (xbox_va == 0x00265785) return init_dsound_00265785;
    if (xbox_va == 0x00265790) return init_dsound_00265790;
    if (xbox_va == 0x00268750) return init_dsound_00268750;
    if (xbox_va == 0x0026875B) return init_dsound_0026875B;
    return (recomp_func_t)0;
}

/* ── ICALL failure logging ─────────────────────────────────── */

/*
 * Called when RECOMP_ICALL cannot resolve a target address.
 * This usually means one of:
 *   - A vtable dispatch to an address not in the dispatch table
 *   - A function pointer loaded from uninitialized or corrupt memory
 *   - A kernel thunk address that the bridge doesn't handle
 *
 * During early bring-up you will see many of these. Most are harmless
 * (the ICALL macro pops the dummy return address and continues).
 * Focus on the ones that cause crashes or incorrect behavior.
 */
void recomp_icall_fail_log(uint32_t va)
{
    static uint32_t failure_count;
    static uint64_t null_failure_count;
    static uint32_t site_debug_count;  /* TEMP: per-VA site trace for active bug hunt */
    static long s_total_log_count;
    long total_n;
    failure_count++;
    if (va == 0 && ++null_failure_count > 8)
        return;
    if (va == 0x002AE888u && ++site_debug_count > 5)
        return;
    /* Any OTHER va (e.g. 0x00000004, from sub_001AB760's per-object vtable
     * pump) previously had no throttle at all -- only these two specific,
     * previously-known-bad VAs were ever capped. A va that fails on every
     * one of a ~272-entry per-frame list walk hits this function hundreds
     * of times per frame, forever (nothing ever fixes the underlying
     * target), and every call unconditionally fprintf's a 16-line dump and
     * fflush(stderr)s -- real, uncached I/O. That cost, multiplied by
     * hundreds of calls per frame and compounding as other processes also
     * contend for the disk, is enough to make frame times balloon from
     * milliseconds to many seconds, looking exactly like a hang from the
     * outside. Bound logging for ANY va the same way, not just the two
     * previously-known offenders. */
    total_n = ++s_total_log_count;
    if (total_n > 20 && (total_n % 2000) != 0)
        return;
    DAH2_TRACE_FPRINTF(stderr, "[ICALL] Failed to resolve VA 0x%08X (total calls: %llu) caller_rva=0x%llX\n",
            va, (unsigned long long)g_icall_count,
            (unsigned long long)((uintptr_t)_ReturnAddress() - (uintptr_t)GetModuleHandleA(NULL)));

    if ((failure_count <= 8 || (va == 0 && null_failure_count <= 8) ||
         (va == 0x002AE888u && site_debug_count <= 5)) &&
        g_esp >= 0x10000 && g_esp < 0x04000000) {
        const uint32_t *stack = (const uint32_t *)((uintptr_t)g_esp + g_xbox_mem_offset);
        DAH2_TRACE_FPRINTF(stderr,
                "  site/stack esp=%08X: %08X %08X %08X %08X %08X %08X eax=%08X ecx=%08X edx=%08X\n",
                g_esp, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5],
                g_eax, g_ecx, g_edx);
        DAH2_TRACE_FPRINTF(stderr, "  regs esi=%08X edi=%08X ebx=%08X\n", g_esi, g_edi, g_ebx);
        if (g_edi >= 0x10000u && g_edi < 0x38000000u) {
            const uint32_t *obj = (const uint32_t *)((uintptr_t)g_edi + g_xbox_mem_offset);
            DAH2_TRACE_FPRINTF(stderr,
                    "  edi-obj[+0x58 count]=%08X [+0x5C]=%08X [+0x60 base]=%08X [+0x64]=%08X\n",
                    obj[0x58/4], obj[0x5C/4], obj[0x60/4], obj[0x64/4]);
        }
        if (g_esi >= 0x10000u && g_esi < 0x38000000u) {
            const uint32_t *arr = (const uint32_t *)((uintptr_t)g_esi + g_xbox_mem_offset);
            DAH2_TRACE_FPRINTF(stderr, "  esi-array[0..3]=%08X %08X %08X %08X\n",
                    arr[0], arr[1], arr[2], arr[3]);
        }
    }

    /* Dump last 16 call targets from the ring buffer */
    DAH2_TRACE_FPRINTF(stderr, "  Recent ICALL targets:\n");
    for (int i = 0; i < 16; i++) {
        int idx = (g_icall_trace_idx - 16 + i) & 15;
        if (g_icall_trace[idx])
            DAH2_TRACE_FPRINTF(stderr, "    [%2d] 0x%08X\n", i, g_icall_trace[idx]);
    }
    fflush(stderr);
}
