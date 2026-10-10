/**
 * kernel_bridge.c - Bridge between translated game code and kernel functions
 *
 * Problem:
 *   Translated game code calls kernel functions via indirect calls through
 *   the kernel thunk table at VA 0x0036B7C0. In the XBE file, these entries
 *   contain unresolved ordinals (0x80000000 | ordinal). On real Xbox hardware,
 *   the kernel loader replaces these with actual function pointers before the
 *   game runs.
 *
 * Solution:
 *   1. After xbox_MemoryLayoutInit copies .rdata, call xbox_kernel_bridge_init()
 *   2. Replace each ordinal entry in Xbox memory with a synthetic VA
 *   3. When RECOMP_ICALL encounters a synthetic VA, route it to a per-ordinal
 *      bridge function that reads args from the simulated Xbox stack, translates
 *      pointer arguments from Xbox VA→native, and calls the kernel function.
 *
 * Synthetic VA scheme:
 *   Each thunk slot i gets VA 0xFE000000 + i*4
 *   The lookup function checks this range and dispatches appropriately.
 *
 * Why per-ordinal bridges instead of a generic trampoline:
 *   Kernel functions receive Xbox pointers (32-bit VAs) that must be translated
 *   to native pointers by adding g_xbox_mem_offset. Different functions have
 *   different parameter layouts (pointer vs value), so each needs its own bridge.
 */

#include "kernel.h"
#include "xbox_memory_layout.h"
#include <stdio.h>
/* stdlib.h is load-bearing, not tidiness. Without it C89 implicit declaration
 * makes malloc return `int`, so bridge_spawn_thread truncated its heap pointer
 * to 32 bits and sign-extended it into a `struct bridge_thread_start *`. Every
 * subsequent s->field wrote to an address that had nothing to do with the
 * allocation. MSVC says so (C4013 + C4047 "differs in levels of indirection")
 * but only as warnings, and this file is compiled with /W4 /WX-. */
#include <stdlib.h>
#include <float.h>

/* Access to recompiled code registers. Per-thread: RECOMP_TLS comes from
 * xbox_memory_layout.h and must match the definitions there -- a plain extern
 * here binds to the TLS template rather than the calling thread's copy, which
 * reads as every register being zero. */
extern RECOMP_TLS uint32_t g_eax, g_ecx, g_edx, g_esp;
extern RECOMP_TLS uint32_t g_ebx, g_esi, g_edi;
extern RECOMP_TLS uint32_t g_ebp;
extern RECOMP_TLS uint32_t g_seh_ebp;
extern ptrdiff_t g_xbox_mem_offset;

/* Dispatch table lookup (for function pointer args) */
typedef void (*recomp_func_t)(void);
recomp_func_t recomp_lookup(uint32_t xbox_va);
recomp_func_t recomp_lookup_manual(uint32_t xbox_va);

/* Memory access - same as recomp_types.h MEM32 but without the #define guard */
#define BRIDGE_MEM32(addr) (*(volatile uint32_t *)((uintptr_t)(addr) + g_xbox_mem_offset))

/* Translate Xbox VA to native pointer (NULL-safe: 0 → NULL) */
#define XBOX_TO_NATIVE(va) ((va) ? (void*)((uintptr_t)(va) + g_xbox_mem_offset) : NULL)

/* ── Synthetic VA range (for function exports) ─────────── */

#define KERNEL_VA_BASE  0xFE000000u
#define KERNEL_VA_END   (KERNEL_VA_BASE + XBOX_KERNEL_THUNK_TABLE_SIZE * 4)

/* ── Kernel data exports ──────────────────────────────────
 *
 * Some kernel ordinals are DATA exports (structs/variables), not functions.
 * The game reads their thunk entries and dereferences the result to access
 * the data. These cannot use synthetic VAs — they must point to real,
 * dereferenceable addresses in the Xbox VA space.
 *
 * We allocate a "kernel data area" at XBOX_KERNEL_DATA_BASE and populate
 * it with the expected structures.
 */

#define BRIDGE_MEM16(addr) (*(volatile uint16_t *)((uintptr_t)(addr) + g_xbox_mem_offset))
#define BRIDGE_MEM8(addr)  (*(volatile uint8_t  *)((uintptr_t)(addr) + g_xbox_mem_offset))

/**
 * Get the Xbox VA of data for a kernel DATA export ordinal.
 * Returns 0 if the ordinal is not a data export (i.e., it's a function).
 */
static uint32_t kernel_data_va_for_ordinal(ULONG ordinal)
{
    /* Ordinals here are checked BEFORE function routing (see the thunk build
     * loop), so an ordinal listed by mistake turns a real kernel function into
     * a data address -- the title then calls it and jumps into kernel data.
     *
     * This table had a whole block shifted. 17 (ExFreePool), 65
     * (IoCreateDevice), 327 (XeLoadSection) and 328 (XeUnloadSection) are all
     * functions and were all being handed data addresses; Crimson Skies imports
     * every one of them. In the other direction, the genuine exports at 16, 353,
     * 354, 355, 356 and 357 got no thunk at all, so a title reading
     * XboxLANKey or KeTimeIncrement read whatever the function fallback left.
     *
     * test_bridge_ordinals.py now checks every entry below against the export
     * table, which is why the block cannot drift again unnoticed. */
    switch (ordinal) {
    case  16: return XBOX_KERNEL_DATA_BASE + KDATA_EVENT_OBJ_TYPE;
    case  22: return XBOX_KERNEL_DATA_BASE + KDATA_MUTANT_OBJ_TYPE;
    case  30: return XBOX_KERNEL_DATA_BASE + KDATA_SEMAPHORE_OBJ_TYPE;
    case  31: return XBOX_KERNEL_DATA_BASE + KDATA_TIMER_OBJ_TYPE;
    case  40: return XBOX_KERNEL_DATA_BASE + KDATA_DISK_CACHE_PARTS;
    case  41: return XBOX_KERNEL_DATA_BASE + KDATA_DISK_MODEL_STR;
    case  42: return XBOX_KERNEL_DATA_BASE + KDATA_DISK_SERIAL_STR;
    case  64: return XBOX_KERNEL_DATA_BASE + KDATA_IO_COMPLETION_TYPE;
    case  70: return XBOX_KERNEL_DATA_BASE + KDATA_IO_DEVICE_TYPE;
    case  71: return XBOX_KERNEL_DATA_BASE + KDATA_FILE_OBJ_TYPE;
    case 156: return XBOX_KERNEL_DATA_BASE + KDATA_TICK_COUNT;
    case 157: return XBOX_KERNEL_DATA_BASE + KDATA_TIME_INCREMENT;
    case 164: return XBOX_KERNEL_DATA_BASE + KDATA_LAUNCH_DATA_PAGE;
    case 259: return XBOX_KERNEL_DATA_BASE + KDATA_THREAD_OBJ_TYPE;
    case 322: return XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO;
    case 323: return XBOX_KERNEL_DATA_BASE + KDATA_HD_KEY;
    case 324: return XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION;
    case 325: return XBOX_KERNEL_DATA_BASE + KDATA_SIGNATURE_KEY;
    case 326: return XBOX_KERNEL_DATA_BASE + KDATA_XE_IMAGE_FILENAME;
    case 353: return XBOX_KERNEL_DATA_BASE + KDATA_LAN_KEY;
    case 354: return XBOX_KERNEL_DATA_BASE + KDATA_ALT_SIGNATURE_KEYS;
    case 355: return XBOX_KERNEL_DATA_BASE + KDATA_XE_PUBLIC_KEY;
    case 356: return XBOX_KERNEL_DATA_BASE + KDATA_BOOT_SMC_VIDEO;
    case 357: return XBOX_KERNEL_DATA_BASE + KDATA_IDEX_CHANNEL;
    default:  return 0;  /* Not a data export */
    }
}

/**
 * Initialize kernel data export values at the kernel data area.
 * Called during bridge init, after Xbox memory is mapped.
 */
static void kernel_data_init(void)
{
    /* XboxHardwareInfo (ordinal 322) - XBOX_HARDWARE_INFO
     *   +0: ULONG Flags (0 = retail, 0x20 = devkit)
     *   +4: UCHAR GpuRevision
     *   +5: UCHAR McpRevision
     */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO + 0) = 0;   /* Retail */
    BRIDGE_MEM8(XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO + 4) = 0xA1; /* NV2A A1 */
    BRIDGE_MEM8(XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO + 5) = 0xB1; /* MCPX B1 */

    /* XboxKrnlVersion (ordinal 324) - XBOX_KRNL_VERSION
     *   +0: USHORT Major (1)
     *   +2: USHORT Minor (0)
     *   +4: USHORT Build (5849 = XDK version)
     *   +6: USHORT Qfe (0)
     */
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 0) = 1;
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 2) = 0;
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 4) = 5849;
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 6) = 0;

    /* KeTickCount (ordinal 156) - initialized to current tick count.
     * A background thread in main.c updates this every ~1ms. */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_TICK_COUNT) = GetTickCount();

    /* LaunchDataPage (ordinal 164) - NULL (no launch data) */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_LAUNCH_DATA_PAGE) = 0;

    /* Object-type exports. Each gets a DISTINCT non-zero value rather than 0.
     *
     * They were all zero, which is wrong twice over: a title that null-checks
     * one sees "no such type", and a title that distinguishes two of them --
     * ObReferenceObjectByHandle takes an expected type and compares it -- sees
     * every type as equal, so a mutant handle passes a check meant for events.
     * The values are opaque to the game; only identity and non-nullness matter,
     * so they are the export ordinal offset into the kernel data area, which
     * also makes a stray one recognisable in a crash dump.
     */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_THREAD_OBJ_TYPE)    = XBOX_KERNEL_DATA_BASE + KDATA_THREAD_OBJ_TYPE;
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_EVENT_OBJ_TYPE)     = XBOX_KERNEL_DATA_BASE + KDATA_EVENT_OBJ_TYPE;
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_MUTANT_OBJ_TYPE)    = XBOX_KERNEL_DATA_BASE + KDATA_MUTANT_OBJ_TYPE;
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_SEMAPHORE_OBJ_TYPE) = XBOX_KERNEL_DATA_BASE + KDATA_SEMAPHORE_OBJ_TYPE;
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_TIMER_OBJ_TYPE)     = XBOX_KERNEL_DATA_BASE + KDATA_TIMER_OBJ_TYPE;
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_FILE_OBJ_TYPE)      = XBOX_KERNEL_DATA_BASE + KDATA_FILE_OBJ_TYPE;

    /* KeTimeIncrement (ordinal 157) - 100ns units per clock tick. 0x2710 is
     * 1 ms, which is what KeTickCount above is updated at. A title dividing by
     * this to convert ticks to time gets a division by zero if it is left 0. */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_TIME_INCREMENT) = 0x2710;

    /* HalBootSMCVideoMode (ordinal 356) - SMC video mode word from boot. 0 is
     * "no video mode reported", which titles treat as auto-detect. */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_BOOT_SMC_VIDEO) = 0;

    /* IdexChannelObject (ordinal 357) - IDE channel object. Opaque; only ever
     * passed back to Io* routines we stub, so a recognisable non-null is enough. */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_IDEX_CHANNEL) = XBOX_KERNEL_DATA_BASE + KDATA_IDEX_CHANNEL;

    /* HalDiskCachePartitionCount (ordinal 40) - number of cache partitions.
     * Retail consoles report 3 (X, Y, Z). Titles size a partition array from
     * this, so 0 gives a zero-length array and 1 hides two drives. */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_DISK_CACHE_PARTS) = 3;

    /* IoCompletionObjectType (ordinal 64) - type object */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_IO_COMPLETION_TYPE) = 0;

    /* IoDeviceObjectType (ordinal 71) - type object (stub: 0) */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_IO_DEVICE_TYPE) = 0;

    /* XboxHDKey (ordinal 323) - 16 bytes of zeros (no key) */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_HD_KEY) + g_xbox_mem_offset), 0, 16);

    /* XboxSignatureKey (ordinal 325) - 16 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_SIGNATURE_KEY) + g_xbox_mem_offset), 0, 16);

    /* XboxLANKey (ordinals 326, 355) - 16 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_LAN_KEY) + g_xbox_mem_offset), 0, 16);

    /* XboxAlternateSignatureKeys (ordinals 327, 356) - 256 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_ALT_SIGNATURE_KEYS) + g_xbox_mem_offset), 0, 256);

    /* XePublicKeyData (ordinal 357) - 284 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_XE_PUBLIC_KEY) + g_xbox_mem_offset), 0, 284);

    /* HAL disk identity strings (ordinals 41/42). The exported symbol is an
     * XBOX_ANSI_STRING whose Buffer must be an Xbox VA the title can deref --
     * HalRandGather reads the bytes for entropy. Build the struct and its text
     * inside the kernel data area so both are addressable. */
    {
        struct { uint32_t str_off, buf_off; const char *text; } d[] = {
            { KDATA_DISK_MODEL_STR,  KDATA_DISK_MODEL_BUF,  "XBOXRECOMP VIRTUAL HDD" },
            { KDATA_DISK_SERIAL_STR, KDATA_DISK_SERIAL_BUF, "XR0000000000" },
        };
        for (int k = 0; k < 2; k++) {
            uint32_t str_va = XBOX_KERNEL_DATA_BASE + d[k].str_off;
            uint32_t buf_va = XBOX_KERNEL_DATA_BASE + d[k].buf_off;
            size_t len = strlen(d[k].text);
            memcpy(XBOX_TO_NATIVE(buf_va), d[k].text, len + 1);
            BRIDGE_MEM16(str_va + 0) = (uint16_t)len;        /* Length */
            BRIDGE_MEM16(str_va + 2) = (uint16_t)(len + 1);  /* MaximumLength */
            BRIDGE_MEM32(str_va + 4) = buf_va;               /* Buffer (Xbox VA) */
        }
    }

    fprintf(stderr, "  Kernel data exports: initialized at Xbox VA 0x%08X\n",
            XBOX_KERNEL_DATA_BASE);
}

/* ── Per-slot ordinal and bridge function ────────────────── */

/* Ordinal for each slot (read from Xbox memory during init) */
static ULONG g_slot_ordinals[XBOX_KERNEL_THUNK_TABLE_SIZE];

/* Per-slot kernel-call accounting, readable from outside the process (these
 * are plain exported globals, found through the linker map) so frame cost can
 * be attributed to a specific kernel service without enabling any logging --
 * stderr is discarded in normal runs and tracing itself changes timing.
 * Ticks are QPC ticks spent inside the bridge, inclusive of anything it calls
 * (a wait, or a guest routine run on the caller's behalf). */
volatile LONG64  g_xbox_kernel_stat_calls[XBOX_KERNEL_THUNK_TABLE_SIZE];
volatile LONG64  g_xbox_kernel_stat_ticks[XBOX_KERNEL_THUNK_TABLE_SIZE];
volatile LONG    g_xbox_kernel_stat_ordinal[XBOX_KERNEL_THUNK_TABLE_SIZE];

/* The same, restricted to calls made on the thread that presents frames
 * (g_dah2_present_thread_id, set by dah2_guest_gpu_present). Only these count
 * against the 33.3 ms frame budget: a worker thread blocked in a wait costs
 * nothing, the frame thread blocked in one is the frame time. */
extern volatile LONG g_dah2_present_thread_id;
volatile LONG64  g_xbox_kernel_frame_calls[XBOX_KERNEL_THUNK_TABLE_SIZE];
volatile LONG64  g_xbox_kernel_frame_ticks[XBOX_KERNEL_THUNK_TABLE_SIZE];

/* Guest return address and requested microseconds of each distinct
 * KeStallExecutionProcessor call site, so a recurring stall can be traced to
 * the code that issues it. */
typedef struct { volatile LONG ret; volatile LONG usec; volatile LONG64 calls; } kernel_stall_site;
volatile kernel_stall_site g_xbox_kernel_stall_sites[8];

/* Log counter - limit output to avoid flooding */
static int g_kernel_call_count = 0;

/* Read Xbox stack arg as uint32_t.
 * After kernel_thunk_dispatch pops the dummy return address (g_esp += 4),
 * arg0 is at g_esp+0, arg1 at g_esp+4, etc. */
#define STACK_ARG(n) ((uint32_t)BRIDGE_MEM32(g_esp + (n) * 4))

/* ── Per-ordinal bridge functions ─────────────────────────
 *
 * Each bridge reads args from the Xbox stack, translates pointer
 * args from Xbox VA→native, calls the kernel function, and stores
 * the result in g_eax.
 *
 * Xbox cdecl: args pushed right-to-left, caller cleans stack.
 * Xbox stdcall: args pushed right-to-left, callee cleans stack.
 * In our case the caller (translated code) does "PUSH32" for each arg
 * before calling, and the kernel function's ret-N is handled by the
 * translated code's own stack adjustment.
 */

/* ── PsCreateSystemThreadEx (ordinal 255) ────────────────
 * NTSTATUS PsCreateSystemThreadEx(
 *   PHANDLE ThreadHandle,      // arg0: Xbox VA → pointer
 *   ULONG ThreadExtraSize,     // arg1: value
 *   ULONG KernelStackSize,     // arg2: value
 *   ULONG TlsDataSize,         // arg3: value
 *   PULONG ThreadId,           // arg4: Xbox VA → pointer (can be NULL)
 *   PVOID StartContext1,       // arg5: Xbox VA → opaque
 *   PVOID StartContext2,       // arg6: Xbox VA → opaque
 *   BOOLEAN CreateSuspended,   // arg7: value
 *   BOOLEAN DebugStack,        // arg8: value
 *   PXBOX_SYSTEM_ROUTINE StartRoutine  // arg9: Xbox function pointer
 * )
 *
 * For static recompilation, we don't create a real thread.
 * Instead we call the StartRoutine synchronously via RECOMP_ICALL.
 * This is correct because on Xbox, the entry point creates a system
 * thread and returns, and the thread runs the actual game.
 */
static int g_thread_call_count = 0;

/* Thread entry shim. Sets up the new thread's own simulated stack, pushes the
 * two Xbox start-context arguments plus the dummy return address the callee's
 * `ret` consumes, and runs. */
/* Set on threads this bridge spawned; see PsTerminateSystemThread. */
static RECOMP_TLS int g_is_spawned_thread = 0;
static RECOMP_TLS uint32_t g_spawned_stack_top = 0;

static void bridge_release_thread_stack(void)
{
    uint32_t stack_top = g_spawned_stack_top;
    g_spawned_stack_top = 0;
    if (stack_top) xbox_FreeThreadStack(stack_top);
}

struct bridge_thread_start {
    recomp_func_t fn;
    uint32_t ctx1, ctx2, stack_top;
};

static void bridge_write_handle(uint32_t handle_va, HANDLE h);

static void bridge_run_thread_inline(recomp_func_t fn, uint32_t ctx1,
                                     uint32_t ctx2)
{
    g_esp -= 4; BRIDGE_MEM32(g_esp) = ctx2;
    g_esp -= 4; BRIDGE_MEM32(g_esp) = ctx1;
    g_esp -= 4; BRIDGE_MEM32(g_esp) = 0;
    g_seh_ebp = g_esp;
    fn();
    g_esp += 12;
}

static DWORD WINAPI bridge_thread_main(LPVOID param)
{
    struct bridge_thread_start *s = (struct bridge_thread_start *)param;
    recomp_func_t fn = s->fn;
    uint32_t ctx1 = s->ctx1, ctx2 = s->ctx2;

    /* Own register set (RECOMP_TLS), own simulated stack. */
    g_is_spawned_thread = 1;
    g_spawned_stack_top = s->stack_top;
    g_esp = g_spawned_stack_top;
    free(s);

    bridge_run_thread_inline(fn, ctx1, ctx2);

    fprintf(stderr, "  [KERNEL] worker thread returned (eax=0x%08X)\n", g_eax);
    fflush(stderr);
    bridge_release_thread_stack();
    return 0;
}

static HANDLE bridge_spawn_thread(recomp_func_t fn, uint32_t ctx1,
                                  uint32_t ctx2, uint32_t stack_top,
                                  int create_suspended)
{
    struct bridge_thread_start *s = malloc(sizeof(*s));
    HANDLE th;

    if (!s) return NULL;
    s->fn = fn; s->ctx1 = ctx1; s->ctx2 = ctx2; s->stack_top = stack_top;

    th = CreateThread(NULL, 0, bridge_thread_main, s,
                      create_suspended ? CREATE_SUSPENDED : 0, NULL);
    if (!th) free(s);
    /* Record the game thread so a host-tick-driven title's watchdog can sample
     * it via xbox_thread_debug_handle. Harmless for default-model titles: they
     * spawn workers too, but never read it back. See kernel_thread.c. */
    else xbox_set_game_thread(th);
    return th;
}

/* Two ways a title expects its first PsCreateSystemThreadEx to behave.
 *
 * INLINE (default): the first call IS the game starting -- run the routine
 * inline, inheriting register state, and it drives its own main loop forever.
 * This is what Halo and Crimson Skies need and the historical behavior.
 *
 * SPAWN: the title's entry spawns an init thread and RETURNS, expecting the host
 * to drive the per-frame tick afterwards (Burnout 3 is tick-driven). Here the
 * first call must spawn a real thread and return, so control comes back to the
 * host. Opt in with xbox_SetThreadMode before the game starts. See
 * docs/technical/burnout3-reunification.md. */
/* XBOX_THREAD_MODE_* and xbox_SetThreadMode are declared in xbox_memory_layout.h. */
static int g_thread_mode = XBOX_THREAD_MODE_INLINE;
void xbox_SetThreadMode(int mode) { g_thread_mode = mode; }

static void bridge_PsCreateSystemThreadEx(void)
{
    uint32_t xbox_handle_ptr = STACK_ARG(0);
    uint32_t start_context1  = STACK_ARG(5);
    uint32_t start_context2  = STACK_ARG(6);
    uint32_t create_suspended = STACK_ARG(7);
    uint32_t start_routine   = STACK_ARG(9);
    /* In SPAWN mode there is no privileged "first call": every thread is real,
     * so the entry can return. In INLINE mode the first call runs the game. */
    int is_first_call = (g_thread_mode == XBOX_THREAD_MODE_INLINE)
                        && (g_thread_call_count == 0);
    g_thread_call_count++;

    fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx #%d: routine=0x%08X ctx1=0x%08X ctx2=0x%08X\n",
            g_thread_call_count, start_routine, start_context1, start_context2);
    fflush(stderr);

    /* Only the compatibility INLINE bootstrap has a synthetic handle. A
     * worker failure must leave its output untouched and return an error. */
    if (is_first_call && xbox_handle_ptr) {
        BRIDGE_MEM32(xbox_handle_ptr) = 0xBEEF0001;
    }

    /* Call the start routine synchronously through the recomp dispatch.
     * Xbox thread start routines receive two parameters:
     *   void ThreadRoutine(PVOID StartContext1, PVOID StartContext2)
     * We push both onto the simulated stack (right-to-left).
     *
     * First call: the game's main thread entry point. Must run synchronously
     * and inherit the current register state (this IS the game starting).
     *
     * Subsequent calls: worker threads. Must save/restore ALL global registers
     * because on real Xbox each thread has its own register set. Without this,
     * the worker clobbers the caller's g_esi, g_ebx, etc. */
    if (start_routine) {
        recomp_func_t fn = recomp_lookup(start_routine);
        if (!fn) fn = recomp_lookup_manual(start_routine);
        if (fn) {
            if (is_first_call) {
                /* Main game thread: run directly, inheriting register state */
                g_esp -= 4; BRIDGE_MEM32(g_esp) = start_context2;
                g_esp -= 4; BRIDGE_MEM32(g_esp) = start_context1;
                g_esp -= 4; BRIDGE_MEM32(g_esp) = 0;
                fn();
                g_esp += 12;
                fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: main thread returned (g_eax=0x%08X)\n", g_eax);
                fflush(stderr);
            } else {
                /* Worker thread: a real one.
                 *
                 * This used to run the routine synchronously and restore the
                 * caller's registers afterwards, which is fine only for a
                 * worker that finishes. Halo's cache/file worker does not -- it
                 * blocks on an event waiting for requests, so CreateThread
                 * never returned and startup deadlocked before the main loop.
                 *
                 * Now that the register set is thread-local (RECOMP_TLS), a
                 * spawned thread gets its own, and the caller's is untouched by
                 * construction rather than by save/restore. */
                uint32_t stack_top = xbox_AllocThreadStack();

                if (!stack_top) {
                    fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: out of "
                            "thread stacks for worker 0x%08X\n", start_routine);
                    fflush(stderr);
                    g_eax = 0xC000009Au; /* STATUS_INSUFFICIENT_RESOURCES */
                    return;
                } else {
                    HANDLE th = bridge_spawn_thread(fn, start_context1,
                                                    start_context2, stack_top,
                                                    create_suspended != 0);
                    if (!th) {
                        xbox_FreeThreadStack(stack_top);
                        g_eax = 0xC000009Au; /* STATUS_INSUFFICIENT_RESOURCES */
                        return;
                    }
                    fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: spawned "
                            "worker 0x%08X (ctx=0x%08X, stack top 0x%08X, suspended=%u)\n",
                            start_routine, start_context1, stack_top,
                            create_suspended != 0);
                    fflush(stderr);
                    if (xbox_handle_ptr && th) {
                        bridge_write_handle(xbox_handle_ptr, th);
                    }
                }
            }
        } else {
            fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: start routine 0x%08X not found in dispatch!\n",
                    start_routine);
        }
    }

    g_eax = 0; /* STATUS_SUCCESS */
}

/* ── NtClose (ordinal 187) ───────────────────────────────
 * NTSTATUS NtClose(HANDLE Handle)
 * Handle is a value (not a pointer), so safe for generic call.
 */
/* Handle-table helpers; defined further below. Xbox memory slots are 32-bit
 * but native HANDLEs are 64-bit pointers, so handles are kept in a table and
 * referenced by tagged 32-bit tokens. */
static void   bridge_write_handle(uint32_t handle_va, HANDLE h);
static HANDLE bridge_take_handle(uint32_t token);
static int    bridge_close_mutant(uint32_t token);

static void bridge_NtClose(void)
{
    uint32_t raw_handle = STACK_ARG(0);

    if (g_kernel_call_count <= 400) {
        fprintf(stderr, "  [KERNEL] NtClose: handle=0x%08X\n", raw_handle);
        fflush(stderr);
    }

    /* Close real handles but skip fake/synthetic ones */
    if (raw_handle && raw_handle != 0xDEAD0001u && raw_handle != 0xBEEF0010u) {
        if (!bridge_close_mutant(raw_handle)) {
            HANDLE h = bridge_take_handle(raw_handle);
            if (h && h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    }
    g_eax = 0; /* STATUS_SUCCESS */
}

/* ── MmAllocateContiguousMemory (ordinal 165) ─────────────
 * PVOID MmAllocateContiguousMemory(ULONG NumberOfBytes)
 */
static uint32_t bridge_alloc_contiguous(uint32_t size, uint32_t align);

static void bridge_MmAllocateContiguousMemory(void)
{
    uint32_t size = STACK_ARG(0);

    uint32_t xbox_va = bridge_alloc_contiguous(size, 4096);

    if (g_kernel_call_count <= 1000) {
        fprintf(stderr, "  [KERNEL] MmAllocateContiguousMemory: size=%u → Xbox VA 0x%08X\n",
                size, xbox_va);
        fflush(stderr);
    }
    /* TEMP: unconditional trace for allocations landing in the address range
     * under active investigation (a resource-descriptor bug -- see
     * diagnostics/menu_recovery_2026-09-20.md), regardless of
     * g_kernel_call_count, since the real allocation of interest happens
     * well past the first 1000 calls. */
    if (xbox_va >= 0x80160000u && xbox_va < 0x80170000u) {
        fprintf(stderr, "  [KERNEL-WATCH] MmAllocateContiguousMemory: size=%u -> Xbox VA 0x%08X (call#%u)\n",
                size, xbox_va, g_kernel_call_count);
        fflush(stderr);
    }

    g_eax = xbox_va;
}

/* ── MmAllocateContiguousMemoryEx (ordinal 166) ───────────
 * PVOID MmAllocateContiguousMemoryEx(SIZE_T size, ULONG_PTR low, ULONG_PTR high,
 *                                     ULONG alignment, ULONG protect)
 */
/* Contiguous memory is addressed through the physical-memory mirror: physical
 * page P is visible at 0x80000000 + P. Titles that pin buffers at fixed
 * physical addresses check the returned pointer against that, so the address
 * has to be honoured rather than satisfied from the general heap. */
#define XBOX_PHYSICAL_MIRROR_BASE 0x80000000u
#define XBOX_PHYSICAL_MIRROR_TOP  (XBOX_PHYSICAL_MIRROR_BASE + XBOX_CONTIG_SIZE)

typedef struct bridge_contiguous_block {
    uint32_t addr;
    uint32_t size;
    int free;
} bridge_contiguous_block;

static bridge_contiguous_block g_contiguous_blocks[512];
static int g_contiguous_block_count;
/* Retail XAPI's small-allocation arena (guest 0x0029870E) owns the
 * first physical page and fills its allocations with 0xCC. It is not
 * available to MmAllocateContiguousMemoryEx: overlapping it destroys
 * long-lived resource factory tables during later startup allocations. */
static uint32_t g_contiguous_next = XBOX_PHYSICAL_MIRROR_BASE + 0x1000u;

static uint32_t bridge_alloc_contiguous(uint32_t size, uint32_t align)
{
    uint32_t addr;
    int i;
    {
        static long s_n;
        long n = ++s_n;
        if (n <= 20 || (n % 100000) == 0)
            fprintf(stderr, "  [ALLOC-CONTIG] #%ld size=%u align=%u XBOX_CONTIG_SIZE=%u\n",
                    n, size, align, (unsigned)XBOX_CONTIG_SIZE);
    }
    if (align < 4096) align = 4096;
    if (size == 0) size = 4096;
    /* Reject outright anything that can't possibly fit, before any
     * addr+size arithmetic that could wrap around in 32-bit unsigned math
     * and slip past the overflow/bounds checks below. Titles that probe
     * "how much contiguous memory is available" via repeated
     * alloc-then-free-then-double-the-size loops rely on this call
     * eventually failing once the request exceeds the pool; on real
     * Xbox hardware (64MB total RAM) that happens quickly, but a
     * same-iteration integer overflow here (size doubling all the way
     * toward 2^32) could otherwise make addr+size wrap back below
     * XBOX_PHYSICAL_MIRROR_TOP and appear to succeed, so the probe loop
     * never sees a failure and spins forever. */
    if (size > XBOX_CONTIG_SIZE)
        return 0;
    for (i = 0; i < g_contiguous_block_count; ++i) {
        bridge_contiguous_block *b = &g_contiguous_blocks[i];
        if (b->free && b->size >= size && !(b->addr & (align - 1))) {
            b->free = 0;
            memset((void *)((uintptr_t)b->addr + g_xbox_mem_offset), 0, size);
            return b->addr;
        }
    }
    addr = (g_contiguous_next + align - 1) & ~(align - 1);
    if (addr < XBOX_PHYSICAL_MIRROR_BASE || addr + size < addr ||
        addr + size > XBOX_PHYSICAL_MIRROR_TOP ||
        g_contiguous_block_count >= (int)(sizeof(g_contiguous_blocks) / sizeof(g_contiguous_blocks[0])))
        return 0;
    g_contiguous_blocks[g_contiguous_block_count++] =
        (bridge_contiguous_block){ addr, size, 0 };
    g_contiguous_next = addr + size;
    memset((void *)((uintptr_t)addr + g_xbox_mem_offset), 0, size);
    return addr;
}

static int bridge_free_contiguous(uint32_t addr)
{
    int i;
    for (i = 0; i < g_contiguous_block_count; ++i) {
        if (g_contiguous_blocks[i].addr == addr) {
            if (i == g_contiguous_block_count - 1 &&
                g_contiguous_blocks[i].addr + g_contiguous_blocks[i].size == g_contiguous_next) {
                g_contiguous_next = g_contiguous_blocks[i].addr;
                --g_contiguous_block_count;
                return 1;
            }
            g_contiguous_blocks[i].free = 1;
            return 1;
        }
    }
    return 0;
}

static void bridge_MmAllocateContiguousMemoryEx(void)
{
    uint32_t size = STACK_ARG(0);
    uint32_t low = STACK_ARG(1);
    uint32_t high = STACK_ARG(2);
    uint32_t align = STACK_ARG(3);
    uint32_t prot = STACK_ARG(4);
    uint32_t xbox_va;

    (void)prot;

    {
        static long s_n2;
        long n = ++s_n2;
        if (n <= 10) {
            int k;
            fprintf(stderr, "  [MMACME-ENTRY] #%ld size=%u low=0x%08X high=0x%08X align=%u g_esp=0x%08X\n",
                    n, size, low, high, align, g_esp);
            for (k = -8; k <= 24; ++k) {
                uint32_t v = BRIDGE_MEM32(g_esp + k * 4);
                fprintf(stderr, "    [%3d] esp%+d = 0x%08X%s\n", k, k*4, v,
                        (v >= 0x00010000u && v < 0x00300000u) ? "  <-- looks like guest code" : "");
            }
        }
    }

    /*
     * A caller that constrains the range to exactly one allocation's worth is
     * demanding a specific physical address, not expressing a preference.
     * Halo does this for its two big pools and asserts on the result
     * (physical_memory_map.c:46) - XPhysicalAlloc passes lowest = the address
     * it wants and highest = lowest + size - 1, then requires
     * 0x80000000 | lowest back. Satisfying that from the heap fails the assert
     * and leaves its whole memory map wrong.
     */
    if (low && high >= low && (high - low + 1) <= size + 0x1000) {
        xbox_va = XBOX_PHYSICAL_MIRROR_BASE + low;

        /* The console hands out zeroed pages here, and titles rely on it:
         * pool headers and free-list roots are assumed clear, so whatever the
         * backing view happened to contain shows up later as structures that
         * are "allocated" but full of garbage. */
        memset((void *)((uintptr_t)xbox_va + g_xbox_mem_offset), 0, size);

        if (g_kernel_call_count <= 1000 ||
            (xbox_va >= 0x80160000u && xbox_va < 0x80170000u)) {  /* TEMP watch */
            uint32_t caller = g_esp >= 4 ? BRIDGE_MEM32(g_esp - 4) : 0;
            fprintf(stderr, "  [KERNEL] MmAllocateContiguousMemoryEx: caller=0x%08X size=%u "
                    "pinned phys 0x%08X -> Xbox VA 0x%08X (zeroed)\n",
                    caller, size, low, xbox_va);
            fflush(stderr);
        }
        g_eax = xbox_va;
        return;
    }

    if (align < 4096) align = 4096;
    xbox_va = bridge_alloc_contiguous(size, align);

    if (g_kernel_call_count <= 1000 || size >= 0x01000000u ||
        (xbox_va >= 0x80160000u && xbox_va < 0x80170000u)) {  /* TEMP watch, see menu_recovery doc */
        /* The thunk dispatcher has already consumed the guest return address,
         * so it remains one dword below the current simulated stack pointer.
         * Keep large-allocation call sites visible even after the general
         * kernel trace throttle expires; D3D probes available memory by
         * deliberately requesting progressively larger contiguous blocks. */
        uint32_t caller = g_esp >= 4 ? BRIDGE_MEM32(g_esp - 4) : 0;
        /* This title reaches the thunk through its five-argument
         * XPhysicalAlloc wrapper.  Its saved ESI, EBP, and caller return sit
         * immediately after the five kernel arguments. */
        uint32_t parent = BRIDGE_MEM32(g_esp + 28);
        uint32_t origin = BRIDGE_MEM32(g_esp + 56);
        fprintf(stderr, "  [KERNEL] MmAllocateContiguousMemoryEx: caller=0x%08X parent=0x%08X origin=0x%08X size=%u low=0x%08X high=0x%08X align=%u → Xbox VA 0x%08X\n",
                caller, parent, origin, size, low, high, align, xbox_va);
        fflush(stderr);
    }

    g_eax = xbox_va;
}

/* ── MmFreeContiguousMemory (ordinal 171) ─────────────────
 * VOID MmFreeContiguousMemory(PVOID BaseAddress)
 */
static void bridge_MmFreeContiguousMemory(void)
{
    static int free_trace_count;
    uint32_t addr = STACK_ARG(0);
    int found = bridge_free_contiguous(addr);
    if (free_trace_count++ < 64) {
        fprintf(stderr, "  [KERNEL] MmFreeContiguousMemory: addr=0x%08X contiguous=%d\n",
                addr, found);
        fflush(stderr);
    }
    if (!found)
        xbox_HeapFree(addr);
    g_eax = 0;
}

/* ── NtAllocateVirtualMemory (ordinal 184) ────────────────
 * NTSTATUS NtAllocateVirtualMemory(PVOID *BaseAddress, ULONG ZeroBits,
 *     PULONG AllocationSize, ULONG AllocationType, ULONG Protect)
 */
static void bridge_NtAllocateVirtualMemory(void)
{
    static int alloc_trace_count;
    static uint32_t reserve_next = 0x04000000u;
    uint32_t base_ptr = STACK_ARG(0);  /* PVOID* in Xbox VA */
    uint32_t zero_bits = STACK_ARG(1);
    uint32_t size_ptr = STACK_ARG(2);  /* PULONG in Xbox VA */
    uint32_t alloc_type = STACK_ARG(3);
    uint32_t protect = STACK_ARG(4);

    if (alloc_trace_count++ < 32) {
        fprintf(stderr, "  [VMALLOC] base_ptr=%08X base=%08X size_ptr=%08X size=%u type=%08X protect=%08X esp=%08X\n",
                base_ptr, base_ptr ? BRIDGE_MEM32(base_ptr) : 0, size_ptr,
                size_ptr ? BRIDGE_MEM32(size_ptr) : 0, alloc_type, protect, g_esp);
        fflush(stderr);
    }

    /* Read the requested size from Xbox memory */
    uint32_t size = size_ptr ? BRIDGE_MEM32(size_ptr) : 0;
    /* Read the base address hint (0 = let kernel choose) */
    uint32_t base_hint = base_ptr ? BRIDGE_MEM32(base_ptr) : 0;

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] NtAllocateVirtualMemory: base=0x%08X size=%u type=0x%X prot=0x%X\n",
                base_hint, size, alloc_type, protect);
        fflush(stderr);
    }

    if (size == 0) {
        g_eax = 0xC0000045u; /* STATUS_INVALID_PAGE_PROTECTION */
        return;
    }

    /*
     * Xbox NtAllocateVirtualMemory supports two modes:
     * - MEM_RESERVE (0x2000): Reserve virtual address space
     * - MEM_COMMIT  (0x1000): Commit pages within a reserved region
     * - MEM_RESERVE|MEM_COMMIT (0x3000): Both in one call
     *
     * Our Xbox heap (bump allocator) always commits memory immediately,
     * so MEM_COMMIT on an already-reserved region is a no-op.
     * Only allocate new memory when MEM_RESERVE is requested.
     */
    if (base_hint != 0 && (alloc_type & 0x2000) == 0) {
        /* MEM_COMMIT only, on an already-reserved region.
         * The memory is already committed by our bump allocator.
         * Don't change the base address - just return success. */
        if (g_kernel_call_count <= 200) {
            fprintf(stderr, "  [KERNEL] → MEM_COMMIT on existing region 0x%08X, no-op\n", base_hint);
            fflush(stderr);
        }
        memset((void *)((uintptr_t)base_hint + g_xbox_mem_offset), 0, size);
        g_eax = 0; /* STATUS_SUCCESS */
        return;
    }

    /* A pure MEM_RESERVE consumes virtual address space, not physical RAM.
     * Keep it out of the 48 MiB physical heap; the memory-layout layer maps
     * Xbox RAM mirrors through this range so later small commits are valid. */
    if ((alloc_type & 0x3000) == 0x2000) {
        uint32_t rounded = (size + 0xFFFFu) & ~0xFFFFu;
        uint32_t xbox_va = (reserve_next + 0xFFFFu) & ~0xFFFFu;
        if (rounded < size || xbox_va > 0x70000000u - rounded) {
            g_eax = 0xC0000017u; /* STATUS_NO_MEMORY */
            return;
        }
        reserve_next = xbox_va + rounded;
        if (base_ptr) BRIDGE_MEM32(base_ptr) = xbox_va;
        if (size_ptr) BRIDGE_MEM32(size_ptr) = rounded;
        g_eax = 0;
        return;
    }

    /* Allocate from Xbox heap (MEM_RESERVE or MEM_RESERVE|MEM_COMMIT) */
    uint32_t xbox_va = xbox_HeapAlloc(size, 4096);
    if (!xbox_va) {
        g_eax = 0xC0000017u; /* STATUS_NO_MEMORY */
        return;
    }

    /* Write back the allocated address and actual size */
    if (base_ptr) BRIDGE_MEM32(base_ptr) = xbox_va;
    if (size_ptr) BRIDGE_MEM32(size_ptr) = size;

    g_eax = 0; /* STATUS_SUCCESS */
}

/* ── NtFreeVirtualMemory (ordinal 199) ────────────────────
 * NTSTATUS NtFreeVirtualMemory(PVOID *BaseAddress, PULONG FreeSize,
 *     ULONG FreeType)
 */
static void bridge_NtFreeVirtualMemory(void)
{
    uint32_t base_ptr = STACK_ARG(0);
    uint32_t size_ptr = STACK_ARG(1);
    uint32_t free_type = STACK_ARG(2);

    g_eax = (uint32_t)xbox_NtFreeVirtualMemory(
        XBOX_TO_NATIVE(base_ptr), XBOX_TO_NATIVE(size_ptr), free_type);
}

/* ── ExAllocatePool / ExAllocatePoolWithTag (ordinals 15, 16) ─
 * Must allocate from Xbox heap so the returned pointer is an Xbox VA
 * that can be accessed via MEM32(). Native HeapAlloc returns 64-bit
 * pointers that get truncated and produce garbage Xbox VAs.
 */
/* ExQueryNonVolatileSetting(ValueIndex, Type, Value, ValueLength, ResultLength)
 *
 * Titles read region, language and AV settings from EEPROM through this very
 * early in boot. Ordinal 24 was previously routed to bridge_ExQueryPoolBlockSize,
 * so the call returned a pool size where the game expected a settings blob. */
static void bridge_ExQueryNonVolatileSetting(void)
{
    uint32_t value_index  = STACK_ARG(0);
    uint32_t type_va      = STACK_ARG(1);
    uint32_t value_va     = STACK_ARG(2);
    uint32_t value_length = STACK_ARG(3);
    uint32_t result_va    = STACK_ARG(4);

    NTSTATUS st = xbox_ExQueryNonVolatileSetting(
        value_index,
        type_va   ? (PULONG)&BRIDGE_MEM32(type_va)   : NULL,
        value_va  ? (PVOID)((uintptr_t)value_va + g_xbox_mem_offset) : NULL,
        value_length,
        result_va ? (PULONG)&BRIDGE_MEM32(result_va) : NULL);

    g_eax = (uint32_t)st;
}

/* HalReturnToFirmware(Routine) - the title asking to reboot or quit.
 *
 * It never returns on hardware. Returning here would let the game run on past
 * a decision to quit, which reads as a hang rather than an exit. */
static void bridge_HalReturnToFirmware(void)
{
    uint32_t routine = STACK_ARG(0);

    fprintf(stderr, "  [KERNEL] HalReturnToFirmware: routine=%u - title is exiting\n",
            routine);
    fflush(stderr);

    xbox_HalReturnToFirmware(routine);
}

static void bridge_ExAllocatePool(void)
{
    uint32_t size = STACK_ARG(0);
    uint32_t xbox_va = xbox_HeapAlloc(size, 16);

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] ExAllocatePool: size=%u → Xbox VA 0x%08X\n",
                size, xbox_va);
        fflush(stderr);
    }

    g_eax = xbox_va;
}

static void bridge_ExAllocatePoolWithTag(void)
{
    uint32_t size = STACK_ARG(0);
    uint32_t tag = STACK_ARG(1);
    uint32_t xbox_va = xbox_HeapAlloc(size, 16);

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] ExAllocatePoolWithTag: size=%u tag='%c%c%c%c' → Xbox VA 0x%08X\n",
                size,
                (char)(tag & 0xFF), (char)((tag >> 8) & 0xFF),
                (char)((tag >> 16) & 0xFF), (char)((tag >> 24) & 0xFF),
                xbox_va);
        fflush(stderr);
    }

    g_eax = xbox_va;
}

/* ── KfRaiseIrql / KfLowerIrql (ordinals 160, 161) ────── */
static void bridge_KfRaiseIrql(void)
{
    uint32_t new_irql = STACK_ARG(0);
    g_eax = (uint32_t)xbox_KfRaiseIrql((UCHAR)new_irql);
}

static void bridge_KfLowerIrql(void)
{
    uint32_t new_irql = STACK_ARG(0);
    xbox_KfLowerIrql((UCHAR)new_irql);
    g_eax = 0;
}

/* ── KeRaiseIrqlToDpcLevel (ordinal 129) ─────────────────── */
static void bridge_KeRaiseIrqlToDpcLevel(void)
{
    g_eax = (uint32_t)xbox_KeRaiseIrqlToDpcLevel();
}

/* ── RtlInitializeCriticalSection / Enter / Leave (ordinals 291, 277, 294) ─ */
static void bridge_RtlInitializeCriticalSection(void)
{
    uint32_t cs_va = STACK_ARG(0);
    xbox_RtlInitializeCriticalSection(XBOX_TO_NATIVE(cs_va));
    g_eax = 0;
}

static void bridge_RtlEnterCriticalSection(void)
{
    uint32_t cs_va = STACK_ARG(0);
    xbox_RtlEnterCriticalSection(XBOX_TO_NATIVE(cs_va));
    g_eax = 0;
}

static void bridge_RtlLeaveCriticalSection(void)
{
    uint32_t cs_va = STACK_ARG(0);
    xbox_RtlLeaveCriticalSection(XBOX_TO_NATIVE(cs_va));
    g_eax = 0;
}

/* ── KeQueryPerformanceCounter / Frequency (ordinals 126, 127) ─ */
static void bridge_KeQueryPerformanceCounter(void)
{
    LARGE_INTEGER li = xbox_KeQueryPerformanceCounter();
    g_eax = (uint32_t)li.LowPart;
    g_edx = (uint32_t)li.HighPart;
}

static void bridge_KeQueryPerformanceFrequency(void)
{
    LARGE_INTEGER li = xbox_KeQueryPerformanceFrequency();
    g_eax = (uint32_t)li.LowPart;
    g_edx = (uint32_t)li.HighPart;
}

/* ── KeQuerySystemTime (ordinal 128) ─────────────────────── */
static void bridge_KeQuerySystemTime(void)
{
    uint32_t time_ptr = STACK_ARG(0);
    xbox_KeQuerySystemTime(XBOX_TO_NATIVE(time_ptr));
    g_eax = 0;
}

/* ── MmQueryStatistics (ordinal 181) ─────────────────────── */
static void bridge_MmQueryStatistics(void)
{
    uint32_t stats_ptr = STACK_ARG(0);
    g_eax = (uint32_t)xbox_MmQueryStatistics(XBOX_TO_NATIVE(stats_ptr));
}

/* ── NtCreateEvent (ordinal 189) ─────────────────────────── */
static void bridge_NtCreateEvent(void)
{
    uint32_t handle_ptr = STACK_ARG(0);
    uint32_t obj_attr_ptr = STACK_ARG(1);
    uint32_t event_type = STACK_ARG(2);
    uint32_t initial_state = STACK_ARG(3);

    /* Use local HANDLE to avoid 8-byte write to 4-byte Xbox memory slot.
     * On x64, HANDLE is 8 bytes but Xbox expects 4-byte handles. */
    HANDLE local_handle = NULL;
    NTSTATUS status = xbox_NtCreateEvent(
        &local_handle,
        XBOX_TO_NATIVE(obj_attr_ptr),
        event_type, initial_state);

    if (handle_ptr) {
        bridge_write_handle(handle_ptr, local_handle);
    }

    fprintf(stderr, "  [BRIDGE] NtCreateEvent: handle_ptr=0x%08X type=%u init=%u → status=0x%08X handle=0x%08X\n",
            handle_ptr, event_type, initial_state, (uint32_t)status,
            (uint32_t)(uintptr_t)local_handle);

    g_eax = (uint32_t)status;
}

/* ── KeSetEvent (ordinal 145) ────────────────────────────── */
static void bridge_KeSetEvent(void)
{
    uint32_t event_ptr = STACK_ARG(0);
    uint32_t increment = STACK_ARG(1);
    uint32_t wait = STACK_ARG(2);

    g_eax = (uint32_t)xbox_KeSetEvent(XBOX_TO_NATIVE(event_ptr), increment, (BOOLEAN)wait);
}

/* ── KeWaitForSingleObject (ordinal 159) ─────────────────── */
static void bridge_KeWaitForSingleObject(void)
{
    uint32_t object = STACK_ARG(0);
    uint32_t wait_reason = STACK_ARG(1);
    uint32_t wait_mode = STACK_ARG(2);
    uint32_t alertable = STACK_ARG(3);
    uint32_t timeout_ptr = STACK_ARG(4);
    PLARGE_INTEGER native_timeout = (PLARGE_INTEGER)XBOX_TO_NATIVE(timeout_ptr);
    LARGE_INTEGER fallback_timeout;

    /* Same bounded-INFINITE-wait treatment as bridge_NtWaitForSingleObjectEx
     * below: a NULL timeout trusts something else to eventually signal this
     * object, which this recompilation cannot always guarantee. Bound it
     * instead of risking a permanent hang. */
    if (!timeout_ptr) {
        static long s_infinite_wait_count;
        long n = ++s_infinite_wait_count;
        if (n <= 20 || (n % 500) == 0)
            fprintf(stderr, "  [KERNEL] KeWaitForSingleObject: INFINITE wait "
                    "on object=0x%08X bounded to 5s (#%ld)\n", object, n);
        fallback_timeout.QuadPart = -50000000LL;
        native_timeout = &fallback_timeout;
    }

    g_eax = (uint32_t)xbox_KeWaitForSingleObject(
        XBOX_TO_NATIVE(object), wait_reason, wait_mode,
        (BOOLEAN)alertable, native_timeout);
}

static HANDLE bridge_resolve_handle(uint32_t token);
static NTSTATUS bridge_wait_mutant_token(uint32_t token,
                                         PLARGE_INTEGER timeout, int *handled);

/* ── NtWaitForSingleObject (ordinal 233) ─────────────────── */
/*
 * The synchronous sibling of ...Ex. Halo's synchronous ReadFile issues the read
 * and then waits on its completion event through this; unbridged it fell to the
 * "return 0" default (STATUS_SUCCESS = "already signalled"), so the read handshake
 * completed before the data arrived and the UI-map precache never made progress.
 */
static void bridge_NtWaitForSingleObject(void)
{
    uint32_t token       = STACK_ARG(0);
    HANDLE handle;
    uint32_t alertable   = STACK_ARG(1);
    uint32_t timeout_ptr = STACK_ARG(2);
    PLARGE_INTEGER native_timeout = (PLARGE_INTEGER)XBOX_TO_NATIVE(timeout_ptr);
    int mutant_handled = 0;
    NTSTATUS mutant_status = bridge_wait_mutant_token(
        token, native_timeout, &mutant_handled);

    if (mutant_handled) { g_eax = (uint32_t)mutant_status; return; }
    handle = bridge_resolve_handle(token);
    LARGE_INTEGER fallback_timeout;

    /* Same bounded-INFINITE-wait treatment as bridge_NtWaitForSingleObjectEx
     * below (its synchronous sibling) -- see that function's comment. */
    if (!timeout_ptr) {
        static long s_infinite_wait_count;
        long n = ++s_infinite_wait_count;
        if (n <= 20 || (n % 500) == 0)
            fprintf(stderr, "  [KERNEL] NtWaitForSingleObject: INFINITE wait "
                    "on token=0x%08X handle=%p bounded to 5s (#%ld)\n",
                    STACK_ARG(0), handle, n);
        fallback_timeout.QuadPart = -50000000LL;
        native_timeout = &fallback_timeout;
    }

    g_eax = (uint32_t)xbox_NtWaitForSingleObject(
        handle, (BOOLEAN)alertable, native_timeout);
}

/* ── NtClearEvent (ordinal 186) ──────────────────────────── */
/* Resets an event to non-signalled. Halo clears the read-completion event
 * before each async map read; a no-op here left the event stuck signalled. */
static void bridge_NtClearEvent(void)
{
    HANDLE handle = bridge_resolve_handle(STACK_ARG(0));
    g_eax = (uint32_t)xbox_NtClearEvent(handle);
}

/* ── NtSetEvent (ordinal 225) ────────────────────────────── */
/* Signals an event and optionally returns its previous state. Unbridged it
 * no-op'd, so a producer's "work ready" signal never landed -- Halo's map-copy
 * worker thread then slept forever in WaitForSingleObject on the decompress
 * context's go-event and only the first 14 KB of the map ever loaded. */
static void bridge_NtSetEvent(void)
{
    static LONG set_event_trace_count;
    uint32_t token = STACK_ARG(0);
    HANDLE   handle = bridge_resolve_handle(token);
    uint32_t prev   = STACK_ARG(1);
    g_eax = (uint32_t)xbox_NtSetEvent(handle, XBOX_TO_NATIVE(prev));
    if (InterlockedIncrement(&set_event_trace_count) <= 64) {
        fprintf(stderr,
                "  [KERNEL] NtSetEvent token=0x%08X handle=%p prev=0x%08X status=0x%08X thread=%lu\n",
                token, handle, prev, g_eax, (unsigned long)GetCurrentThreadId());
        fflush(stderr);
    }
}

/* ── NtPulseEvent (ordinal 205) ──────────────────────────── */
/* Signal-then-reset: releases threads currently waiting, then leaves the event
 * non-signalled. Same unbridged-no-op hazard as NtSetEvent in the map-load
 * handoff chain. PulseEvent carries the (deprecated, lossy) Xbox semantics
 * faithfully -- a waiter not yet blocked misses it, exactly as on hardware. */
static void bridge_NtPulseEvent(void)
{
    HANDLE handle = bridge_resolve_handle(STACK_ARG(0));
    if (handle) PulseEvent(handle);
    g_eax = 0;
}

/* ── NtWaitForSingleObjectEx (ordinal 234) ───────────────── */
/*
 * Unbridged, this fell through to the "no bridge, returning 0" default -- and 0
 * is STATUS_SUCCESS, so every wait returned instantly as though the object were
 * already signalled. Halo's main loop then spun: 91 million calls in 100
 * seconds, no blocking, no progress. A wait that always succeeds is worse than
 * one that always fails, because it looks like the game is running.
 */
static HANDLE bridge_resolve_handle(uint32_t token);

static void bridge_NtWaitForSingleObjectEx(void)
{
    uint32_t token       = STACK_ARG(0);
    HANDLE handle;
    uint32_t wait_mode   = STACK_ARG(1);
    uint32_t alertable   = STACK_ARG(2);
    uint32_t timeout_ptr = STACK_ARG(3);
    PLARGE_INTEGER native_timeout = (PLARGE_INTEGER)XBOX_TO_NATIVE(timeout_ptr);
    int mutant_handled = 0;
    NTSTATUS mutant_status = bridge_wait_mutant_token(
        token, native_timeout, &mutant_handled);

    if (mutant_handled) { g_eax = (uint32_t)mutant_status; return; }
    handle = bridge_resolve_handle(token);

    static int logged = 0;
    if (logged++ < 20) {
        fprintf(stderr, "  [KERNEL] NtWaitForSingleObjectEx: token=0x%08X "
                "handle=%p timeout=%s\n",
                STACK_ARG(0), handle, timeout_ptr ? "finite" : "INFINITE");
        fflush(stderr);
    }

    g_eax = (uint32_t)xbox_NtWaitForSingleObjectEx(
        handle, (KPROCESSOR_MODE)wait_mode, (BOOLEAN)alertable,
        native_timeout);
}

/* ── NtWaitForMultipleObjectsEx (ordinal 235) ─────────────── */
static void bridge_NtWaitForMultipleObjectsEx(void)
{
    enum { XBOX_MAXIMUM_WAIT_OBJECTS = 64 };
    HANDLE native_handles[XBOX_MAXIMUM_WAIT_OBJECTS];
    uint32_t count = STACK_ARG(0);
    uint32_t handles_va = STACK_ARG(1);
    uint32_t wait_type = STACK_ARG(2);
    uint32_t wait_mode = STACK_ARG(3);
    uint32_t alertable = STACK_ARG(4);
    uint32_t timeout_va = STACK_ARG(5);
    uint32_t i;

    if (count == 0 || count > XBOX_MAXIMUM_WAIT_OBJECTS || !handles_va) {
        g_eax = (uint32_t)STATUS_INVALID_PARAMETER;
        return;
    }

    /* Xbox HANDLEs are 32-bit guest tokens. Build a native-width array;
     * casting the guest array directly would read pairs of tokens as one
     * HANDLE in the 64-bit host process. */
    for (i = 0; i < count; ++i) {
        uint32_t token = BRIDGE_MEM32(handles_va + i * sizeof(uint32_t));
        native_handles[i] = bridge_resolve_handle(token);
    }

    /* Xbox's kernel export has six stack arguments.  The host helper has no
     * kernel/user-mode distinction, so WaitMode is intentionally ignored,
     * but it must still occupy its ABI slot (and be popped by the thunk). */
    (void)wait_mode;
    g_eax = (uint32_t)xbox_NtWaitForMultipleObjectsEx(
        count, native_handles, wait_type, (BOOLEAN)alertable,
        (PLARGE_INTEGER)XBOX_TO_NATIVE(timeout_va));
}

/* ── MmQueryAddressProtect (ordinal 179) ─────────────────── */
/*
 * Takes an Xbox VA, so the native pointer has to be formed before the query --
 * an unbridged 0 return reads as PAGE_NOACCESS. Halo walks all 22 MB of its
 * physical memory map asserting every page is PAGE_READWRITE
 * (physical_memory_map.c:77), so a zero here stops startup on the first page.
 */
static void bridge_MmQueryAddressProtect(void)
{
    uint32_t address = STACK_ARG(0);

    g_eax = address ? (uint32_t)xbox_MmQueryAddressProtect(XBOX_TO_NATIVE(address))
                    : 0;
}

/* ── NtUserIoApcDispatcher (ordinal 232) ─────────────────── */
/*
 * The kernel side of XAPI's ReadFileEx/WriteFileEx. XAPI passes *this* as the
 * ApcRoutine to NtReadFile and puts the title's completion routine in
 * ApcContext, so the dispatcher's only job is to call it with Win32 argument
 * shape:
 *
 *   VOID CALLBACK Completion(DWORD dwErrorCode,
 *                            DWORD dwNumberOfBytesTransfered,
 *                            LPOVERLAPPED lpOverlapped)   // __stdcall, ret 12
 *
 * lpOverlapped is the IO_STATUS_BLOCK pointer: an NT OVERLAPPED begins with
 * Internal/InternalHigh, which is exactly a IO_STATUS_BLOCK, so the title's
 * OVERLAPPED and the block it handed to NtReadFile are the same address.
 * Halo's cache_files_windows completion relies on that -- it reads its own
 * field at lpOverlapped+0x10 and sets the flag the setup loop polls.
 */
static void bridge_NtUserIoApcDispatcher(void)
{
    uint32_t apc_context = STACK_ARG(0);
    uint32_t iostatus    = STACK_ARG(1);
    uint32_t status      = iostatus ? BRIDGE_MEM32(iostatus) : 0;
    uint32_t information = iostatus ? BRIDGE_MEM32(iostatus + 4) : 0;
    recomp_func_t fn;

    fn = recomp_lookup(apc_context);
    if (!fn) fn = recomp_lookup_manual(apc_context);
    if (!fn) {
        fprintf(stderr, "  [KERNEL] NtUserIoApcDispatcher: completion routine "
                "0x%08X not in dispatch\n", apc_context);
        fflush(stderr);
        g_eax = 0;
        return;
    }

    /* __stdcall, right-to-left. The callee's `ret 12` consumes the dummy
     * return address and all three arguments, so g_esp needs no fixup here. */
    g_esp -= 4; BRIDGE_MEM32(g_esp) = iostatus;
    g_esp -= 4; BRIDGE_MEM32(g_esp) = information;
    g_esp -= 4; BRIDGE_MEM32(g_esp) = (status == 0) ? 0 : status;
    g_esp -= 4; BRIDGE_MEM32(g_esp) = 0;
    fn();

    g_eax = 0;
}

/* ── KeDelayExecutionThread (ordinal 99) ─────────────────── */
/* Unbridged this returned instantly, turning every "sleep and retry" in the
 * title into a hot spin. Halo's cache-partition setup retries this way. */
static void bridge_KeDelayExecutionThread(void)
{
    uint32_t wait_mode    = STACK_ARG(0);
    uint32_t alertable    = STACK_ARG(1);
    uint32_t interval_ptr = STACK_ARG(2);


    g_eax = (uint32_t)xbox_KeDelayExecutionThread(
        (KPROCESSOR_MODE)wait_mode, (BOOLEAN)alertable,
        XBOX_TO_NATIVE(interval_ptr));
}

/* ── KeBugCheck (ordinal 95) / KeBugCheckEx (96) ─────────── */
/*
 * The title asking the kernel to die. Unbridged this returned 0 and execution
 * carried on into whatever the bug check was there to prevent, so the real
 * failure surfaced later somewhere unrelated. Report the code and stop
 * pretending the call succeeded.
 */
static void bridge_KeBugCheck(void)
{
    fprintf(stderr, "  [KERNEL] *** KeBugCheck: code=0x%08X ***\n",
            STACK_ARG(0));
    fflush(stderr);
    g_eax = 0;
}

static void bridge_KeBugCheckEx(void)
{
    fprintf(stderr, "  [KERNEL] *** KeBugCheckEx: code=0x%08X "
            "(0x%08X, 0x%08X, 0x%08X, 0x%08X) ***\n",
            STACK_ARG(0), STACK_ARG(1), STACK_ARG(2),
            STACK_ARG(3), STACK_ARG(4));
    fflush(stderr);
    g_eax = 0;
}

/* ── NtYieldExecution (ordinal 238) ──────────────────────── */
static void bridge_NtYieldExecution(void)
{
    g_eax = (uint32_t)xbox_NtYieldExecution();
}

/* ── MmGetPhysicalAddress (ordinal 173) ──────────────────── */
static void bridge_MmGetPhysicalAddress(void)
{
    uint32_t addr = STACK_ARG(0);
    /* Xbox RAM is mirrored throughout the 32-bit virtual address space.  The
     * NV2A consumes an offset into physical RAM, not the mirrored CPU VA.  In
     * particular DAH2's dynamic title/UI vertices are allocated around
     * 0x30xxxxxx; returning that VA unchanged makes the GPU reader reject the
     * otherwise valid vertex arrays as being outside RAM. */
    if (g_xbox_total_ram && !(g_xbox_total_ram & (g_xbox_total_ram - 1)))
        g_eax = addr & (uint32_t)(g_xbox_total_ram - 1);
    else if (g_xbox_total_ram)
        g_eax = addr % (uint32_t)g_xbox_total_ram;
    else
        g_eax = addr;
}

/* ── MmSetAddressProtect (ordinal 182) ───────────────────── */
static void bridge_MmSetAddressProtect(void)
{
    uint32_t addr = STACK_ARG(0);
    uint32_t size = STACK_ARG(1);
    uint32_t prot = STACK_ARG(2);

    xbox_MmSetAddressProtect(XBOX_TO_NATIVE(addr), size, prot);
    g_eax = 0;
}

/* ── AvSetDisplayMode (ordinal 3) ────────────────────────── */
static void bridge_AvSetDisplayMode(void)
{
    uint32_t addr = STACK_ARG(0);
    uint32_t step = STACK_ARG(1);
    uint32_t mode = STACK_ARG(2);
    uint32_t format = STACK_ARG(3);
    uint32_t pitch = STACK_ARG(4);
    uint32_t fb = STACK_ARG(5);

    xbox_AvSetDisplayMode(XBOX_TO_NATIVE(addr), step, mode, format, pitch, fb);
    g_eax = 0;
}

/* ── PsTerminateSystemThread (ordinal 258) ───────────────
 * VOID PsTerminateSystemThread(NTSTATUS ExitStatus)
 *
 * On real Xbox, this terminates the calling thread (never returns).
 * In our recompiled version, threads run synchronously, so we just
 * return. The caller (sub_001D1818) handles this gracefully.
 */
static void bridge_PsTerminateSystemThread(void)
{
    uint32_t exit_status = STACK_ARG(0);

    fprintf(stderr, "  [KERNEL] PsTerminateSystemThread: status=0x%08X%s\n",
            exit_status, g_is_spawned_thread ? " (worker)" : " (main)");
    fflush(stderr);

    g_eax = exit_status;

    /*
     * This does not return on hardware. Returning was survivable while every
     * thread ran on the host's main thread, but a spawned worker that returns
     * here falls off the end of its start routine and into whatever bytes
     * follow -- Halo's input worker landed on an int 3, and the resulting
     * breakpoint took down the whole process while the main thread was still
     * inside input_initialize.
     *
     * The main thread still returns: it is the host's thread and unwinding
     * back to main() is how the process shuts down cleanly.
     */
    if (g_is_spawned_thread) {
        /* No guest-stack reads occur after release: ExitThread is native and
         * noreturn. Normal return owns the alternative cleanup path. */
        bridge_release_thread_stack();
        ExitThread(exit_status);
    }
}

/* ── HalReadSMCTrayState (ordinal 47) ─────────────────────
 * VOID HalReadSMCTrayState(PDWORD TrayState, PDWORD TrayStateChangeCount)
 *
 * Returns DVD tray state. 0x10 = no disc, 0x14 = tray closed with disc.
 */
static void bridge_HalReadSMCTrayState(void)
{
    uint32_t state_ptr = STACK_ARG(0);
    uint32_t count_ptr = STACK_ARG(1);

    if (state_ptr) BRIDGE_MEM32(state_ptr) = 0x10;  /* No disc */
    if (count_ptr) BRIDGE_MEM32(count_ptr) = 0;
    g_eax = 0;
}

/* ── KeInitializeDpc (ordinal 107) ────────────────────────
 * VOID KeInitializeDpc(PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine,
 *                       PVOID DeferredContext)
 *
 * Initializes a DPC object. The Xbox KDPC structure is 32 bytes.
 * We zero it and set the routine and context pointers.
 */
static void bridge_KeInitializeDpc(void)
{
    uint32_t dpc_va = STACK_ARG(0);
    uint32_t routine = STACK_ARG(1);
    uint32_t context = STACK_ARG(2);

    /* Zero the structure (32 bytes) */
    memset(XBOX_TO_NATIVE(dpc_va), 0, 32);

    /* Set Type (0x13 = DpcObject) and fields */
    BRIDGE_MEM16(dpc_va + 0) = 0x13;   /* Type */
    BRIDGE_MEM32(dpc_va + 12) = routine; /* DeferredRoutine */
    BRIDGE_MEM32(dpc_va + 16) = context; /* DeferredContext */
    g_eax = 0;
}

/* ── NV2A interrupt plumbing (ordinals 44, 98, 109) ───────
 *
 * The D3D8 library linked into a title installs an ISR for the GPU's vblank /
 * command-completion interrupt. There is no NV2A here and nothing ever raises
 * that interrupt, so these exist to let initialisation complete rather than to
 * deliver anything.
 *
 * KeConnectInterrupt reports success: reporting failure sends Halo's
 * rasterizer down an error path during preinitialize, and the goal is to get
 * past setup, not to pretend the hardware is broken.
 *
 * ponytail: no interrupt is ever delivered. Code that *waits* on the ISR
 * rather than polling will hang here, and the fix for that is to bridge the
 * D3D8 entry point that owns the wait, not to synthesise NV2A interrupts.
 */

/* ULONG HalGetInterruptVector(ULONG BusInterruptLevel, PKIRQL Irql) */
static void bridge_HalGetInterruptVector(void)
{
    uint32_t level   = STACK_ARG(0);
    uint32_t irql_va = STACK_ARG(1);

    if (irql_va) {
        /* IRQL is conventionally the vector for device interrupts. */
        BRIDGE_MEM8(irql_va) = (uint8_t)level;
    }
    g_eax = level;
}

/* VOID KeInitializeInterrupt(PKINTERRUPT, ServiceRoutine, ServiceContext,
 *                            Vector, Irql, InterruptMode, ShareVector) */
static void bridge_KeInitializeInterrupt(void)
{
    uint32_t interrupt_va = STACK_ARG(0);
    uint32_t routine      = STACK_ARG(1);
    uint32_t context      = STACK_ARG(2);
    uint32_t vector       = STACK_ARG(3);

    /* Xbox KINTERRUPT is 44 bytes. */
    memset(XBOX_TO_NATIVE(interrupt_va), 0, 44);
    BRIDGE_MEM32(interrupt_va + 0)  = routine;
    BRIDGE_MEM32(interrupt_va + 4)  = context;
    BRIDGE_MEM32(interrupt_va + 8)  = vector;
    g_eax = 0;
}

/* Guest KINTERRUPT addresses this layer has reported as connected, so that
 * KeDisconnectInterrupt can answer with the real previous state without
 * touching a host-layout struct. 16 slots is far more than a title connects. */
static uint32_t g_connected_interrupts[16];

/* BOOLEAN KeConnectInterrupt(PKINTERRUPT Interrupt) */
static void bridge_KeConnectInterrupt(void)
{
    uint32_t interrupt = STACK_ARG(0);
    int i, free_slot = -1;

    for (i = 0; i < 16; ++i) {
        if (g_connected_interrupts[i] == interrupt) { free_slot = -2; break; }
        if (!g_connected_interrupts[i] && free_slot < 0) free_slot = i;
    }
    if (interrupt && free_slot >= 0)
        g_connected_interrupts[free_slot] = interrupt;
    g_eax = 1;  /* connected -- see the note above */
}

/* ── MmClaimGpuInstanceMemory (ordinal 168) ───────────────
 * PVOID MmClaimGpuInstanceMemory(SIZE_T NumberOfBytes, SIZE_T *Padding)
 *
 * Reserves the GPU instance memory the NV2A keeps its object context in. On
 * hardware it sits at the very top of physical RAM, so the returned address is
 * the end of the contiguous window minus the request. D3D8 stores this and
 * indexes off it, so returning 0 (the unbridged default) had it building
 * pointers from a null base.
 *
 * MAXULONG_PTR means "claim everything left"; the console answers with the
 * default instance size rather than the whole of RAM.
 */
static void bridge_MmClaimGpuInstanceMemory(void)
{
    uint32_t bytes      = STACK_ARG(0);
    uint32_t padding_va = STACK_ARG(1);

    if (bytes == 0xFFFFFFFFu) {
        bytes = XBOX_GPU_INSTANCE_DEFAULT;
    }
    if (padding_va) {
        BRIDGE_MEM32(padding_va) = 0;
    }
    g_eax = XBOX_CONTIG_BASE + XBOX_CONTIG_SIZE - bytes;
}

/* VOID HalRegisterShutdownNotification(PHAL_SHUTDOWN_REGISTRATION, BOOLEAN)
 * Records a callback for console shutdown. Nothing here ever shuts down that
 * way, so registration is accepted and dropped. */
static void bridge_HalRegisterShutdownNotification(void)
{
    g_eax = 0;
}

/* ── KeInitializeTimerEx (ordinal 113) ────────────────────
 * VOID KeInitializeTimerEx(PKTIMER Timer, TIMER_TYPE Type)
 *
 * Initializes a timer object. Xbox KTIMER is 40 bytes.
 */
static void bridge_KeInitializeTimerEx(void)
{
    uint32_t timer_va = STACK_ARG(0);
    uint32_t type = STACK_ARG(1);

    /* Zero the structure (40 bytes) */
    memset(XBOX_TO_NATIVE(timer_va), 0, 40);

    /* Set Type (0x08 = TimerNotificationObject, 0x09 = TimerSynchronizationObject) */
    BRIDGE_MEM16(timer_va + 0) = (uint16_t)(0x08 + (type & 1));
    g_eax = 0;
}

/* ── KeSetTimer / KeSetTimerEx (ordinal 149/150) ──────────
 * BOOLEAN KeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc)
 *
 * Sets a timer. We don't actually start timers - just record the state.
 * Returns FALSE (timer was not already set).
 */
static void bridge_KeSetTimer(void)
{
    /* Timer functionality is not needed for basic execution.
     * Return FALSE = timer was not previously set. */
    g_eax = 0;
}

/* ── ExQueryPoolBlockSize (ordinal 24) ────────────────────
 * ULONG ExQueryPoolBlockSize(PVOID PoolBlock)
 *
 * Returns the size of a pool memory block.
 * Since we use HeapAlloc, we can query the Windows heap.
 */
static void bridge_ExQueryPoolBlockSize(void)
{
    uint32_t block = STACK_ARG(0);
    /* Return a reasonable default size. Actual pool blocks are managed
     * by the kernel; for recompilation, returning 0 might be OK since
     * code usually uses this for debugging/stats. */
    g_eax = 0;
}

/* ── RtlNtStatusToDosError (ordinal 301) ─────────────────
 * ULONG RtlNtStatusToDosError(NTSTATUS Status)
 *
 * Converts an NTSTATUS to a Win32 error code.
 */
static void bridge_RtlNtStatusToDosError(void)
{
    uint32_t status = STACK_ARG(0);

    /* Simple mapping of common status codes */
    switch (status) {
    case 0x00000000: g_eax = 0; break;          /* STATUS_SUCCESS → ERROR_SUCCESS */
    case 0xC0000034: g_eax = 2; break;          /* STATUS_OBJECT_NAME_NOT_FOUND → ERROR_FILE_NOT_FOUND */
    case 0xC000003A: g_eax = 3; break;          /* STATUS_OBJECT_PATH_NOT_FOUND → ERROR_PATH_NOT_FOUND */
    case 0xC0000022: g_eax = 5; break;          /* STATUS_ACCESS_DENIED → ERROR_ACCESS_DENIED */
    case 0xC0000008: g_eax = 6; break;          /* STATUS_INVALID_HANDLE → ERROR_INVALID_HANDLE */
    case 0xC0000017: g_eax = 8; break;          /* STATUS_NO_MEMORY → ERROR_NOT_ENOUGH_MEMORY */
    case 0xC000000D: g_eax = 87; break;         /* STATUS_INVALID_PARAMETER → ERROR_INVALID_PARAMETER */
    default:         g_eax = 317; break;         /* ERROR_MR_MID_NOT_FOUND (generic) */
    }
}

/* ── File I/O bridge helpers ─────────────────────────────── */

/*
 * Xbox structures use 32-bit pointers. On Win64, the C structs
 * (XBOX_OBJECT_ATTRIBUTES, etc.) have 64-bit pointers, so we can't
 * cast Xbox memory to them directly. Instead, parse the 32-bit
 * Xbox layout manually:
 *
 * XBOX_OBJECT_ATTRIBUTES (12 bytes):
 *   offset 0: RootDirectory  (uint32_t)
 *   offset 4: ObjectName     (uint32_t, Xbox VA to ANSI_STRING)
 *   offset 8: Attributes     (uint32_t)
 *
 * XBOX_ANSI_STRING (8 bytes):
 *   offset 0: Length          (uint16_t)
 *   offset 2: MaximumLength   (uint16_t)
 *   offset 4: Buffer          (uint32_t, Xbox VA to char[])
 *
 * XBOX_IO_STATUS_BLOCK (8 bytes):
 *   offset 0: Status          (uint32_t)
 *   offset 4: Information     (uint32_t)
 */

/* Extract the ANSI path string from an Xbox OBJECT_ATTRIBUTES */
static const char* bridge_get_xbox_path(uint32_t obj_attrs_va)
{
    uint32_t ansi_str_va, buf_va;
    if (!obj_attrs_va) return NULL;
    ansi_str_va = BRIDGE_MEM32(obj_attrs_va + 4);
    if (!ansi_str_va) return NULL;
    buf_va = BRIDGE_MEM32(ansi_str_va + 4);
    if (!buf_va) return NULL;
    return (const char*)XBOX_TO_NATIVE(buf_va);
}

/* Write NTSTATUS + Information into Xbox IO_STATUS_BLOCK */
static void bridge_write_iostatus(uint32_t ios_va, NTSTATUS status, uint32_t info)
{
    if (ios_va) {
        BRIDGE_MEM32(ios_va + 0) = (uint32_t)status;
        BRIDGE_MEM32(ios_va + 4) = info;
    }
}

/*
 * Handle table.
 *
 * Xbox memory only has 32-bit handle slots, but native HANDLEs are 64-bit
 * pointers (win32_compat objects, or real Win32 handles on Windows). Map
 * 32-bit tokens <-> native HANDLEs so a handle survives a round-trip through
 * Xbox memory. Tokens carry a tag in the high byte so they never collide
 * with the synthetic handles (0xDEAD0001 / 0xBEEF0010) used elsewhere.
 */
#define BRIDGE_HANDLE_TAG  0x48000000u
#define BRIDGE_HANDLE_MASK 0x00FFFFFFu
#define BRIDGE_HANDLE_MAX  16384
static HANDLE s_handle_table[BRIDGE_HANDLE_MAX];

#define BRIDGE_HANDLE_KIND_NATIVE 0u
#define BRIDGE_HANDLE_KIND_MUTANT 1u
typedef struct BridgeMutant {
    CRITICAL_SECTION lock;
    DWORD owner_thread;
    LONG recursion;
} BridgeMutant;
static uint8_t s_handle_kind[BRIDGE_HANDLE_MAX];

static uint32_t bridge_handle_token(HANDLE h)
{
    int i;
    if (!h || h == INVALID_HANDLE_VALUE) return 0;
    for (i = 1; i < BRIDGE_HANDLE_MAX; i++)
        if (s_handle_table[i] == h) return BRIDGE_HANDLE_TAG | (uint32_t)i;
    for (i = 1; i < BRIDGE_HANDLE_MAX; i++)
        if (s_handle_table[i] == NULL) {
            s_handle_table[i] = h;
            return BRIDGE_HANDLE_TAG | (uint32_t)i;
        }
    fprintf(stderr, "  [BRIDGE] handle table full\n");
    return 0;
}

/* Store a native HANDLE into a 32-bit Xbox memory slot (as a token). */
static void bridge_write_handle(uint32_t handle_va, HANDLE h)
{
    static LONG handle_trace_count;
    if (handle_va) {
        uint32_t token = bridge_handle_token(h);
        BRIDGE_MEM32(handle_va) = token;
        if (InterlockedIncrement(&handle_trace_count) <= 32) {
            fprintf(stderr,
                    "  [BRIDGE] handle token=0x%08X native=%p out=0x%08X\n",
                    token, h, handle_va);
            fflush(stderr);
        }
    }
}
/* Xbox mutants are recursive ownership locks. A Win32 kernel mutex is
 * semantically close but extremely expensive in DAH2's Bink inner loop, which
 * acquires and releases an uncontended mutant thousands of times per frame.
 * CRITICAL_SECTION preserves recursive/cross-thread blocking semantics while
 * keeping the uncontended path in user mode. */
static BridgeMutant *bridge_mutant_from_token(uint32_t token)
{
    uint32_t index;
    if ((token & 0xFF000000u) != BRIDGE_HANDLE_TAG) return NULL;
    index = token & BRIDGE_HANDLE_MASK;
    if (!index || index >= BRIDGE_HANDLE_MAX ||
        s_handle_kind[index] != BRIDGE_HANDLE_KIND_MUTANT)
        return NULL;
    return (BridgeMutant *)s_handle_table[index];
}

static void bridge_note_mutant_acquire(BridgeMutant *mutant)
{
    DWORD thread = GetCurrentThreadId();
    if (mutant->owner_thread == thread)
        ++mutant->recursion;
    else {
        mutant->owner_thread = thread;
        mutant->recursion = 1;
    }
}

static DWORD bridge_mutant_timeout_ms(PLARGE_INTEGER timeout)
{
    LONGLONG ticks;
    if (!timeout) return INFINITE;
    ticks = timeout->QuadPart;
    if (ticks == 0) return 0;
    if (ticks < 0) {
        ULONGLONG relative = (ULONGLONG)(-(ticks + 1)) + 1u;
        ULONGLONG ms = (relative + 9999u) / 10000u;
        return ms >= INFINITE ? INFINITE - 1u : (DWORD)ms;
    }
    {
        FILETIME file_time;
        ULARGE_INTEGER now;
        ULONGLONG delta, ms;
        GetSystemTimeAsFileTime(&file_time);
        now.LowPart = file_time.dwLowDateTime;
        now.HighPart = file_time.dwHighDateTime;
        if ((ULONGLONG)ticks <= now.QuadPart) return 0;
        delta = (ULONGLONG)ticks - now.QuadPart;
        ms = (delta + 9999u) / 10000u;
        return ms >= INFINITE ? INFINITE - 1u : (DWORD)ms;
    }
}

static NTSTATUS bridge_wait_mutant_token(uint32_t token,
                                         PLARGE_INTEGER timeout, int *handled)
{
    BridgeMutant *mutant = bridge_mutant_from_token(token);
    DWORD wait_ms;
    ULONGLONG started;

    *handled = mutant != NULL;
    if (!mutant) return STATUS_SUCCESS;
    wait_ms = bridge_mutant_timeout_ms(timeout);
    if (wait_ms == INFINITE) {
        EnterCriticalSection(&mutant->lock);
        bridge_note_mutant_acquire(mutant);
        return STATUS_SUCCESS;
    }

    started = GetTickCount64();
    do {
        if (TryEnterCriticalSection(&mutant->lock)) {
            bridge_note_mutant_acquire(mutant);
            return STATUS_SUCCESS;
        }
        if (GetTickCount64() - started >= wait_ms) return STATUS_TIMEOUT;
        Sleep(1);
    } while (1);
}

static NTSTATUS bridge_release_mutant_token(uint32_t token,
                                            LONG *previous, int *handled)
{
    BridgeMutant *mutant = bridge_mutant_from_token(token);
    DWORD thread = GetCurrentThreadId();

    *handled = mutant != NULL;
    if (!mutant) return STATUS_SUCCESS;
    if (mutant->owner_thread != thread || mutant->recursion <= 0)
        return STATUS_MUTANT_NOT_OWNED;
    if (previous) *previous = 0;
    if (--mutant->recursion == 0) mutant->owner_thread = 0;
    LeaveCriticalSection(&mutant->lock);
    return STATUS_SUCCESS;
}

static NTSTATUS bridge_create_mutant(uint32_t handle_va, BOOLEAN initial_owner)
{
    BridgeMutant *mutant;
    uint32_t token, index;

    if (!handle_va) return STATUS_INVALID_PARAMETER;
    mutant = (BridgeMutant *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                       sizeof(*mutant));
    if (!mutant) return STATUS_INSUFFICIENT_RESOURCES;
    InitializeCriticalSection(&mutant->lock);
    if (initial_owner) {
        EnterCriticalSection(&mutant->lock);
        mutant->owner_thread = GetCurrentThreadId();
        mutant->recursion = 1;
    }

    token = bridge_handle_token((HANDLE)mutant);
    if (!token) {
        if (initial_owner) LeaveCriticalSection(&mutant->lock);
        DeleteCriticalSection(&mutant->lock);
        HeapFree(GetProcessHeap(), 0, mutant);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    index = token & BRIDGE_HANDLE_MASK;
    s_handle_kind[index] = BRIDGE_HANDLE_KIND_MUTANT;
    BRIDGE_MEM32(handle_va) = token;
    return STATUS_SUCCESS;
}

static int bridge_close_mutant(uint32_t token)
{
    uint32_t index;
    BridgeMutant *mutant = bridge_mutant_from_token(token);
    if (!mutant) return 0;
    index = token & BRIDGE_HANDLE_MASK;
    s_handle_table[index] = NULL;
    s_handle_kind[index] = BRIDGE_HANDLE_KIND_NATIVE;
    /* Titles must release ownership before closing the last handle. Preserve
     * safety if a bad caller violates that contract rather than freeing a
     * lock that another host thread could still be waiting on. */
    if (mutant->recursion != 0) return 1;
    DeleteCriticalSection(&mutant->lock);
    HeapFree(GetProcessHeap(), 0, mutant);
    return 1;
}



/* Narrow exports for manually recompiled title wrappers that otherwise spend
 * more time constructing an XDK call frame and redispatching the kernel thunk
 * than they do acquiring the uncontended lock. */
uint32_t xbox_kernel_fast_wait_mutant(uint32_t token)
{
    int handled = 0;
    NTSTATUS status = bridge_wait_mutant_token(token, NULL, &handled);
    if (!handled)
        status = xbox_NtWaitForSingleObjectEx(
            bridge_resolve_handle(token), KernelMode, FALSE, NULL);
    return (uint32_t)status;
}

uint32_t xbox_kernel_fast_release_mutant(uint32_t token)
{
    int handled = 0;
    NTSTATUS status = bridge_release_mutant_token(token, NULL, &handled);
    if (!handled)
        status = xbox_NtReleaseMutant(bridge_resolve_handle(token), NULL);
    return (uint32_t)status;
}
/* Resolve a 32-bit Xbox handle slot back to a native HANDLE. */
static HANDLE bridge_read_handle(uint32_t va)
{
    uint32_t token = BRIDGE_MEM32(va);
    if ((token & 0xFF000000u) == BRIDGE_HANDLE_TAG) {
        uint32_t i = token & BRIDGE_HANDLE_MASK;
        return (i > 0 && i < BRIDGE_HANDLE_MAX) ? s_handle_table[i] : NULL;
    }
    /* Untagged value: synthetic/dummy handle -- pass through unchanged. */
    return (HANDLE)(uintptr_t)token;
}

/* Resolve a token to a HANDLE and release its table slot (for NtClose). */
/* Resolve a handle token passed BY VALUE, without consuming it.
 *
 * Three accessors, easily confused, and confusing two of them broke all file
 * I/O: bridge_read_handle(va) reads a token *from memory* and suits a PHANDLE
 * out-parameter; bridge_take_handle(token) resolves and CLEARS the table slot,
 * which is NtClose semantics; this one resolves and leaves the slot alone,
 * which is what every by-value HANDLE argument needs.
 *
 * NtSetInformationFile and friends take the handle by value, but were calling
 * bridge_read_handle on it -- dereferencing the token as if it were an address.
 * Halo created its save file successfully and then failed the very next call,
 * which surfaced as "couldn't open or create saved game file". */
static HANDLE bridge_resolve_handle(uint32_t token)
{
    if ((token & 0xFF000000u) == BRIDGE_HANDLE_TAG) {
        uint32_t i = token & BRIDGE_HANDLE_MASK;
        return (i > 0 && i < BRIDGE_HANDLE_MAX) ? s_handle_table[i] : NULL;
    }
    /* Untagged: synthetic/dummy handle -- pass through unchanged. */
    return (HANDLE)(uintptr_t)token;
}

static HANDLE bridge_take_handle(uint32_t token)
{
    if ((token & 0xFF000000u) == BRIDGE_HANDLE_TAG) {
        uint32_t i = token & BRIDGE_HANDLE_MASK;
        if (i > 0 && i < BRIDGE_HANDLE_MAX) {
            HANDLE h = s_handle_table[i];
            s_handle_table[i] = NULL;
            return h;
        }
    }
    return NULL;   /* untagged -> not a table handle, do not close */
}

/* Build a native OBJECT_ATTRIBUTES wrapping the translated Xbox path. */
static void bridge_build_oa(uint32_t obj_attrs_va,
                            XBOX_OBJECT_ATTRIBUTES* oa, XBOX_ANSI_STRING* name)
{
    const char* path = bridge_get_xbox_path(obj_attrs_va);
    name->Buffer        = (PCHAR)path;
    name->Length        = path ? (USHORT)strlen(path) : 0;
    name->MaximumLength = (USHORT)(name->Length + 1);
    oa->RootDirectory = NULL;
    oa->ObjectName    = name;
    oa->Attributes    = 0;
}

/* Open a file by delegating to the ported xbox_NtCreateFile kernel HLE. */
static NTSTATUS bridge_create_file_impl(
    uint32_t handle_va, ACCESS_MASK access, uint32_t obj_attrs_va,
    uint32_t iostatus_va, ULONG file_attrs, ULONG share,
    ULONG disposition, ULONG options)
{
    XBOX_OBJECT_ATTRIBUTES oa;
    XBOX_ANSI_STRING       name;
    XBOX_IO_STATUS_BLOCK   ios;
    HANDLE   h  = NULL;
    NTSTATUS st;

    bridge_build_oa(obj_attrs_va, &oa, &name);
    if (!name.Buffer) {
        bridge_write_iostatus(iostatus_va, STATUS_OBJECT_PATH_NOT_FOUND, 0);
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }
    memset(&ios, 0, sizeof(ios));

    st = xbox_NtCreateFile(&h, access, &oa, &ios, NULL,
                           file_attrs, share, disposition, options);

    if (NT_SUCCESS(st)) {
        bridge_write_handle(handle_va, h);
        bridge_write_iostatus(iostatus_va, ios.Status, (uint32_t)ios.Information);
    } else {
        bridge_write_iostatus(iostatus_va, st, 0);
    }
    return st;
}

/* ── RtlInitAnsiString (ordinal 289) ──────────────────────
 * VOID RtlInitAnsiString(PANSI_STRING Destination, PCSZ Source)
 *
 * Fills an ANSI_STRING { USHORT Length; USHORT MaximumLength; PCHAR Buffer; }.
 * Unbridged this returned 0 and wrote nothing, so every path a title built
 * this way arrived at NtCreateFile as a null Buffer and failed with
 * STATUS_OBJECT_PATH_NOT_FOUND -- which looks like a missing file rather than
 * a missing bridge. Halo builds its map paths exactly this way.
 */
/* -- RtlEqualString (ordinal 279, 3 args) ----------------
 * BOOLEAN RtlEqualString(PSTRING String1, PSTRING String2, BOOLEAN CaseInSens)
 *
 * The fields are read out by hand rather than casting the guest struct. A
 * guest ANSI_STRING is {USHORT Length, USHORT MaximumLength, 32-bit Buffer},
 * eight bytes; the native one has a 64-bit PCHAR, so a cast would read
 * MaximumLength and Buffer from the wrong offsets and then dereference a guest
 * VA as a host address. RtlInitAnsiString stores a guest VA in that field --
 * see the bridge below -- so it has to be translated, not passed through.
 *
 * Stubbed, this returned 0: "never equal". Wreckless initialises a string and
 * compares it in a critical-section-protected lookup, so every comparison
 * missing turned that lookup into unbounded recursion and the process died of
 * a host stack overflow 200 kernel calls in.
 */
static void bridge_RtlEqualString(void)
{
    uint32_t s1_va  = STACK_ARG(0);
    uint32_t s2_va  = STACK_ARG(1);
    uint32_t nocase = STACK_ARG(2);
    XBOX_ANSI_STRING a, b;

    if (!s1_va || !s2_va) {
        g_eax = 0;
        return;
    }
    a.Length        = BRIDGE_MEM16(s1_va + 0);
    a.MaximumLength = BRIDGE_MEM16(s1_va + 2);
    a.Buffer        = (PCHAR)XBOX_TO_NATIVE(BRIDGE_MEM32(s1_va + 4));
    b.Length        = BRIDGE_MEM16(s2_va + 0);
    b.MaximumLength = BRIDGE_MEM16(s2_va + 2);
    b.Buffer        = (PCHAR)XBOX_TO_NATIVE(BRIDGE_MEM32(s2_va + 4));

    if (!a.Buffer || !b.Buffer) {
        g_eax = 0;
        return;
    }
    g_eax = xbox_RtlEqualString(&a, &b, (BOOLEAN)nocase) ? 1 : 0;
}

/* RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue) is a
 * non-local control transfer: it walks the SEH handler chain from the
 * current frame to TargetFrame running each handler's unwind cleanup,
 * then continues execution AT TargetIp with esp=TargetFrame and
 * eax=ReturnValue -- it does not return to its caller in the normal
 * sense. This project has no guest-visible SEH frame chain to walk (no
 * bridge previously existed for ordinal 312 at all -- it silently
 * returned 0 and let the guest's __try/__finally-style cleanup vanish),
 * so this is a pragmatic approximation rather than a faithful unwind:
 * restore the guest-visible state a caller can observe (esp, eax) and,
 * if TargetIp resolves to a real recompiled function, call it directly.
 * This does NOT abandon the native C call stack the way a real unwind
 * would, so nested guest callers between here and TargetFrame still run
 * their own epilogues afterward -- but for the common __finally-cleanup-
 * then-continue pattern this restores the guest-visible register state
 * those epilogues and TargetIp actually depend on, which is strictly
 * better than the previous silent no-op. */
static void bridge_RtlUnwind(void)
{
    uint32_t target_frame  = STACK_ARG(0);
    uint32_t target_ip     = STACK_ARG(1);
    uint32_t return_value  = STACK_ARG(3);

    if (target_frame) {
        g_esp = target_frame;
    }
    g_eax = return_value;

    if (target_ip) {
        recomp_func_t fn = recomp_lookup_manual(target_ip);
        if (!fn) fn = recomp_lookup(target_ip);
        if (fn) {
            fn();
        }
    }
}

static void bridge_RtlInitAnsiString(void)
{
    uint32_t dest_va = STACK_ARG(0);
    uint32_t src_va  = STACK_ARG(1);

    if (!dest_va) {
        g_eax = 0;
        return;
    }
    if (src_va) {
        const char *src = (const char *)XBOX_TO_NATIVE(src_va);
        size_t len = strlen(src);
        if (len > 0xFFFE) {
            len = 0xFFFE;
        }
        BRIDGE_MEM16(dest_va + 0) = (uint16_t)len;
        BRIDGE_MEM16(dest_va + 2) = (uint16_t)(len + 1);
        BRIDGE_MEM32(dest_va + 4) = src_va;
    } else {
        BRIDGE_MEM16(dest_va + 0) = 0;
        BRIDGE_MEM16(dest_va + 2) = 0;
        BRIDGE_MEM32(dest_va + 4) = 0;
    }
    g_eax = 0;
}

/* ── NtCreateFile (ordinal 190, 9 args = 36 bytes) ─────── */
static void bridge_NtCreateFile(void)
{
    uint32_t handle_va   = STACK_ARG(0);  /* PHANDLE */
    uint32_t access      = STACK_ARG(1);  /* ACCESS_MASK */
    uint32_t obj_attrs   = STACK_ARG(2);  /* POBJECT_ATTRIBUTES */
    uint32_t iostatus    = STACK_ARG(3);  /* PIO_STATUS_BLOCK */
    /* arg4: AllocationSize - ignored */
    uint32_t file_attrs  = STACK_ARG(5);  /* FileAttributes */
    uint32_t share       = STACK_ARG(6);  /* ShareAccess */
    uint32_t disposition = STACK_ARG(7);  /* CreateDisposition */
    uint32_t options     = STACK_ARG(8);  /* CreateOptions */

    /* The out-parameter addresses matter as much as the result: this bridge
     * hands them to a real Win32 call, so a bogus one has Windows itself write
     * into Xbox memory. That is how a wild write ends up with a stack inside
     * ntdll and no recompiled frame to blame. */
    fprintf(stderr, "  [FILE] NtCreateFile handle_va=0x%08X oa=0x%08X ios=0x%08X\n",
            handle_va, obj_attrs, iostatus);
    fflush(stderr);

    g_eax = (uint32_t)bridge_create_file_impl(
        handle_va, access, obj_attrs, iostatus,
        file_attrs, share, disposition, options);
}

/* ── NtOpenFile (ordinal 202, 6 args = 24 bytes) ──────── */
static void bridge_NtOpenFile(void)
{
    uint32_t handle_va = STACK_ARG(0);  /* PHANDLE */
    uint32_t access    = STACK_ARG(1);  /* ACCESS_MASK */
    uint32_t obj_attrs = STACK_ARG(2);  /* POBJECT_ATTRIBUTES */
    uint32_t iostatus  = STACK_ARG(3);  /* PIO_STATUS_BLOCK */
    uint32_t share     = STACK_ARG(4);  /* ShareAccess */
    uint32_t options   = STACK_ARG(5);  /* OpenOptions */

    /* NtOpenFile = NtCreateFile with FILE_OPEN disposition */
    g_eax = (uint32_t)bridge_create_file_impl(
        handle_va, access, obj_attrs, iostatus,
        0, share, 1 /* FILE_OPEN */, options);
}

/*
 * Completion for a file request that carried an Event or an APC routine.
 *
 * Both bridges below do the I/O synchronously, and used to drop args 1-3
 * (Event, ApcRoutine, ApcContext) on the floor. A title that issues an async
 * request and waits alertably for the completion then waits forever: Halo's
 * cache-partition setup does exactly that, gives up after its 5-second SleepEx,
 * and asserts "setup for new cache file failed (#0)".
 *
 * ponytail: the APC runs inline here rather than at the next alertable wait.
 * The data really is ready by then, so the observable result matches; a title
 * that depends on the APC *not* having run yet would notice. A per-thread
 * deferred queue drained at alertable waits was tried for Halo's map streamer
 * and made no difference (it still issues one 14 KB batch and stops), so it was
 * dropped rather than risk changing this shared path for the other titles.
 */
recomp_func_t recomp_lookup_kernel(uint32_t xbox_va);

static void deliver_one_apc(uint32_t apc_routine, uint32_t apc_context,
                            uint32_t iostatus)
{
    /* The APC can be game code or a kernel export. Halo's XAPI passes the
     * latter -- 0xFE0000FC, one of our own synthetic thunk VAs -- so the recomp
     * dispatch correctly fails to find it and the kernel fallback is the one
     * that matters. Checking only recomp_lookup left it undelivered. */
    recomp_func_t fn = recomp_lookup(apc_routine);
    if (!fn) fn = recomp_lookup_manual(apc_routine);
    if (!fn) fn = recomp_lookup_kernel(apc_routine);
    if (fn) {
        static LONG dah2_file_apc_trace_count;
        LONG trace_index = InterlockedIncrement(&dah2_file_apc_trace_count);
        uint32_t saved_eax = g_eax, saved_ecx = g_ecx;
        uint32_t saved_edx = g_edx, saved_esp = g_esp;
        uint32_t saved_ebx = g_ebx, saved_esi = g_esi;
        uint32_t saved_edi = g_edi, saved_ebp = g_ebp;
        uint32_t saved_seh_ebp = g_seh_ebp;

        /* VOID ApcRoutine(PVOID ApcContext, PIO_STATUS_BLOCK, ULONG) */
        g_esp -= 4; BRIDGE_MEM32(g_esp) = 0;
        g_esp -= 4; BRIDGE_MEM32(g_esp) = iostatus;
        g_esp -= 4; BRIDGE_MEM32(g_esp) = apc_context;
        g_esp -= 4; BRIDGE_MEM32(g_esp) = 0;   /* dummy return address */
        fn();

        if (trace_index <= 64 && getenv("DAH2_TEST_WINDOW_HIDDEN")) {
            printf("[FILE-APC] n=%ld routine=%08X context=%08X ios=%08X esp_before=%08X esp_after=%08X eax_before=%08X eax_after=%08X\n",
                   trace_index, apc_routine, apc_context, iostatus,
                   saved_esp, g_esp, saved_eax, g_eax);
            fflush(stdout);
        }

        /* APC delivery is being performed inline as a stand-in for the
         * kernel restoring the interrupted thread context at an alertable
         * wait. The callback keeps its memory side effects, but must not leak
         * its register file or stdcall stack cleanup into NtReadFile's caller.
         * kernel_thunk_dispatch already consumes the dummy return plus
         * NtUserIoApcDispatcher's 12 argument bytes. */
        g_eax = saved_eax; g_ecx = saved_ecx; g_edx = saved_edx;
        g_esp = saved_esp; g_ebx = saved_ebx; g_esi = saved_esi;
        g_edi = saved_edi; g_ebp = saved_ebp;
        g_seh_ebp = saved_seh_ebp;
    } else {
        uint32_t ord = 0;
        if (apc_routine >= KERNEL_VA_BASE && apc_routine < KERNEL_VA_END) {
            ord = g_slot_ordinals[(apc_routine - KERNEL_VA_BASE) / 4];
        }
        fprintf(stderr, "  [KERNEL] file I/O APC 0x%08X unresolved"
                " (kernel ordinal %u)\n", apc_routine, ord);
        fflush(stderr);
    }
}

/* Per-thread pending-APC ring. An APC is delivered on the thread that issued
 * the request, which is also the thread that waits, so thread-local is right. */
static void bridge_complete_file_io(uint32_t event_token, uint32_t apc_routine,
                                    uint32_t apc_context, uint32_t iostatus)
{
    if (event_token) {
        HANDLE ev = bridge_resolve_handle(event_token);
        if (ev) SetEvent(ev);
    }
    if (apc_routine) {
        deliver_one_apc(apc_routine, apc_context, iostatus);
    }
}

/* ── NtReadFile (ordinal 219, 8 args = 32 bytes) ──────── */
static void bridge_NtReadFile(void)
{
    HANDLE   handle    = bridge_resolve_handle(STACK_ARG(0));
    uint32_t iostatus  = STACK_ARG(4);
    uint32_t buffer_va = STACK_ARG(5);
    uint32_t length    = STACK_ARG(6);
    uint32_t offset_va = STACK_ARG(7);
    XBOX_IO_STATUS_BLOCK ios;
    LARGE_INTEGER  off;
    PLARGE_INTEGER poff = NULL;

    memset(&ios, 0, sizeof(ios));
    if (offset_va) {
        off.LowPart  = BRIDGE_MEM32(offset_va);
        off.HighPart = (LONG)BRIDGE_MEM32(offset_va + 4);
        poff = &off;
    }
    g_eax = (uint32_t)xbox_NtReadFile(handle, NULL, NULL, NULL, &ios,
                XBOX_TO_NATIVE(buffer_va), length, poff);
    bridge_write_iostatus(iostatus, ios.Status, (uint32_t)ios.Information);
    bridge_complete_file_io(STACK_ARG(1), STACK_ARG(2), STACK_ARG(3),
                            iostatus);
}

/* ── NtWriteFile (ordinal 236, 8 args = 32 bytes) ─────── */
static void bridge_NtWriteFile(void)
{
    HANDLE   handle    = bridge_resolve_handle(STACK_ARG(0));
    uint32_t iostatus  = STACK_ARG(4);
    uint32_t buffer_va = STACK_ARG(5);
    uint32_t length    = STACK_ARG(6);
    uint32_t offset_va = STACK_ARG(7);
    XBOX_IO_STATUS_BLOCK ios;
    LARGE_INTEGER  off;
    PLARGE_INTEGER poff = NULL;

    memset(&ios, 0, sizeof(ios));
    if (offset_va) {
        off.LowPart  = BRIDGE_MEM32(offset_va);
        off.HighPart = (LONG)BRIDGE_MEM32(offset_va + 4);
        poff = &off;
    }
    g_eax = (uint32_t)xbox_NtWriteFile(handle, NULL, NULL, NULL, &ios,
                XBOX_TO_NATIVE(buffer_va), length, poff);
    bridge_write_iostatus(iostatus, ios.Status, (uint32_t)ios.Information);
    bridge_complete_file_io(STACK_ARG(1), STACK_ARG(2), STACK_ARG(3),
                            iostatus);
}

/* ── NtQueryInformationFile (ordinal 211, 5 args = 20 bytes) */
static void bridge_NtQueryInformationFile(void)
{
    HANDLE   handle    = bridge_resolve_handle(STACK_ARG(0));
    uint32_t ios_va    = STACK_ARG(1);
    uint32_t info_va   = STACK_ARG(2);
    uint32_t length    = STACK_ARG(3);
    uint32_t infoclass = STACK_ARG(4);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    g_eax = (uint32_t)xbox_NtQueryInformationFile(handle, &ios,
                XBOX_TO_NATIVE(info_va), length,
                (XBOX_FILE_INFORMATION_CLASS)infoclass);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtSetInformationFile (ordinal 226, 5 args = 20 bytes) ─ */
static void bridge_NtSetInformationFile(void)
{
    HANDLE   handle    = bridge_resolve_handle(STACK_ARG(0));
    uint32_t ios_va    = STACK_ARG(1);
    uint32_t info_va   = STACK_ARG(2);
    uint32_t length    = STACK_ARG(3);
    uint32_t infoclass = STACK_ARG(4);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    g_eax = (uint32_t)xbox_NtSetInformationFile(handle, &ios,
                XBOX_TO_NATIVE(info_va), length,
                (XBOX_FILE_INFORMATION_CLASS)infoclass);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtQueryVolumeInformationFile (ordinal 218, 5 args = 20 bytes) */
static void bridge_NtQueryVolumeInformationFile(void)
{
    HANDLE   handle    = bridge_resolve_handle(STACK_ARG(0));
    uint32_t ios_va    = STACK_ARG(1);
    uint32_t info_va   = STACK_ARG(2);
    uint32_t length    = STACK_ARG(3);
    uint32_t infoclass = STACK_ARG(4);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    g_eax = (uint32_t)xbox_NtQueryVolumeInformationFile(handle, &ios,
                XBOX_TO_NATIVE(info_va), length,
                (XBOX_FS_INFORMATION_CLASS)infoclass);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtQueryFullAttributesFile (ordinal 210, 2 args = 8 bytes) */
static void bridge_NtQueryFullAttributesFile(void)
{
    uint32_t obj_attrs = STACK_ARG(0);
    uint32_t info_va   = STACK_ARG(1);
    XBOX_OBJECT_ATTRIBUTES oa;
    XBOX_ANSI_STRING       name;

    bridge_build_oa(obj_attrs, &oa, &name);
    if (!name.Buffer) { g_eax = STATUS_OBJECT_PATH_NOT_FOUND; return; }
    g_eax = (uint32_t)xbox_NtQueryFullAttributesFile(&oa,
                (PXBOX_FILE_NETWORK_OPEN_INFORMATION)XBOX_TO_NATIVE(info_va));
}

/* ── NtFlushBuffersFile (ordinal 198, 2 args = 8 bytes) ─── */
static void bridge_NtFlushBuffersFile(void)
{
    HANDLE   handle = bridge_resolve_handle(STACK_ARG(0));
    uint32_t ios_va = STACK_ARG(1);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    g_eax = (uint32_t)xbox_NtFlushBuffersFile(handle, &ios);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtDeleteFile (ordinal 195, 1 arg = 4 bytes) ─────── */
static void bridge_NtDeleteFile(void)
{
    XBOX_OBJECT_ATTRIBUTES oa;
    XBOX_ANSI_STRING       name;

    bridge_build_oa(STACK_ARG(0), &oa, &name);
    if (!name.Buffer) { g_eax = STATUS_OBJECT_PATH_NOT_FOUND; return; }
    g_eax = (uint32_t)xbox_NtDeleteFile(&oa);
}

/* ── NtQueryDirectoryFile (ordinal 207, 9 args = 36 bytes) ─ */
static void bridge_NtQueryDirectoryFile(void)
{
    HANDLE   handle      = bridge_resolve_handle(STACK_ARG(0));
    uint32_t ios_va      = STACK_ARG(4);
    uint32_t info_va     = STACK_ARG(5);
    uint32_t length      = STACK_ARG(6);
    uint32_t filename_va = STACK_ARG(7);  /* PXBOX_ANSI_STRING */
    uint32_t restart     = STACK_ARG(8);  /* BOOLEAN */
    XBOX_IO_STATUS_BLOCK ios;
    XBOX_ANSI_STRING     fn;
    PXBOX_ANSI_STRING    pfn = NULL;

    memset(&ios, 0, sizeof(ios));
    if (filename_va) {
        /* Xbox ANSI_STRING: 0=Length(u16), 2=MaximumLength(u16), 4=Buffer(u32) */
        uint32_t fn_buf  = BRIDGE_MEM32(filename_va + 4);
        fn.Length        = BRIDGE_MEM16(filename_va);
        fn.MaximumLength = BRIDGE_MEM16(filename_va + 2);
        fn.Buffer        = fn_buf ? (PCHAR)XBOX_TO_NATIVE(fn_buf) : NULL;
        if (fn.Buffer) pfn = &fn;
    }
    g_eax = (uint32_t)xbox_NtQueryDirectoryFile(handle, NULL, NULL, NULL, &ios,
                XBOX_TO_NATIVE(info_va), length, pfn, (BOOLEAN)restart);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtOpenSymbolicLinkObject (ordinal 203, 2 args = 8 bytes) */
static void bridge_NtOpenSymbolicLinkObject(void)
{
    uint32_t handle_va = STACK_ARG(0);
    /* arg1: POBJECT_ATTRIBUTES - ignored, we return a synthetic handle.
     * Written raw (untagged) so NtClose recognises it and skips it. */
    if (handle_va) BRIDGE_MEM32(handle_va) = 0xDEAD0001u;
    g_eax = STATUS_SUCCESS;
}

/* ── NtQuerySymbolicLinkObject (ordinal 215, 3 args = 12 bytes) */
static void bridge_NtQuerySymbolicLinkObject(void)
{
    /* uint32_t handle = STACK_ARG(0); */
    uint32_t target_va = STACK_ARG(1);
    uint32_t retlen_va = STACK_ARG(2);
    const char* target = "\\Device\\CdRom0";
    USHORT len = (USHORT)strlen(target);

    if (target_va) {
        uint16_t max_len = BRIDGE_MEM16(target_va + 2);
        uint32_t buf_va  = BRIDGE_MEM32(target_va + 4);
        if (buf_va && len < max_len) {
            memcpy(XBOX_TO_NATIVE(buf_va), target, len + 1);
            BRIDGE_MEM16(target_va) = len;
        }
    }
    if (retlen_va) BRIDGE_MEM32(retlen_va) = (uint32_t)len;
    g_eax = STATUS_SUCCESS;
}

/* ── IoCreateFile (ordinal 67, 10 args = 40 bytes) ────── */
static void bridge_IoCreateFile(void)
{
    /* Same as NtCreateFile with an extra Options arg at the end */
    uint32_t handle_va   = STACK_ARG(0);
    uint32_t access      = STACK_ARG(1);
    uint32_t obj_attrs   = STACK_ARG(2);
    uint32_t iostatus    = STACK_ARG(3);
    uint32_t file_attrs  = STACK_ARG(5);
    uint32_t share       = STACK_ARG(6);
    uint32_t disposition = STACK_ARG(7);
    uint32_t options     = STACK_ARG(8);

    g_eax = (uint32_t)bridge_create_file_impl(
        handle_va, access, obj_attrs, iostatus,
        file_attrs, share, disposition, options);
}

/* ── NtDeviceIoControlFile (ordinal 196, 10 args = 40 bytes) */
static void bridge_NtDeviceIoControlFile(void)
{
    uint32_t ioctl = STACK_ARG(5);
    uint32_t ios_va = STACK_ARG(4);
    fprintf(stderr, "  [FILE] NtDeviceIoControlFile(0x%X) - stub\n", ioctl);
    bridge_write_iostatus(ios_va, 0xC00000BBu, 0);
    g_eax = 0xC00000BBu; /* STATUS_NOT_IMPLEMENTED */
}

/* ── NtFsControlFile (ordinal 200, 10 args = 40 bytes) ──── */
static void bridge_NtFsControlFile(void)
{
    uint32_t fsctl = STACK_ARG(5);
    uint32_t ios_va = STACK_ARG(4);
    fprintf(stderr, "  [FILE] NtFsControlFile(0x%X) - stub\n", fsctl);
    bridge_write_iostatus(ios_va, 0xC00000BBu, 0);
    g_eax = 0xC00000BBu;
}

/* ── NtCreateDirectoryObject (ordinal 188) ──────────────── */
static void bridge_NtCreateDirectoryObject(void)
{
    /* Return STATUS_SUCCESS with a fake handle */
    uint32_t handle_ptr = STACK_ARG(0);
    if (handle_ptr) BRIDGE_MEM32(handle_ptr) = 0xBEEF0010;
    g_eax = 0;  /* STATUS_SUCCESS */
}

/* ── IoCreateSymbolicLink (ordinal 63) ───────────────────── */
static void bridge_IoCreateSymbolicLink(void)
{
    g_eax = 0;  /* STATUS_SUCCESS */
}

/* ── ObReferenceObjectByHandle (ordinal 246) ─────────────── */
static void bridge_ObReferenceObjectByHandle(void)
{
    /* Xbox: NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, PVOID ObjectType, PVOID* Object)
     * 3 args (not 6 like Windows NT) */
    uint32_t handle = STACK_ARG(0);
    uint32_t obj_type = STACK_ARG(1);
    uint32_t object_ptr = STACK_ARG(2);
    if (object_ptr) BRIDGE_MEM32(object_ptr) = 0;
    g_eax = 0;  /* STATUS_SUCCESS */
}

/* ── RtlRaiseException (ordinal 302) ─────────────────────
 * VOID RtlRaiseException(PEXCEPTION_RECORD ExceptionRecord)
 *
 * Called by CRT / SEH code to raise structured exceptions.
 * On Xbox this triggers the kernel exception dispatcher.
 * For recompilation, we log and continue (no real SEH dispatch yet).
 */
static void bridge_RtlRaiseException(void)
{
    uint32_t record_ptr = STACK_ARG(0);
    uint32_t code = record_ptr ? BRIDGE_MEM32(record_ptr) : 0;

    static int raise_count = 0;
#ifdef DAH2_FN_TRACE
    {   /* trace builds: record who raised what (record, code, caller return address, first exception parameter) */
        extern void dah2_note(uint32_t tag, uint32_t a, uint32_t b, uint32_t c);
        dah2_note(0x52AE, record_ptr, code, BRIDGE_MEM32(g_esp));
    }
#endif
    raise_count++;
    if (raise_count <= 10) {
        fprintf(stderr, "  [KERNEL] RtlRaiseException: record=0x%08X code=0x%08X (#%d)\n",
                record_ptr, code, raise_count);
        fflush(stderr);
    }

    /* Handle float exceptions by clearing the FPU status.
     *
     * On the real Xbox, RtlRaiseException dispatches through the SEH chain.
     * For float exceptions (0xC0000090-0xC0000096), the CRT exception handler
     * clears the x87/SSE status word and continues execution. Without clearing,
     * the caller re-checks the FPU status, sees the exception still pending,
     * and re-raises in an infinite loop.
     *
     * _clearfp() clears both x87 and SSE exception flags on Windows x64.
     */
    if (code >= 0xC0000090u && code <= 0xC0000096u) {
        _clearfp();
    }

    g_eax = 0;
}

/* ── MmMapIoSpace (ordinal 177) ──────────────────────────
 * PVOID MmMapIoSpace(ULONG_PTR PhysicalAddress, ULONG NumberOfBytes, ULONG Protect)
 *
 * Maps physical I/O memory (GPU registers, etc.) into virtual address space.
 * Allocate from Xbox heap so the returned pointer is a valid Xbox VA.
 */
static void bridge_MmMapIoSpace(void)
{
    uint32_t phys_addr = STACK_ARG(0);
    uint32_t num_bytes = STACK_ARG(1);
    uint32_t protect = STACK_ARG(2);
    uint32_t xbox_va = xbox_HeapAlloc(num_bytes, 4096);

    fprintf(stderr, "  [KERNEL] MmMapIoSpace: phys=0x%08X size=%u → Xbox VA 0x%08X\n",
            phys_addr, num_bytes, xbox_va);
    fflush(stderr);

    g_eax = xbox_va;
}

/* ── MmPersistContiguousMemory (ordinal 178) ─────────────
 * VOID MmPersistContiguousMemory(PVOID BaseAddress, ULONG NumberOfBytes, BOOLEAN Persist)
 *
 * Marks contiguous memory as persistent across reboots (for save data).
 * No-op for recompilation.
 */
static void bridge_MmPersistContiguousMemory(void)
{
    /* No-op stub */
    g_eax = 0;
}

/* ── Generic fallback for simple value-only functions ────── */
static void bridge_generic_stub(void)
{
    /* Success-returning stub for functions whose callers only check for 0.
     * Deliberately silent: the caller (kernel_thunk_dispatch) warns for
     * ordinals with no bridge at all, which is the case worth hearing about. */
    g_eax = 0;
}


/* ══════════════════════════════════════════════════════════════════════════
 * Wrappers for the ordinals Halo 2276's thunk table binds but the bridge did
 * not route. Every one of these already had a working xbox_* implementation in
 * src/kernel/*.c; only the wrapper that moves arguments off the simulated stack
 * was missing, so each call was silently a no-op returning 0.
 *
 * Guest pointers go through XBOX_TO_NATIVE, which maps NULL to NULL. Scalars
 * pass straight through. Handles are tokens, not host HANDLEs, so they go
 * through bridge_resolve_handle / bridge_write_handle.
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── AvGetSavedDataAddress (ordinal 1, void) */
static void bridge_AvGetSavedDataAddress(void)
{
    g_eax = (uint32_t)xbox_AvGetSavedDataAddress();
}

/* ── HalReadWritePCISpace (ordinal 46, 6 args)
 * The linked Xbox D3D8 runtime reads PCI config register 0x4c before writing
 * it back.  Returning from an unbridged thunk leaves the caller's stack-local
 * read buffer uninitialized; the kernel implementation deliberately clears
 * reads, which is deterministic and sufficient for our virtual GPU. */
static void bridge_HalReadWritePCISpace(void)
{
    xbox_HalReadWritePCISpace(STACK_ARG(0), STACK_ARG(1), STACK_ARG(2),
                              XBOX_TO_NATIVE(STACK_ARG(3)), STACK_ARG(4),
                              (BOOLEAN)STACK_ARG(5));
    g_eax = 0;
}

/* ── AvSendTVEncoderOption (ordinal 2, 4 args) ─────────────
 * ULONG AvSendTVEncoderOption(PVOID RegisterBase, ULONG Option, ULONG Param,
 *                             ULONG *Result)
 *
 * OBSERVATION-ONLY, deliberately. xbox_AvSendTVEncoderOption (kernel_hal.c)
 * answers queries with option numbers and values that were invented, not
 * checked against a retail kernel (e.g. "encoder type = 4"). Routing it would
 * change what the D3D8 runtime sees from this call, and with the unbridged
 * stub the title's presentation parameters already match retail under xemu.
 * So this keeps exactly the previous behaviour (return 0, leave *Result
 * untouched) and records each distinct (Option, Param) tuple the title really
 * sends, so the answers can be taken from retail rather than guessed. */
static void bridge_AvSendTVEncoderOption(void)
{
    static uint32_t seen[16][2];
    static int seen_count;
    uint32_t reg_base = STACK_ARG(0);
    uint32_t option   = STACK_ARG(1);
    uint32_t param    = STACK_ARG(2);
    uint32_t result   = STACK_ARG(3);
    int i, known = 0;

    for (i = 0; i < seen_count; ++i) {
        if (seen[i][0] == option && seen[i][1] == param) { known = 1; break; }
    }
    if (!known && seen_count < 16) {
        seen[seen_count][0] = option;
        seen[seen_count][1] = param;
        ++seen_count;
        fprintf(stderr, "  [KERNEL] AvSendTVEncoderOption (observed, not modelled): "
                "base=0x%08X option=0x%X param=0x%X result_ptr=0x%08X *result=0x%08X\n",
                reg_base, option, param, result,
                result ? BRIDGE_MEM32(result) : 0);
        fflush(stderr);
    }
    g_eax = 0;
}

/* ── AvSetSavedDataAddress (ordinal 4, 1 arg) ──────────────
 * VOID AvSetSavedDataAddress(PVOID Address)
 * Stores a plain guest VA scalar; the host global holds exactly that value. */
static void bridge_AvSetSavedDataAddress(void)
{
    xbox_AvSetSavedDataAddress(STACK_ARG(0));
    g_eax = 0;
}

/* ── DbgPrint (ordinal 8, cdecl varargs, caller cleans) ────
 * ULONG DbgPrint(PCH Format, ...)
 * Retail returns STATUS_SUCCESS and the text only reaches an attached kernel
 * debugger. Echo the (bounded) format string for the first few calls so a
 * title's own diagnostics are visible without flooding the log. The argument
 * size is 0 because the caller pops the arguments (cdecl). */
static void bridge_DbgPrint(void)
{
    static int dbg_count;
    uint32_t fmt = STACK_ARG(0);

    if (dbg_count < 16 && fmt) {
        char text[160];
        int n = 0;
        while (n < (int)sizeof(text) - 1) {
            char c = (char)BRIDGE_MEM8(fmt + n);
            if (!c) break;
            text[n++] = (c == '\n' || c == '\r') ? ' ' : c;
        }
        text[n] = 0;
        fprintf(stderr, "  [KERNEL] DbgPrint #%d: \"%s\"\n", ++dbg_count, text);
        fflush(stderr);
    }
    g_eax = 0;
}

/* ── ExFreePool (ordinal 17, 1 arg)
 * Pairs with bridge_ExAllocatePool/ExAllocatePoolWithTag, which allocate from
 * the GUEST heap (xbox_HeapAlloc). The host xbox_ExFreePool does HeapFree on
 * GetProcessHeap(), which has never seen these blocks -- that mismatch is why
 * this wrapper was left unrouted. Free through the guest heap instead;
 * xbox_HeapFree ignores an address that is not the start of a live block. */
static void bridge_ExFreePool(void)
{
    xbox_HeapFree(STACK_ARG(0));
    g_eax = 0;
}

/* ── IoCreateDevice (ordinal 65, 6 args) */
static void bridge_IoCreateDevice(void)
{
    g_eax = (uint32_t)xbox_IoCreateDevice(
        XBOX_TO_NATIVE(STACK_ARG(0)), STACK_ARG(1),
        (PXBOX_ANSI_STRING)XBOX_TO_NATIVE(STACK_ARG(2)),
        STACK_ARG(3), (BOOLEAN)STACK_ARG(4),
        (PVOID*)XBOX_TO_NATIVE(STACK_ARG(5)));
}

/* ── Calling a guest __stdcall routine from a bridge ───────
 * Used for kernel services that run title code (DPC routines, the routine
 * handed to KeSynchronizeExecution). Mirrors bridge_NtUserIoApcDispatcher:
 * push the arguments right-to-left plus a dummy return address and call the
 * translated function; its `ret N` consumes all of it.
 *
 * Unlike a real kernel call this must not let the routine's own stack or
 * callee-saved-register slips escape into the caller, so esp, ebx, esi, edi
 * and ebp are restored afterwards. Returns 0 if the routine cannot be
 * resolved. */
static int bridge_call_guest_stdcall(uint32_t routine, int nargs,
                                     uint32_t a0, uint32_t a1,
                                     uint32_t a2, uint32_t a3,
                                     uint32_t *eax_out)
{
    recomp_func_t fn = recomp_lookup(routine);
    uint32_t args[4];
    uint32_t saved_esp = g_esp, saved_ebx = g_ebx, saved_esi = g_esi;
    uint32_t saved_edi = g_edi, saved_ebp = g_ebp;
    int i;

    if (!fn) fn = recomp_lookup_manual(routine);
    if (!fn || nargs < 0 || nargs > 4) return 0;

    args[0] = a0; args[1] = a1; args[2] = a2; args[3] = a3;
    for (i = nargs - 1; i >= 0; --i) { g_esp -= 4; BRIDGE_MEM32(g_esp) = args[i]; }
    g_esp -= 4; BRIDGE_MEM32(g_esp) = 0;   /* dummy return address */
    fn();

    if (eax_out) *eax_out = g_eax;
    g_esp = saved_esp; g_ebx = saved_ebx; g_esi = saved_esi;
    g_edi = saved_edi; g_ebp = saved_ebp;
    return 1;
}

/* ── KeCancelTimer (ordinal 97, 1 arg) ─────────────────────
 * BOOLEAN KeCancelTimer(PKTIMER Timer)
 * TRUE only if the timer was pending. bridge_KeSetTimer never starts a timer,
 * so nothing is ever pending and FALSE is the correct answer. The host
 * xbox_KeCancelTimer works on a host KTIMER holding a host handle and must
 * not be handed a guest structure. */
static void bridge_KeCancelTimer(void)
{
    g_eax = 0;
}

/* ── KeDisconnectInterrupt (ordinal 100, 1 arg) ────────────
 * BOOLEAN KeDisconnectInterrupt(PKINTERRUPT Interrupt)
 * Returns the PREVIOUS connected state. Answered from the guest addresses
 * bridge_KeConnectInterrupt recorded; the host version reads a host-layout
 * KINTERRUPT that the guest's 44-byte structure is not. */
static void bridge_KeDisconnectInterrupt(void)
{
    uint32_t interrupt = STACK_ARG(0);
    int i;

    g_eax = 0;
    for (i = 0; interrupt && i < 16; ++i) {
        if (g_connected_interrupts[i] == interrupt) {
            g_connected_interrupts[i] = 0;
            g_eax = 1;
            break;
        }
    }
}

/* ── DPCs (ordinals 119 KeInsertQueueDpc, 137 KeRemoveQueueDpc) ─
 * The guest KDPC (32 bytes, see bridge_KeInitializeDpc): routine at +12,
 * context at +16, SystemArgument1/2 at +20/+24; +28 is used here as the
 * "queued" marker. There is no DPC dispatcher and no interrupt ever raises
 * one, so a queued DPC is run the moment the queue is drained -- which is when
 * IRQL would drop below DISPATCH_LEVEL on hardware. Draining is not re-entered:
 * a DPC that queues another runs it after returning, as a DPC queue does. */
#define BRIDGE_DPC_QUEUE_MAX 32
static uint32_t g_dpc_queue[BRIDGE_DPC_QUEUE_MAX];
static int      g_dpc_queue_count;
static volatile LONG g_dpc_draining;
static SRWLOCK  g_dpc_lock = SRWLOCK_INIT;

static void bridge_drain_dpcs(void)
{
    if (InterlockedCompareExchange(&g_dpc_draining, 1, 0) != 0)
        return;

    for (;;) {
        uint32_t dpc, routine, context, sa1, sa2, ignored;

        AcquireSRWLockExclusive(&g_dpc_lock);
        if (g_dpc_queue_count == 0) {
            ReleaseSRWLockExclusive(&g_dpc_lock);
            break;
        }
        dpc = g_dpc_queue[0];
        memmove(g_dpc_queue, g_dpc_queue + 1,
                (size_t)(g_dpc_queue_count - 1) * sizeof(g_dpc_queue[0]));
        --g_dpc_queue_count;
        ReleaseSRWLockExclusive(&g_dpc_lock);

        routine = BRIDGE_MEM32(dpc + 12);
        context = BRIDGE_MEM32(dpc + 16);
        sa1     = BRIDGE_MEM32(dpc + 20);
        sa2     = BRIDGE_MEM32(dpc + 24);
        BRIDGE_MEM32(dpc + 28) = 0;   /* dequeued: the routine may re-queue it */

        {
            static int run_count;
            if (run_count < 8) {
                ++run_count;
                fprintf(stderr, "  [KERNEL] DPC #%d: dpc=0x%08X routine=0x%08X "
                        "context=0x%08X\n", run_count, dpc, routine, context);
                fflush(stderr);
            }
        }
        if (!routine || !bridge_call_guest_stdcall(routine, 4, dpc, context,
                                                   sa1, sa2, &ignored)) {
            fprintf(stderr, "  [KERNEL] DPC 0x%08X: routine 0x%08X not in "
                    "dispatch, dropped\n", dpc, routine);
            fflush(stderr);
        }
    }
    InterlockedExchange(&g_dpc_draining, 0);
}

/* BOOLEAN KeInsertQueueDpc(PKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2) */
static void bridge_KeInsertQueueDpc(void)
{
    uint32_t dpc = STACK_ARG(0);
    uint32_t sa1 = STACK_ARG(1);
    uint32_t sa2 = STACK_ARG(2);
    uint32_t queued = 0;

    if (dpc && BRIDGE_MEM32(dpc + 12) && BRIDGE_MEM32(dpc + 28) == 0) {
        AcquireSRWLockExclusive(&g_dpc_lock);
        if (g_dpc_queue_count < BRIDGE_DPC_QUEUE_MAX) {
            BRIDGE_MEM32(dpc + 20) = sa1;
            BRIDGE_MEM32(dpc + 24) = sa2;
            BRIDGE_MEM32(dpc + 28) = 1;
            g_dpc_queue[g_dpc_queue_count++] = dpc;
            queued = 1;
        }
        ReleaseSRWLockExclusive(&g_dpc_lock);
    }
    if (queued)
        bridge_drain_dpcs();
    g_eax = queued;
}

/* BOOLEAN KeRemoveQueueDpc(PKDPC Dpc): TRUE if it was still queued. */
static void bridge_KeRemoveQueueDpc(void)
{
    uint32_t dpc = STACK_ARG(0);
    int i, found = 0;

    AcquireSRWLockExclusive(&g_dpc_lock);
    for (i = 0; dpc && i < g_dpc_queue_count; ++i) {
        if (g_dpc_queue[i] == dpc) {
            memmove(g_dpc_queue + i, g_dpc_queue + i + 1,
                    (size_t)(g_dpc_queue_count - i - 1) * sizeof(g_dpc_queue[0]));
            --g_dpc_queue_count;
            BRIDGE_MEM32(dpc + 28) = 0;
            found = 1;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_dpc_lock);
    g_eax = (uint32_t)found;
}

/* ── KeSynchronizeExecution (ordinal 153, 3 args) ──────────
 * BOOLEAN KeSynchronizeExecution(PKINTERRUPT Interrupt,
 *                                PKSYNCHRONIZE_ROUTINE Routine, PVOID Context)
 * Runs Routine(Context) at the interrupt's IRQL and returns its BOOLEAN. No
 * interrupt can preempt here, so running it inline is the full semantics. */
static void bridge_KeSynchronizeExecution(void)
{
    uint32_t routine = STACK_ARG(1);
    uint32_t context = STACK_ARG(2);
    uint32_t result = 0;

    if (!routine || !bridge_call_guest_stdcall(routine, 1, context, 0, 0, 0, &result)) {
        fprintf(stderr, "  [KERNEL] KeSynchronizeExecution: routine 0x%08X "
                "not in dispatch\n", routine);
        fflush(stderr);
        result = 0;
    }
    g_eax = result & 0xFFu;
}

/* ── KeSaveFloatingPointState / KeRestoreFloatingPointState (142 / 139) ──
 * NTSTATUS Ke{Save,Restore}FloatingPointState(PKFLOATING_SAVE Save)
 * Translated code keeps x87/SSE state in its own emulated registers, not the
 * host FPU, so there is nothing to save or restore. Both succeed. */
static void bridge_KeSaveFloatingPointState(void)    { g_eax = 0; }
static void bridge_KeRestoreFloatingPointState(void) { g_eax = 0; }

/* ── KeSetBasePriorityThread (ordinal 143, 2 args) ─────────
 * LONG KeSetBasePriorityThread(PKTHREAD Thread, LONG Increment)
 * Takes a kernel thread OBJECT pointer, which this layer never hands out
 * (threads are handle tokens), so there is nothing to retarget. Returns the
 * previous base priority: the default, 0. */
static void bridge_KeSetBasePriorityThread(void)
{
    g_eax = 0;
}

/* ── KeStallExecutionProcessor (ordinal 151, 1 arg) ────────
 * Real busy-wait, as on hardware (callers use it for short device settle
 * times). Clamped so one bad argument cannot freeze a thread. */
static void bridge_KeStallExecutionProcessor(void)
{
    static volatile LONG   calls;
    static volatile LONG64 total_usec;
    uint32_t usec = STACK_ARG(0);
    uint32_t ret = BRIDGE_MEM32(g_esp - 4);   /* the caller's pushed return address */
    LONG n;
    int s;

    for (s = 0; s < 8; ++s) {
        if (g_xbox_kernel_stall_sites[s].ret == (LONG)ret &&
            g_xbox_kernel_stall_sites[s].usec == (LONG)usec) break;
        if (g_xbox_kernel_stall_sites[s].ret == 0) {
            g_xbox_kernel_stall_sites[s].usec = (LONG)usec;
            g_xbox_kernel_stall_sites[s].ret = (LONG)ret;
            break;
        }
    }
    if (s < 8) InterlockedIncrement64(&g_xbox_kernel_stall_sites[s].calls);

    if (usec > 20000u) usec = 20000u;
    n = InterlockedIncrement(&calls);
    InterlockedAdd64(&total_usec, usec);
    /* A stall is real elapsed time on the game thread, so its total is the
     * first thing to read when frame pacing looks off. */
    if (n <= 8 || (n & 0x7FF) == 0) {
        fprintf(stderr, "  [KERNEL] KeStallExecutionProcessor #%ld: %u us "
                "(cumulative %lld us)\n", (long)n, usec, (long long)total_usec);
        fflush(stderr);
    }
    xbox_KeStallExecutionProcessor(usec);
    g_eax = 0;
}

/* ── MmLockUnlockBufferPages (175) / MmLockUnlockPhysicalPage (176) ──
 * VOID MmLockUnlockBufferPages(PVOID BaseAddress, SIZE_T NumberOfBytes,
 *                              BOOLEAN UnlockPages)
 * VOID MmLockUnlockPhysicalPage(ULONG_PTR PhysicalAddress, BOOLEAN UnlockPage)
 * Page locking pins memory for DMA. Guest memory is one permanently committed
 * mapping that is never paged out or moved, so there is nothing to pin. */
static void bridge_MmLockUnlockBufferPages(void)
{
    g_eax = 0;
}

static void bridge_MmLockUnlockPhysicalPage(void)
{
    g_eax = 0;
}

/* ── MmQueryAllocationSize (ordinal 180, 1 arg) ────────────
 * ULONG MmQueryAllocationSize(PVOID BaseAddress)
 * Page-rounded size of an allocation starting at BaseAddress. The host
 * xbox_MmQueryAllocationSize returns VirtualQuery's region size, i.e. the size
 * of the whole host reservation, not the allocation. Answer from the guest
 * allocators' own bookkeeping: the contiguous-memory blocks first, then the
 * guest heap. 0 if BaseAddress is not the start of a live allocation. */
static void bridge_MmQueryAllocationSize(void)
{
    uint32_t va = STACK_ARG(0);
    uint32_t size = 0;
    int i;

    for (i = 0; va && i < g_contiguous_block_count; ++i) {
        if (g_contiguous_blocks[i].addr == va && !g_contiguous_blocks[i].free) {
            size = g_contiguous_blocks[i].size;
            break;
        }
    }
    if (!size)
        size = xbox_HeapBlockSize(va);
    g_eax = size ? ((size + 0xFFFu) & ~0xFFFu) : 0;
}

/* ── NtQueryVirtualMemory (ordinal 217, 2 args) ────────────
 * NTSTATUS NtQueryVirtualMemory(PVOID BaseAddress,
 *                               PMEMORY_BASIC_INFORMATION Info)
 * Two arguments (confirmed against the retail call site at 0xFDEB2), not the
 * five of the Windows NT original. The Xbox MEMORY_BASIC_INFORMATION is seven
 * 32-bit fields (28 bytes); the host one is 48 bytes with 64-bit pointers, so
 * the host structure is queried and converted field by field, with addresses
 * translated back to guest VAs. */
static void bridge_NtQueryVirtualMemory(void)
{
    uint32_t base = STACK_ARG(0);
    uint32_t out  = STACK_ARG(1);
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t region_base, alloc_base, size;

    if (!out || base >= XBOX_PHYSICAL_MIRROR_TOP ||
        !VirtualQuery(XBOX_TO_NATIVE(base), &mbi, sizeof(mbi))) {
        g_eax = 0xC000000Du;   /* STATUS_INVALID_PARAMETER */
        return;
    }

    region_base = (uint64_t)((uintptr_t)mbi.BaseAddress - (uintptr_t)g_xbox_mem_offset);
    alloc_base  = mbi.AllocationBase
                      ? (uint64_t)((uintptr_t)mbi.AllocationBase - (uintptr_t)g_xbox_mem_offset)
                      : 0;
    size = mbi.RegionSize;
    /* The host region can run on past the end of the guest address space. */
    if (region_base + size > XBOX_PHYSICAL_MIRROR_TOP)
        size = region_base < XBOX_PHYSICAL_MIRROR_TOP
                   ? XBOX_PHYSICAL_MIRROR_TOP - region_base : 0;

    BRIDGE_MEM32(out + 0)  = (uint32_t)region_base;        /* BaseAddress */
    BRIDGE_MEM32(out + 4)  = (uint32_t)alloc_base;         /* AllocationBase */
    BRIDGE_MEM32(out + 8)  = (uint32_t)mbi.AllocationProtect;
    BRIDGE_MEM32(out + 12) = (uint32_t)size;               /* RegionSize */
    BRIDGE_MEM32(out + 16) = (uint32_t)mbi.State;
    BRIDGE_MEM32(out + 20) = (uint32_t)mbi.Protect;
    BRIDGE_MEM32(out + 24) = (uint32_t)mbi.Type;
    g_eax = 0;
}

/* ── NtCreateMutant (ordinal 192, 3 args) */
static void bridge_NtCreateMutant(void)
{
    uint32_t handle_va = STACK_ARG(0);
    g_eax = (uint32_t)bridge_create_mutant(
        handle_va, (BOOLEAN)STACK_ARG(2));
}

/* ── NtReleaseMutant (ordinal 221, 2 args) ─────────────────────── */
static void bridge_NtReleaseMutant(void)
{
    uint32_t previous_va = STACK_ARG(1);
    uint32_t token = STACK_ARG(0);
    LONG previous = 0;
    int mutant_handled = 0;
    NTSTATUS st = bridge_release_mutant_token(
        token, previous_va ? &previous : NULL, &mutant_handled);

    if (!mutant_handled)
        st = xbox_NtReleaseMutant(bridge_resolve_handle(token),
                                  previous_va ? &previous : NULL);

    if (previous_va)
        BRIDGE_MEM32(previous_va) = (uint32_t)previous;
    g_eax = (uint32_t)st;
}

/* ── NtResumeThread (ordinal 224, 2 args) */
static void bridge_NtResumeThread(void)
{
    g_eax = (uint32_t)xbox_NtResumeThread(
        bridge_resolve_handle(STACK_ARG(0)),
        (PULONG)XBOX_TO_NATIVE(STACK_ARG(1)));
}

/* ── ObfDereferenceObject (ordinal 250, fastcall: object in ecx)
 * Not STACK_ARG(0). Xbox uses __fastcall here, so the argument never reaches
 * the stack and the arg-size entry is 0. Reading it off the stack would
 * dereference whatever the caller happened to leave there. */
static void bridge_ObfDereferenceObject(void)
{
    xbox_ObfDereferenceObject(XBOX_TO_NATIVE(g_ecx));
    g_eax = 0;
}

/* ── PhyGetLinkState (ordinal 252, 1 arg) */
static void bridge_PhyGetLinkState(void)
{
    g_eax = (uint32_t)xbox_PhyGetLinkState((BOOLEAN)STACK_ARG(0));
}

/* ── PhyInitialize (ordinal 253, 2 args) */
static void bridge_PhyInitialize(void)
{
    g_eax = (uint32_t)xbox_PhyInitialize((BOOLEAN)STACK_ARG(0),
                                         XBOX_TO_NATIVE(STACK_ARG(1)));
}

/* ── RtlTimeToTimeFields (ordinal 305, 2 args) */
static void bridge_RtlTimeToTimeFields(void)
{
    xbox_RtlTimeToTimeFields(
        (PLARGE_INTEGER)XBOX_TO_NATIVE(STACK_ARG(0)),
        (PXBOX_TIME_FIELDS)XBOX_TO_NATIVE(STACK_ARG(1)));
    g_eax = 0;
}

/* ── XcSHAInit / XcSHAUpdate / XcSHAFinal (ordinals 335-337) */
static void bridge_XcSHAInit(void)
{
    xbox_XcSHAInit((PXBOX_SHA_CONTEXT)XBOX_TO_NATIVE(STACK_ARG(0)));
    g_eax = 0;
}

static void bridge_XcSHAUpdate(void)
{
    xbox_XcSHAUpdate((PXBOX_SHA_CONTEXT)XBOX_TO_NATIVE(STACK_ARG(0)),
                     (const UCHAR*)XBOX_TO_NATIVE(STACK_ARG(1)),
                     STACK_ARG(2));
    g_eax = 0;
}

static void bridge_XcSHAFinal(void)
{
    xbox_XcSHAFinal((PXBOX_SHA_CONTEXT)XBOX_TO_NATIVE(STACK_ARG(0)),
                    (UCHAR*)XBOX_TO_NATIVE(STACK_ARG(1)));
    g_eax = 0;
}

/* ── XcRC4Key / XcRC4Crypt (ordinals 338-339) */
static void bridge_XcRC4Key(void)
{
    xbox_XcRC4Key((PXBOX_RC4_CONTEXT)XBOX_TO_NATIVE(STACK_ARG(0)),
                  STACK_ARG(1),
                  (const UCHAR*)XBOX_TO_NATIVE(STACK_ARG(2)));
    g_eax = 0;
}

static void bridge_XcRC4Crypt(void)
{
    xbox_XcRC4Crypt((PXBOX_RC4_CONTEXT)XBOX_TO_NATIVE(STACK_ARG(0)),
                    STACK_ARG(1),
                    (UCHAR*)XBOX_TO_NATIVE(STACK_ARG(2)));
    g_eax = 0;
}

/* ── XcHMAC (ordinal 340, 7 args) */
static void bridge_XcHMAC(void)
{
    xbox_XcHMAC((const UCHAR*)XBOX_TO_NATIVE(STACK_ARG(0)), STACK_ARG(1),
                (const UCHAR*)XBOX_TO_NATIVE(STACK_ARG(2)), STACK_ARG(3),
                (const UCHAR*)XBOX_TO_NATIVE(STACK_ARG(4)), STACK_ARG(5),
                (UCHAR*)XBOX_TO_NATIVE(STACK_ARG(6)));
    g_eax = 0;
}

/* ── RtlCompareMemoryUlong (ordinal 269, 3 args) ───────────
 * SIZE_T RtlCompareMemoryUlong(PVOID Source, SIZE_T Length, ULONG Pattern)
 * Bytes at Source (in whole ULONGs) that equal Pattern. Reads caller memory
 * only; Length and the result are 32-bit on both sides. */
static void bridge_RtlCompareMemoryUlong(void)
{
    g_eax = (uint32_t)xbox_RtlCompareMemoryUlong(
        XBOX_TO_NATIVE(STACK_ARG(0)), STACK_ARG(1), STACK_ARG(2));
}

/* ── RtlTimeFieldsToTime (ordinal 304, 2 args) ─────────────
 * BOOLEAN RtlTimeFieldsToTime(PTIME_FIELDS TimeFields, PLARGE_INTEGER Time)
 * TIME_FIELDS is eight 16-bit fields and LARGE_INTEGER is 8 bytes on both
 * sides, so the host function can work on the guest bytes in place. */
static void bridge_RtlTimeFieldsToTime(void)
{
    g_eax = xbox_RtlTimeFieldsToTime(
                (PXBOX_TIME_FIELDS)XBOX_TO_NATIVE(STACK_ARG(0)),
                (PLARGE_INTEGER)XBOX_TO_NATIVE(STACK_ARG(1))) ? 1u : 0u;
}

/* ── IoDeleteSymbolicLink (ordinal 69, 1 arg) ──────────────
 * NTSTATUS IoDeleteSymbolicLink(PSTRING SymbolicLinkName)
 * Mirrors bridge_IoCreateSymbolicLink, which records nothing and succeeds, so
 * there is no link to remove and deleting one succeeds the same way. */
static void bridge_IoDeleteSymbolicLink(void)
{
    g_eax = 0;   /* STATUS_SUCCESS */
}

/* ── XeLoadSection / XeUnloadSection (ordinals 327 / 328, 1 arg) ──
 * NTSTATUS Xe{Load,Unload}Section(PXBEIMAGE_SECTION Section)
 * Maps or releases a section that was not preloaded. The recompiled image maps
 * every XBE section into guest memory up front, so a section is always
 * resident and both calls succeed. The kernel's reference counts inside the
 * section header are deliberately not touched: the header sits in the mapped
 * image (not guaranteed writable) and nothing but the kernel reads them. */
static void bridge_XeLoadSection(void)   { g_eax = 0; }
static void bridge_XeUnloadSection(void) { g_eax = 0; }

/* ── HalInitiateShutdown (ordinal 360, void) ───────────────
 * The title asking the console to shut down: the process ends, as the kernel's
 * would. stderr is flushed first so the final log lines survive. */
static void bridge_HalInitiateShutdown(void)
{
    fprintf(stderr, "  [KERNEL] HalInitiateShutdown: title requested shutdown\n");
    fflush(stderr);
    xbox_HalInitiateShutdown();
    g_eax = 0;
}

/* ── XcDESKeyParity (ordinal 346, 2 args) */
static void bridge_XcDESKeyParity(void)
{
    xbox_XcDESKeyParity((PUCHAR)XBOX_TO_NATIVE(STACK_ARG(0)), STACK_ARG(1));
    g_eax = 0;
}

/* ── Dispatch table: ordinal → bridge function + stack arg bytes ── */

typedef void (*bridge_func_t)(void);

/**
 * stdcall arg byte count for each kernel ordinal.
 * On x86 stdcall, the callee cleans (ret N). Our bridges must do the same
 * via g_esp += N after execution so the simulated stack stays balanced.
 *
 * Special cases:
 *   - KfRaiseIrql/KfLowerIrql: fastcall (arg in ecx), 0 stack bytes
 *   - KeSetTimer: DueTime is LARGE_INTEGER (8 bytes on stack) + Timer + Dpc
 */
static int stdcall_args_for_ordinal(ULONG ordinal)
{
    switch (ordinal) {
    /* ── Display / AV ── */
    case   1: return  0;  /* AvGetSavedDataAddress (void) */
    case   2: return 16;  /* AvSendTVEncoderOption (4) */
    case   3: return 24;  /* AvSetDisplayMode (6) */
    case   4: return  4;  /* AvSetSavedDataAddress (1) */
    case   5: return  0;  /* DbgBreakPoint (void) */
    case   8: return  0;  /* DbgPrint - __cdecl varargs, caller cleans */
    case   9: return  8;  /* HalReadSMCTrayState (2) */
    case  14: return  4;  /* ExAllocatePool (1) */
    case  15: return  8;  /* ExAllocatePoolWithTag (2) */
    case  17: return  4;  /* ExFreePool (1) */
    case  23: return  4;  /* ExQueryPoolBlockSize (1) */
    case  24: return 20;  /* ExQueryNonVolatileSetting (5) */
    case  35: return  0;  /* FscGetCacheSize (void) */
    case  37: return  4;  /* FscSetCacheSize (1) */
    case  38: return  4;  /* HalClearSoftwareInterrupt (1) */
    case  39: return  8;  /* HalDisableSystemInterrupt (2) */
    case  42: return  0;  /* HalDiskSerialNumber - data export */
    case  44: return  8;  /* HalGetInterruptVector (2) */
    case  47: return  8;  /* HalRegisterShutdownNotification (2) */
    case  46: return 24;  /* HalReadWritePCISpace (6) */
    case  48: return  4;  /* HalRequestSoftwareInterrupt (1) */
    case  49: return  4;  /* HalReturnToFirmware (1) */
    case  61: return 36;  /* IoBuildDeviceIoControlRequest (9) */
    case  62: return 28;  /* IoBuildSynchronousFsdRequest (7) */
    case  65: return 24;  /* IoCreateDevice (6) */
    case  66: return 40;  /* IoCreateFile (10) */
    case  67: return  8;  /* IoCreateSymbolicLink (2) */
    case  68: return  4;  /* IoDeleteDevice (1) */
    case  69: return  4;  /* IoDeleteSymbolicLink (1) */
    case  73: return 12;  /* IoInitializeIrp (3) */
    case  74: return  8;  /* IoInvalidDeviceRequest (2) */
    case  79: return 20;  /* IoSetIoCompletion (5) */
    case  81: return  8;  /* IoStartNextPacket (2) */
    case  82: return 12;  /* IoStartNextPacketByKey (3) */
    case  83: return 16;  /* IoStartPacket (4) */
    case  84: return 32;  /* IoSynchronousDeviceIoControlRequest (8) */
    case  85: return 20;  /* IoSynchronousFsdRequest (5) */
    case  86: return  0;  /* IofCallDriver (fastcall: args in ecx/edx) */
    case  87: return  0;  /* IofCompleteRequest (fastcall: args in ecx/edx) */
    case  93: return  8;  /* KeAlertThread (2) */
    case  95: return  4;  /* KeBugCheck (1) */
    case  96: return 20;  /* KeBugCheckEx (5) */
    case  97: return  4;  /* KeCancelTimer (1) */
    case  98: return  4;  /* KeConnectInterrupt (1) */
    case  99: return 12;  /* KeDelayExecutionThread (3) */
    case 100: return  4;  /* KeDisconnectInterrupt (1) */
    case 107: return 12;  /* KeInitializeDpc (3) */
    case 109: return 28;  /* KeInitializeInterrupt (7) */
    case 113: return  8;  /* KeInitializeTimerEx (2) */
    case 119: return 12;  /* KeInsertQueueDpc (3) */
    case 124: return  4;  /* KeQueryBasePriorityThread (1) */
    case 125: return  0;  /* KeQueryInterruptTime (void) */
    case 126: return  0;  /* KeQueryPerformanceCounter (void) */
    case 127: return  0;  /* KeQueryPerformanceFrequency (void) */
    case 128: return  4;  /* KeQuerySystemTime (1) */
    case 129: return  0;  /* KeRaiseIrqlToDpcLevel (void) */
    case 137: return  4;  /* KeRemoveQueueDpc (1) */
    case 139: return  4;  /* KeRestoreFloatingPointState (1) */
    case 142: return  4;  /* KeSaveFloatingPointState (1) */
    case 143: return  8;  /* KeSetBasePriorityThread (2) */
    case 144: return  8;  /* KeSetDisableBoostThread (2) */
    case 145: return 12;  /* KeSetEvent (3) */
    case 149: return 16;  /* KeSetTimer (Timer+DueTime[8]+Dpc) */
    case 150: return 20;  /* KeSetTimerEx (Timer+DueTime[8]+Period+Dpc) */
    case 151: return  4;  /* KeStallExecutionProcessor (1) */
    case 153: return 12;  /* KeSynchronizeExecution (3) */
    case 158: return 32;  /* KeWaitForMultipleObjects (8) */
    case 159: return 20;  /* KeWaitForSingleObject (5) */
    case 160: return  0;  /* KfRaiseIrql (fastcall: arg in ecx) */
    case 161: return  0;  /* KfLowerIrql (fastcall: arg in ecx) */
    case 165: return  4;  /* MmAllocateContiguousMemory (1) */
    case 166: return 20;  /* MmAllocateContiguousMemoryEx (5) */
    case 167: return  8;  /* MmAllocateSystemMemory (2) */
    case 168: return  8;  /* MmClaimGpuInstanceMemory (2) */
    case 169: return  8;  /* MmCreateKernelStack (2) */
    case 170: return  8;  /* MmDeleteKernelStack (2) */
    case 171: return  4;  /* MmFreeContiguousMemory (1) */
    case 172: return  8;  /* MmFreeSystemMemory (2) */
    case 173: return  4;  /* MmGetPhysicalAddress (1) */
    case 175: return 12;  /* MmLockUnlockBufferPages (3) */
    case 176: return  8;  /* MmLockUnlockPhysicalPage (2) */
    case 177: return 12;  /* MmMapIoSpace (3) */
    case 178: return 12;  /* MmPersistContiguousMemory (3) */
    case 179: return  4;  /* MmQueryAddressProtect (1) */
    case 180: return  4;  /* MmQueryAllocationSize (1) */
    case 181: return  4;  /* MmQueryStatistics (1) */
    case 182: return 12;  /* MmSetAddressProtect (3) */
    case 184: return 20;  /* NtAllocateVirtualMemory (5) */
    case 185: return  8;  /* NtCancelTimer (2) */
    case 186: return  4;  /* NtClearEvent (1) */
    case 187: return  4;  /* NtClose (1) */
    case 188: return  8;  /* NtCreateDirectoryObject (2) */
    case 189: return 16;  /* NtCreateEvent (4) */
    case 190: return 36;  /* NtCreateFile (9) */
    case 191: return 16;  /* NtCreateIoCompletion (4) */
    case 192: return 12;  /* NtCreateMutant (3) */
    case 193: return 16;  /* NtCreateSemaphore (4) */
    case 194: return 12;  /* NtCreateTimer (3) */
    case 195: return  4;  /* NtDeleteFile (1) */
    case 196: return 40;  /* NtDeviceIoControlFile (10) */
    case 197: return 12;  /* NtDuplicateObject (3) */
    case 198: return  8;  /* NtFlushBuffersFile (2) */
    case 199: return 12;  /* NtFreeVirtualMemory (3) */
    case 200: return 40;  /* NtFsControlFile (10) */
    case 202: return 24;  /* NtOpenFile (6) */
    case 203: return  8;  /* NtOpenSymbolicLinkObject (2) */
    case 204: return 16;  /* NtProtectVirtualMemory (4) */
    case 205: return  8;  /* NtPulseEvent (2) */
    case 206: return 20;  /* NtQueueApcThread (5) */
    case 207: return 36;  /* NtQueryDirectoryFile (9) */
    case 210: return  8;  /* NtQueryFullAttributesFile (2) */
    case 211: return 20;  /* NtQueryInformationFile (5) */
    case 215: return 12;  /* NtQuerySymbolicLinkObject (3) */
    case 217: return  8;  /* NtQueryVirtualMemory (2: BaseAddress, Info) -- the retail
                           * call site at 0xFDEB2 pushes exactly two; the earlier 16
                           * (the NT 4-arg shape) over-popped the guest stack by 8 */
    case 218: return 20;  /* NtQueryVolumeInformationFile (5) */
    case 219: return 32;  /* NtReadFile (8) */
    case 220: return 32;  /* NtReadFileScatter (8) */
    case 221: return  8;  /* NtReleaseMutant (2) */
    case 222: return 12;  /* NtReleaseSemaphore (3) */
    case 223: return 20;  /* NtRemoveIoCompletion (5) */
    case 224: return  8;  /* NtResumeThread (2) */
    case 225: return  8;  /* NtSetEvent (2) */
    case 226: return 20;  /* NtSetInformationFile (5) */
    case 227: return 20;  /* NtSetIoCompletion (5) */
    case 228: return  8;  /* NtSetSystemTime (2) */
    case 229: return 32;  /* NtSetTimerEx (8) */
    case 230: return 20;  /* NtSignalAndWaitForSingleObjectEx (5) */
    case 231: return  8;  /* NtSuspendThread (2) */
    case 232: return 12;  /* NtUserIoApcDispatcher (3) */
    case 233: return 12;  /* NtWaitForSingleObject (3) */
    case 234: return 16;  /* NtWaitForSingleObjectEx (4) */
    case 235: return 24;  /* NtWaitForMultipleObjectsEx (6, includes WaitMode) */
    case 236: return 32;  /* NtWriteFile (8) */
    case 237: return 32;  /* NtWriteFileGather (8) */
    case 238: return  0;  /* NtYieldExecution (void) */
    case 243: return 16;  /* ObOpenObjectByName (4) */
    case 247: return 20;  /* ObReferenceObjectByName (5) */
    case 250: return  0;  /* ObfDereferenceObject (fastcall: arg in ecx) */
    case 252: return  4;  /* PhyGetLinkState (1) */
    case 253: return  8;  /* PhyInitialize (2) */
    case 255: return 40;  /* PsCreateSystemThreadEx (10) */
    case 258: return  4;  /* PsTerminateSystemThread (1) */
    case 260: return 12;  /* RtlAnsiStringToUnicodeString (3) */
    case 268: return 12;  /* RtlCompareMemory (3) */
    case 269: return 12;  /* RtlCompareMemoryUlong (3) */
    case 270: return 12;  /* RtlCompareString (3) */
    case 277: return  4;  /* RtlEnterCriticalSection (1) */
    case 279: return 12;  /* RtlEqualString (3) */
    case 285: return 12;  /* RtlFillMemoryUlong (3) */
    case 286: return  4;  /* RtlFreeAnsiString (1) */
    case 289: return  8;  /* RtlInitAnsiString (2) */
    case 290: return  8;  /* RtlInitUnicodeString (2) */
    case 291: return  4;  /* RtlInitializeCriticalSection (1) */
    case 294: return  4;  /* RtlLeaveCriticalSection (1) */
    case 301: return  4;  /* RtlNtStatusToDosError (1) */
    case 302: return  4;  /* RtlRaiseException (1) */
    case 304: return  8;  /* RtlTimeFieldsToTime (2) */
    case 305: return  8;  /* RtlTimeToTimeFields (2) */
    case 308: return 12;  /* RtlUnicodeStringToAnsiString (3) */
    case 312: return 16;  /* RtlUnwind (4) */
    case 327: return  4;  /* XeLoadSection (1) */
    case 328: return  4;  /* XeUnloadSection (1) */
    case 333: return 12;  /* WRITE_PORT_BUFFER_USHORT (3) */
    case 334: return 12;  /* WRITE_PORT_BUFFER_ULONG (3) */
    case 335: return  4;  /* XcSHAInit (1) */
    case 336: return 12;  /* XcSHAUpdate (3) */
    case 337: return  8;  /* XcSHAFinal (2) */
    case 338: return 12;  /* XcRC4Key (3) */
    case 339: return 12;  /* XcRC4Crypt (3) */
    case 340: return 28;  /* XcHMAC (7) */
    case 342: return 12;  /* XcPKDecPrivate (3) */
    case 343: return  4;  /* XcPKGetKeyLen (1) */
    case 344: return 12;  /* XcVerifyPKCS1Signature (3) */
    case 345: return 20;  /* XcModExp (5) */
    case 346: return  8;  /* XcDESKeyParity (2) */
    case 347: return 12;  /* XcKeyTable (3) */
    case 349: return 28;  /* XcBlockCryptCBC (7) */
    case 351: return  8;  /* XcUpdateCrypto (2) */
    case 352: return 12;  /* RtlRip (3) */
    case 358: return  0;  /* HalIsResetOrShutdownPending (void) */
    case 359: return  4;  /* IoMarkIrpMustComplete (1) */

    /* ── Unknown stubs ── */

    /* ── Pool Allocator ── */
    /* ordinal 16 is the ExEventObjectType data export; see
     * kernel_thunks.c, which points its thunk at kernel data.
     * 17 is ExFreePool and is a real function. */

    /* ── HAL ── */

    /* ── I/O Manager ── */
    /* ordinal 64 is the IoCompletionObjectType data export; see
     * kernel_thunks.c. 65 is IoCreateDevice, a real function. */
    /* case  71: DATA export - IoDeviceObjectType */

    /* ── Kernel Synchronization ── */
    /* case 156: DATA export - KeTickCount */

    /* ── Launch Data ── */
    /* case 164: DATA export - LaunchDataPage */

    /* ── Memory Management ── */

    /* ── NT Virtual Memory ── */

    /* ── NT File I/O & Handle ── */

    /* ── Object Manager ── */
    case 246: return 12;  /* ObReferenceObjectByHandle(3) - Xbox: Handle,Type,Object* */
    case 360: return  0;  /* HalInitiateShutdown (void) */

    /* ── Network / PHY ── */

    /* ── Threading ── */
    /* case 259: DATA export - PsThreadObjectType */

    /* ── Runtime Library ── */

    /* ── Xbox Identity (data exports) ── */
    /* cases 322-328, 355-357: DATA exports */

    /* ── Port I/O ── */

    /* ── Crypto ── */

    default:  return  0;  /* DATA exports or truly unknown */
    }
}

static bridge_func_t bridge_for_ordinal(ULONG ordinal)
{
    switch (ordinal) {
    /* Threading */
    case 255: return bridge_PsCreateSystemThreadEx;
    case 258: return bridge_PsTerminateSystemThread;

    /* File/Handle */
    case 187: return bridge_NtClose;
    case 190: return bridge_NtCreateFile;
    case 279: return bridge_RtlEqualString;
    case 289: return bridge_RtlInitAnsiString;
    case 312: return bridge_RtlUnwind;
    case 195: return bridge_NtDeleteFile;
    case 196: return bridge_NtDeviceIoControlFile;
    case 198: return bridge_NtFlushBuffersFile;
    case 200: return bridge_NtFsControlFile;
    case 202: return bridge_NtOpenFile;
    case 203: return bridge_NtOpenSymbolicLinkObject;
    case 207: return bridge_NtQueryDirectoryFile;
    case 210: return bridge_NtQueryFullAttributesFile;
    case 211: return bridge_NtQueryInformationFile;
    case 215: return bridge_NtQuerySymbolicLinkObject;
    case 218: return bridge_NtQueryVolumeInformationFile;
    case 219: return bridge_NtReadFile;
    case 226: return bridge_NtSetInformationFile;
    case 236: return bridge_NtWriteFile;

    /* Memory - contiguous */
    case 165: return bridge_MmAllocateContiguousMemory;
    case 166: return bridge_MmAllocateContiguousMemoryEx;
    case 171: return bridge_MmFreeContiguousMemory;
    case 173: return bridge_MmGetPhysicalAddress;
    case 182: return bridge_MmSetAddressProtect;
    case 181: return bridge_MmQueryStatistics;

    /* HAL / PCI configuration used by the stock XDK D3D8 initializer. */
    case  46: return bridge_HalReadWritePCISpace;

    /* Memory - virtual */
    case 184: return bridge_NtAllocateVirtualMemory;
    case 199: return bridge_NtFreeVirtualMemory;

    /* Pool */
    case  14: return bridge_ExAllocatePool;
    case  15: return bridge_ExAllocatePoolWithTag;
    case  23: return bridge_ExQueryPoolBlockSize;
    case  24: return bridge_ExQueryNonVolatileSetting;

    /* IRQL */
    case 160: return bridge_KfRaiseIrql;
    case 161: return bridge_KfLowerIrql;
    case 129: return bridge_KeRaiseIrqlToDpcLevel;

    /* Critical sections */
    case 291: return bridge_RtlInitializeCriticalSection;
    case 277: return bridge_RtlEnterCriticalSection;
    case 294: return bridge_RtlLeaveCriticalSection;

    /* Timing */
    case 126: return bridge_KeQueryPerformanceCounter;
    case 127: return bridge_KeQueryPerformanceFrequency;
    case 128: return bridge_KeQuerySystemTime;
    case 149: return bridge_KeSetTimer;
    case 150: return bridge_KeSetTimer;  /* KeSetTimerEx */

    /* DPC / Timer init */
    case 107: return bridge_KeInitializeDpc;
    case 113: return bridge_KeInitializeTimerEx;

    /* NV2A interrupt plumbing */
    case  44: return bridge_HalGetInterruptVector;
    case  98: return bridge_KeConnectInterrupt;
    case 109: return bridge_KeInitializeInterrupt;
    case  47: return bridge_HalRegisterShutdownNotification;
    case 168: return bridge_MmClaimGpuInstanceMemory;

    /* Synchronization */
    case 189: return bridge_NtCreateEvent;
    case 145: return bridge_KeSetEvent;
    case 159: return bridge_KeWaitForSingleObject;
    case  99: return bridge_KeDelayExecutionThread;
    case 179: return bridge_MmQueryAddressProtect;
    case 232: return bridge_NtUserIoApcDispatcher;
    case  95: return bridge_KeBugCheck;
    case  96: return bridge_KeBugCheckEx;
    case 186: return bridge_NtClearEvent;
    case 205: return bridge_NtPulseEvent;
    case 221: return bridge_NtReleaseMutant;
    case 225: return bridge_NtSetEvent;
    case 233: return bridge_NtWaitForSingleObject;
    case 234: return bridge_NtWaitForSingleObjectEx;
    case 235: return bridge_NtWaitForMultipleObjectsEx;
    case 238: return bridge_NtYieldExecution;

    /* Hardware */
    case   9: return bridge_HalReadSMCTrayState;
    case  49: return bridge_HalReturnToFirmware;

    /* Display */
    case   3: return bridge_AvSetDisplayMode;

    /* I/O */
    case  66: return bridge_IoCreateFile;
    case  67: return bridge_IoCreateSymbolicLink;
    case 188: return bridge_NtCreateDirectoryObject;
    case 246: return bridge_ObReferenceObjectByHandle;

    /* Memory - I/O mapping */
    case 177: return bridge_MmMapIoSpace;
    case 178: return bridge_MmPersistContiguousMemory;

    /* RTL */
    case 301: return bridge_RtlNtStatusToDosError;
    case 302: return bridge_RtlRaiseException;


    /* BISECT-OFF case 338: bridge_XcRC4Key */
    /* BISECT-OFF case 339: bridge_XcRC4Crypt */


    /* NOT ROUTED, deliberately. The wrappers above exist and compile, and each
     * has a working xbox_* behind it, but routing them made Halo 2276 crash
     * EARLIER than leaving them stubbed -- twice, with two different faults.
     * Bisected to a memory-model mismatch, not to the wrappers' arithmetic:
     *
     *   xbox_IoCreateDevice HeapAllocs from GetProcessHeap() and writes that
     *   NATIVE pointer through its out-parameter. The bridge hands it the
     *   native address of a 4-BYTE GUEST slot, so a 64-bit pointer is written
     *   into 4 bytes: it clobbers the adjacent guest dword and leaves the title
     *   a truncated pointer it then dereferences. Crash was a write to
     *   0x90909090.
     *
     *   xbox_ExFreePool calls HeapFree(GetProcessHeap(), P). Guest pool memory
     *   is not on the host heap, so P is a pointer HeapFree has never seen.
     *
     * These xbox_* functions were written for a NATIVE caller, where pointers
     * are host pointers and allocations are host allocations. The bridge is a
     * different world: pointers are guest VAs and memory lives in the mapped
     * guest space. XBOX_TO_NATIVE converts an address; it cannot convert an
     * allocator.
     *
     * So 'an xbox_* exists, therefore the wrapper is mechanical' is false, and
     * tools.kernel_audit.coverage no longer says it. Each of these needs its
     * memory model checked one at a time: which side owns the allocation, and
     * whether an out-pointer must carry a guest VA. Ones that only read or
     * write bytes at a caller-supplied address (the Xc* crypto group,
     * RtlTimeToTimeFields) should be fine; ones that allocate, free, or hand
     * back a pointer are not.
     *
     * Left in place rather than deleted: the wrappers are correct as argument
     * marshalling, and re-deriving them is the easy half of the work.
     */
    /* ROUTED after a per-ordinal memory-model check (see tools/kernel_audit/
     * test_dah2_import_coverage.py, which keeps every ordinal DAH2 imports
     * routed). Each wrapper below was either rewritten to work on guest
     * addresses and the guest allocators, or reduced to the semantics this
     * layer can actually honour, rather than forwarding guest pointers into
     * host-layout xbox_* code -- the failure mode described above. */
    case   1: return bridge_AvGetSavedDataAddress;
    case   2: return bridge_AvSendTVEncoderOption;     /* observation-only */
    case   4: return bridge_AvSetSavedDataAddress;
    case   8: return bridge_DbgPrint;
    case  17: return bridge_ExFreePool;                /* guest heap */
    case  69: return bridge_IoDeleteSymbolicLink;
    /* case  65: bridge_IoCreateDevice -- not imported by DAH2; still unsafe */
    case  97: return bridge_KeCancelTimer;
    case 100: return bridge_KeDisconnectInterrupt;
    case 119: return bridge_KeInsertQueueDpc;
    case 137: return bridge_KeRemoveQueueDpc;
    case 139: return bridge_KeRestoreFloatingPointState;
    case 142: return bridge_KeSaveFloatingPointState;
    case 143: return bridge_KeSetBasePriorityThread;
    case 151: return bridge_KeStallExecutionProcessor;
    case 153: return bridge_KeSynchronizeExecution;
    case 175: return bridge_MmLockUnlockBufferPages;
    case 176: return bridge_MmLockUnlockPhysicalPage;
    case 180: return bridge_MmQueryAllocationSize;
    case 192: return bridge_NtCreateMutant;
    case 217: return bridge_NtQueryVirtualMemory;
    /* Routed. Checked against the memory-model warning above rather than
     * assumed mechanical: NtResumeThread takes a handle token and writes a
     * 4-byte suspend count through an optional out-parameter. Guest ULONG and
     * host ULONG are both 4 bytes, XBOX_TO_NATIVE already maps NULL to NULL,
     * and xbox_NtResumeThread checks the pointer before writing. Nothing
     * allocates, frees, or hands back a host pointer -- which is what
     * disqualified IoCreateDevice and ExFreePool.
     *
     * Halo 2276 calls this immediately before its first camera frustum build;
     * unbridged it returned 0 (STATUS_SUCCESS) without resuming anything, so a
     * thread the title had created suspended never started. */
    case 224: return bridge_NtResumeThread;
    case 250: return bridge_ObfDereferenceObject;      /* fastcall, ecx */
    /* case 252: bridge_PhyGetLinkState -- not imported by DAH2 */
    /* case 253: bridge_PhyInitialize -- not imported by DAH2 */
    case 269: return bridge_RtlCompareMemoryUlong;
    case 304: return bridge_RtlTimeFieldsToTime;
    case 305: return bridge_RtlTimeToTimeFields;
    case 327: return bridge_XeLoadSection;
    case 328: return bridge_XeUnloadSection;
    case 335: return bridge_XcSHAInit;
    case 336: return bridge_XcSHAUpdate;
    case 337: return bridge_XcSHAFinal;
    case 340: return bridge_XcHMAC;
    /* case 346: bridge_XcDESKeyParity -- not imported by DAH2 */
    case 360: return bridge_HalInitiateShutdown;

    default:  return NULL;
    }
}

/* ── Per-slot bridge functions (resolved at init) ────────── */

static bridge_func_t g_slot_bridges[XBOX_KERNEL_THUNK_TABLE_SIZE];
static int g_slot_arg_bytes[XBOX_KERNEL_THUNK_TABLE_SIZE];

/* Xbox VA to sample around each bridge call; 0 = off. See dispatch. */
uint32_t g_kernel_watch_va = 0;

/* Current dispatching slot. Lookup and dispatch execute on the calling guest
 * thread, and concurrent guest workers can resolve different thunk ordinals.
 * This must track the TLS register file or one worker can make another bridge
 * use the wrong handler and, critically, the wrong stdcall argument cleanup. */
static RECOMP_TLS int g_kernel_dispatch_slot = -1;

/* No specific bridge - the caller gets 0. Warn once per slot rather than
 * gating on g_kernel_call_count: a missing bridge is rare and is usually the
 * reason a game misbehaves, so it must not be swallowed by the general
 * call-trace throttle. Bounded to one line per slot. */
static void kernel_warn_no_bridge(int slot, ULONG ordinal)
{
    static uint8_t warned[XBOX_KERNEL_THUNK_TABLE_SIZE];
    if (!warned[slot]) {
        warned[slot] = 1;
        fprintf(stderr, "  [KERNEL] WARNING: no bridge for ordinal %u (slot %d), returning 0\n",
                ordinal, slot);
        fflush(stderr);
    }
}

static void kernel_thunk_dispatch(void)
{
    int slot = g_kernel_dispatch_slot;
    bridge_func_t bridge;
    ULONG ordinal;

    if (slot < 0 || slot >= XBOX_KERNEL_THUNK_TABLE_SIZE) {
        fprintf(stderr, "  [KERNEL] bad slot %d\n", slot);
        g_eax = 0;
        g_esp += 4;  /* pop dummy return address */
        return;
    }

    ordinal = g_slot_ordinals[slot];
    bridge = g_slot_bridges[slot];

    if (ordinal == 234) {
        static LONG wait_ex_trace_count;
        if (InterlockedIncrement(&wait_ex_trace_count) <= 20) {
            fprintf(stderr,
                    "  [KERNEL] NtWaitForSingleObjectEx callsite=0x%08X token=0x%08X "
                    "mode=%u alertable=%u timeout=0x%08X\n",
                    BRIDGE_MEM32(g_esp), BRIDGE_MEM32(g_esp + 4),
                    BRIDGE_MEM32(g_esp + 8), BRIDGE_MEM32(g_esp + 12),
                    BRIDGE_MEM32(g_esp + 16));
            fflush(stderr);
        }
    }

    g_kernel_call_count++;

    if (g_kernel_call_count <= 400) {
        /* The guest return address sits at the top of the guest stack: the
         * caller pushed it before dispatching here. Logging it turns "some
         * function is calling this" into "this call site is", which is the
         * difference between guessing and knowing when a title recurses. */
        fprintf(stderr,
                "  [KERNEL] #%d: ordinal %u (slot %d) esp=0x%08X ret=0x%08X\n",
                g_kernel_call_count, ordinal, slot, g_esp,
                g_esp ? BRIDGE_MEM32(g_esp) : 0);
        fflush(stderr);
    }

    {
        static DWORD last_summary_tick = 0;
        DWORD now = GetTickCount();
        if (last_summary_tick == 0) last_summary_tick = now;
        if (now - last_summary_tick >= 2000 && g_kernel_call_count > 200) {
            fprintf(stderr, "  [KERNEL] summary: %d total calls, latest ordinal %u (slot %d) esp=0x%08X\n",
                    g_kernel_call_count, ordinal, slot, g_esp);
            fflush(stderr);
            last_summary_tick = now;
        }
    }

    /* Pop the dummy return address that PUSH32(esp, 0) pushed before RECOMP_ICALL.
     * On real x86, "call [thunk]" pushes a real return address and "ret" pops it.
     * In our model, the bridge is called directly (not via the simulated stack),
     * so we must manually consume the dummy return address. */
    g_esp += 4;

    /* Name the bridge that corrupts a watched dword.
     *
     * A bridge hands Xbox pointers to real Win32 calls, so a bad one has
     * Windows write into Xbox memory -- the resulting wild write has a stack
     * inside ntdll with no recompiled frame to blame, and a watchpoint just
     * says "something changed". Sampling either side of the call names the
     * ordinal directly, which is the one fact those tools cannot give.
     *
     * Set g_kernel_watch_va to arm; zero (the default) costs one compare. */
    uint32_t _watch_before = 0;
    if (g_kernel_watch_va) {
        _watch_before = BRIDGE_MEM32(g_kernel_watch_va);
    }

    {
        LARGE_INTEGER _t0, _t1;
        QueryPerformanceCounter(&_t0);
        g_xbox_kernel_stat_ordinal[slot] = (LONG)ordinal;
        InterlockedIncrement64(&g_xbox_kernel_stat_calls[slot]);
        if (bridge) {
            bridge();
        } else {
            g_eax = 0;
            kernel_warn_no_bridge(slot, ordinal);
        }
        QueryPerformanceCounter(&_t1);
        InterlockedAdd64(&g_xbox_kernel_stat_ticks[slot], _t1.QuadPart - _t0.QuadPart);
        if ((LONG)GetCurrentThreadId() == g_dah2_present_thread_id) {
            InterlockedIncrement64(&g_xbox_kernel_frame_calls[slot]);
            InterlockedAdd64(&g_xbox_kernel_frame_ticks[slot], _t1.QuadPart - _t0.QuadPart);
        }
    }

    /* Clean stdcall args from the simulated stack.
     * On real x86, stdcall callee does "ret N" to pop the return address
     * and N bytes of arguments. We already popped the dummy return address
     * above; now pop the args. */
    g_esp += g_slot_arg_bytes[slot];

    if (g_kernel_watch_va) {
        uint32_t _after = BRIDGE_MEM32(g_kernel_watch_va);
        if (_after != _watch_before) {
            fprintf(stderr,
                    "  [KWATCH] ordinal %u changed Xbox VA 0x%08X: "
                    "%08X -> %08X\n",
                    ordinal, g_kernel_watch_va, _watch_before, _after);
            fflush(stderr);
        }
    }

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] → returned 0x%08X\n", g_eax);
        fflush(stderr);
    }
}

/* ── Dispatch lookup ────────────────────────────────────── */

/**
 * Look up a kernel thunk by synthetic VA.
 * Called as a fallback when recomp_lookup() returns NULL.
 */
recomp_func_t recomp_lookup_kernel(uint32_t xbox_va)
{
    if (xbox_va >= KERNEL_VA_BASE && xbox_va < KERNEL_VA_END) {
        int slot = (xbox_va - KERNEL_VA_BASE) / 4;
        if (slot >= 0 && slot < XBOX_KERNEL_THUNK_TABLE_SIZE) {
            g_kernel_dispatch_slot = slot;
            return kernel_thunk_dispatch;
        }
    }
    return NULL;
}

/* ── Initialization ─────────────────────────────────────── */

/*
 * Where this title's kernel thunk table lives. Defaults to the compile-time
 * constant, but every XBE puts it somewhere different (it comes from the
 * header's KernelImageThunkAddress), so xbox_MemoryLayoutInit() parses the
 * real address out of the binary and overrides it here.
 *
 * Halo build 2276 puts it at 0x00253090 against the default's 0x0036B7C0 --
 * without the override the bridge patches ordinals into whatever happens to
 * live at the wrong address and every kernel call goes somewhere arbitrary.
 */
static uint32_t g_thunk_table_base  = XBOX_KERNEL_THUNK_TABLE_BASE;
static uint32_t g_thunk_table_count = XBOX_KERNEL_THUNK_TABLE_SIZE;

void xbox_kernel_set_thunk_address(uint32_t xbox_va, uint32_t count)
{
    if (!xbox_va) {
        return;
    }

    g_thunk_table_base = xbox_va;

    /* count indexes g_slot_* arrays, which are sized by the macro. A title
     * importing more slots than the real kernel exports would run off them. */
    if (count && count <= XBOX_KERNEL_THUNK_TABLE_SIZE) {
        g_thunk_table_count = count;
    } else if (count > XBOX_KERNEL_THUNK_TABLE_SIZE) {
        fprintf(stderr,
                "  Kernel thunk bridge: XBE declares %u thunk slots, clamping to %d\n",
                count, XBOX_KERNEL_THUNK_TABLE_SIZE);
        g_thunk_table_count = XBOX_KERNEL_THUNK_TABLE_SIZE;
    }
}

/**
 * Resolve the kernel thunk table in Xbox memory.
 *
 * Must be called AFTER xbox_MemoryLayoutInit() so Xbox memory is mapped.
 *
 * Reads the actual ordinals from the XBE memory thunk table (0x80000000|ordinal),
 * resolves each to a per-ordinal bridge function, and replaces the entry
 * with a synthetic VA for dispatch.
 */
/* Per-title ordinal remap; NULL = identity (the kernel's own XDK). Set by
 * xbox_kernel_set_ordinal_remap before init. See kernel.h. */
static const unsigned short *g_ordinal_remap = NULL;
static int g_ordinal_remap_count = 0;

/* A/B switch for the 30 ordinals that gained a route when DAH2's import table
 * was brought to full coverage. Setting XBOX_KERNEL_LEGACY_UNROUTED=1 makes
 * them fall back to the old behaviour (generic stub: pop the arguments, return
 * 0) in the SAME binary, so a behaviour or frame-time difference can be pinned
 * on the routing rather than on an unrelated rebuild. Unset by default. */
static bridge_func_t bridge_for_ordinal_gated(ULONG ordinal)
{
    static int legacy = -1;

    if (legacy < 0) {
        const char *e = getenv("XBOX_KERNEL_LEGACY_UNROUTED");
        legacy = (e && *e && *e != '0') ? 1 : 0;
        if (legacy) {
            fprintf(stderr, "  [KERNEL] XBOX_KERNEL_LEGACY_UNROUTED set: the 30 "
                    "newly routed ordinals use the old unrouted stub\n");
            fflush(stderr);
        }
    }
    if (legacy) {
        switch (ordinal) {
        case 1: case 2: case 4: case 8: case 17: case 69: case 97: case 100:
        case 119: case 137: case 139: case 142: case 143: case 151: case 153:
        case 175: case 176: case 180: case 217: case 250: case 269: case 304:
        case 305: case 327: case 328: case 335: case 336: case 337: case 340:
        case 360:
            return NULL;
        default:
            break;
        }
    }
    return bridge_for_ordinal(ordinal);
}

void xbox_kernel_set_ordinal_remap(const unsigned short *map, int count)
{
    g_ordinal_remap = map;
    g_ordinal_remap_count = count;
}

void xbox_kernel_bridge_init(void)
{
    int i;
    int resolved = 0;
    int bridged = 0;
    int unbridged = 0;
    DWORD old_protect;

    fprintf(stderr, "  Kernel thunk bridge: resolving %d entries at 0x%08X\n",
            g_thunk_table_count, g_thunk_table_base);

    /* The thunk table lives in .rdata which is marked PAGE_READONLY.
     * Temporarily make it writable so we can patch the ordinals. */
    VirtualProtect(
        (LPVOID)((uintptr_t)g_thunk_table_base + g_xbox_mem_offset),
        g_thunk_table_count * 4,
        PAGE_READWRITE,
        &old_protect
    );

    /* Initialize kernel data export values first */
    kernel_data_init();

    for (i = 0; i < g_thunk_table_count; i++) {
        uint32_t va = g_thunk_table_base + i * 4;
        uint32_t current = BRIDGE_MEM32(va);

        if (current & 0x80000000) {
            /* Read the actual ordinal from Xbox memory, then translate it into
             * the kernel's canonical ordinal space. Identity unless the title
             * set a remap (a different XDK). Every routing decision below --
             * data export, bridge, arg size -- keys off the canonical ordinal,
             * so one translation here covers all three. */
            ULONG ordinal = current & 0x7FFFFFFF;
            if (g_ordinal_remap && ordinal < (ULONG)g_ordinal_remap_count
                && g_ordinal_remap[ordinal]) {
                ordinal = g_ordinal_remap[ordinal];
            }
            g_slot_ordinals[i] = ordinal;

            /* Check if this is a data export */
            uint32_t data_va = kernel_data_va_for_ordinal(ordinal);
            if (data_va) {
                /* DATA export: point thunk to actual data in mapped memory.
                 * This allows the game to dereference the thunk entry. */
                BRIDGE_MEM32(va) = data_va;
                resolved++;
                bridged++;
                continue;
            }

            /* FUNCTION export: use synthetic VA for dispatch */
            g_slot_bridges[i] = bridge_for_ordinal_gated(ordinal);
            g_slot_arg_bytes[i] = stdcall_args_for_ordinal(ordinal);
            if (g_slot_bridges[i]) {
                bridged++;
            } else {
                unbridged++;
                fprintf(stderr, "  [KERNEL] unbridged function thunk: ordinal %lu"
                        " (slot %u, VA 0x%08X)\n",
                        (unsigned long)ordinal, i, KERNEL_VA_BASE + i * 4);
            }

            /* Replace Xbox memory entry with synthetic VA */
            uint32_t synthetic = KERNEL_VA_BASE + i * 4;
            BRIDGE_MEM32(va) = synthetic;
            resolved++;
        }
    }

    /*
     * Thunk entries below the header-declared base.
     *
     * KernelImageThunkAddress points at the main import run, but the linker can
     * emit further runs just before it, separated by a NULL. Halo has three at
     * base-0x10 (ordinals 52, 51 and 5). Those stay unpatched, so game code
     * doing "mov ebx,[thunk]; call ebx" jumps to the raw 0x8000xxxx marker
     * instead of a kernel function. The indirect call cannot resolve it, yields
     * 0, and a caller looping until it sees an error code never sees one - in
     * Halo that hung main() in a file-enumeration loop before it reached any
     * initialisation.
     *
     * Only entries still carrying the ordinal marker are touched, so scanning
     * back over unrelated .rdata is harmless.
     */
    {
        const int LOOKBEHIND = 16;   /* entries, i.e. 64 bytes */
        DWORD scan_protect;
        uint32_t low = g_thunk_table_base - LOOKBEHIND * 4;

        VirtualProtect((LPVOID)((uintptr_t)low + g_xbox_mem_offset),
                       LOOKBEHIND * 4, PAGE_READWRITE, &scan_protect);

        for (i = 1; i <= LOOKBEHIND; i++) {
            uint32_t va = g_thunk_table_base - i * 4;
            uint32_t current = BRIDGE_MEM32(va);
            int slot;

            if (!(current & 0x80000000)) {
                continue;            /* NULL separator or ordinary data */
            }
            slot = g_thunk_table_count + i;   /* park these above the main run */
            if (slot >= XBOX_KERNEL_THUNK_TABLE_SIZE) {
                break;
            }

            g_slot_ordinals[slot] = current & 0x7FFFFFFF;
            g_slot_bridges[slot] = bridge_for_ordinal_gated(g_slot_ordinals[slot]);
            g_slot_arg_bytes[slot] = stdcall_args_for_ordinal(g_slot_ordinals[slot]);
            BRIDGE_MEM32(va) = KERNEL_VA_BASE + slot * 4;
            resolved++;
            if (g_slot_bridges[slot]) bridged++; else unbridged++;

            fprintf(stderr, "  [KERNEL] extra thunk at 0x%08X: ordinal %u (slot %d)\n",
                    va, g_slot_ordinals[slot], slot);
        }

        VirtualProtect((LPVOID)((uintptr_t)low + g_xbox_mem_offset),
                       LOOKBEHIND * 4, scan_protect, &scan_protect);
    }

    /* Restore original protection */
    VirtualProtect(
        (LPVOID)((uintptr_t)g_thunk_table_base + g_xbox_mem_offset),
        g_thunk_table_count * 4,
        old_protect,
        &old_protect
    );

    fprintf(stderr, "  Kernel thunk bridge: %d/%d resolved (%d bridged, %d stub)\n",
            resolved, g_thunk_table_count, bridged, unbridged);
    fprintf(stderr, "  Synthetic VA range: 0x%08X-0x%08X\n",
            KERNEL_VA_BASE, KERNEL_VA_BASE + (resolved - 1) * 4);
    /* stderr is fully buffered (1 MB, see main.c); without this the coverage
     * line above would not reach the log until the buffer fills or the
     * process exits cleanly. */
    fflush(stderr);

}
