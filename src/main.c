/**
 * Destroy All Humans! 2 - Recompiled Game Entry Point
 *
 * This is the Windows executable that hosts the recompiled game code.
 * It performs the following initialization sequence:
 *
 * 1. Load the original XBE file from disk
 * 2. Initialize the Xbox memory layout (map data sections to original VAs)
 * 3. Initialize the Xbox kernel replacement layer
 * 4. Initialize the kernel bridge (thunk table in Xbox memory)
 * 5. Set up game file paths for I/O redirection
 * 6. Initialize the stack pointer
 * 7. Install VEH crash handler for diagnostics
 * 8. Call the game's original entry point (recompiled)
 *
 * Customize this file for your game:
 *   - Set YOUR_GAME_ENTRY_POINT to the XBE entry point address
 *   - Set YOUR_GAME_XBE_PATH to where the XBE file lives
 *   - Set YOUR_GAME_DIR to the game data directory
 *   - Add any CRT global pre-initialization your game needs
 *   - Customize the VEH handler for game-specific crash diagnosis
 *
 * XBE Details (fill in from xbe_parser output):
 *   Title:       YOUR_GAME_NAME
 *   Title ID:    0x00000000
 *   Base addr:   0x00010000
 *   Entry point: 0x00000000
 *   Code size:   ~??? KB (.text)
 *   Sections:    ?? (list them)
 *   Kernel imports: ??
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <intrin.h>
#include <mmsystem.h>
#include "boot_window.h"
#include "trace_control.h"

/* TEMP diagnostic: a process-wide hang was observed after truncated-
 * function fixes got the frame loop presenting a handful of times (see
 * diagnostics/menu_recovery_2026-09-20.md, "genuine hang" section) --
 * output stops completely and stays identical whether the process is
 * killed at 90s or 180s, with no crash logged (ruling out an access
 * violation) and no other exception type either (ruling out an unhandled
 * non-AV exception silently triggering Windows' default dialog). That
 * leaves either a true infinite spin or a blocking wait on some thread.
 * This watchdog periodically snapshots every thread in the process, reads
 * each one's RIP via a suspend/GetThreadContext/resume cycle, and logs
 * whether it moved since the last sample -- a spin shows a RIP that keeps
 * changing rapidly; a deadlock/blocking wait shows one stuck at a single
 * address (very likely inside a Windows synchronization API). Never
 * suspends the calling (watchdog) thread itself. */
static DWORD WINAPI hang_watchdog_thread(LPVOID unused)
{
    (void)unused;
    DWORD self_tid = GetCurrentThreadId();
    DWORD64 last_rip[256] = {0};
    DWORD last_tid[256] = {0};
    int known_count = 0;

    extern ptrdiff_t g_xbox_mem_offset;  /* forward decl: this function is defined before main.c's own extern */
    for (;;) {
        Sleep(1000);
        /* TEMP: directly inspect the guest object at VA 0x31D990 -- suspected
         * culprit vtable dispatch right after the two known EVENT-BUFFER
         * manager checks that immediately precede the stall. See
         * "sub_00115520 dispatches vtable+0xC on MEM32(0x31D990)" note in
         * diagnostics/menu_recovery_2026-09-20.md. */
        if (g_xbox_mem_offset) {
            uint32_t obj = *(volatile uint32_t *)((uintptr_t)g_xbox_mem_offset + 0x31D990u);
            if (obj) {
                uint32_t vtbl = *(volatile uint32_t *)((uintptr_t)g_xbox_mem_offset + obj);
                uint32_t target = *(volatile uint32_t *)((uintptr_t)g_xbox_mem_offset + vtbl + 0xC);
                fprintf(stderr, "[WATCH-31D990] obj=0x%08X vtbl=0x%08X vtbl+0xC target=0x%08X\n",
                        obj, vtbl, target);
            } else {
                fprintf(stderr, "[WATCH-31D990] obj=0 (not yet constructed)\n");
            }
        }
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te; te.dwSize = sizeof(te);
        DWORD pid = GetCurrentProcessId();
        int total_this_sample = 0;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                if (te.th32ThreadID == self_tid) continue;
                total_this_sample++;
                HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!th) continue;
                int idx = -1;
                for (int i = 0; i < known_count; i++) if (last_tid[i] == te.th32ThreadID) { idx = i; break; }
                int is_new = (idx < 0);
                if (idx < 0 && known_count < 256) { idx = known_count++; last_tid[idx] = te.th32ThreadID; last_rip[idx] = 0; }

                if (is_new) {
                    /* TEMP: only for newly-discovered threads (avoids
                     * reprinting for all 190+ every second) -- get the
                     * actual start address (works even while blocked deep in
                     * ntdll), which directly names the function that created
                     * it, unlike current RIP once it's gone idle.
                     * NtQueryInformationThread isn't declared in the SDK
                     * headers; resolve it dynamically. See "thread
                     * explosion" note in
                     * diagnostics/menu_recovery_2026-09-20.md. */
                    typedef LONG (NTAPI *NtQueryInformationThread_t)(
                        HANDLE, ULONG, PVOID, ULONG, PULONG);
                    static NtQueryInformationThread_t s_NtQIT = NULL;
                    static int s_NtQIT_resolved = 0;
                    if (!s_NtQIT_resolved) {
                        s_NtQIT_resolved = 1;
                        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                        if (ntdll) s_NtQIT = (NtQueryInformationThread_t)
                            GetProcAddress(ntdll, "NtQueryInformationThread");
                    }
                    if (s_NtQIT) {
                        PVOID start_addr = NULL;
                        /* ThreadQuerySetWin32StartAddress = 9 */
                        if (s_NtQIT(th, 9, &start_addr, sizeof(start_addr), NULL) == 0 && start_addr) {
                            HMODULE hmod = NULL; char modname[MAX_PATH] = "?";
                            if (GetModuleHandleExA(
                                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    (LPCSTR)start_addr, &hmod) && hmod) {
                                GetModuleFileNameA(hmod, modname, MAX_PATH);
                                const char *base = strrchr(modname, '\\');
                                base = base ? base + 1 : modname;
                                fprintf(stderr, "  NEW tid=%lu START=%p (%s +0x%llX)\n",
                                        (unsigned long)te.th32ThreadID, start_addr, base,
                                        (unsigned long long)((uintptr_t)start_addr - (uintptr_t)hmod));
                            } else {
                                fprintf(stderr, "  NEW tid=%lu START=%p (unknown module)\n",
                                        (unsigned long)te.th32ThreadID, start_addr);
                            }
                        }
                    }
                }

                if (SuspendThread(th) != (DWORD)-1) {
                    CONTEXT ctx; ctx.ContextFlags = CONTEXT_ALL;
                    DWORD64 rip = 0, rsp = 0;
                    if (GetThreadContext(th, &ctx)) { rip = ctx.Rip; rsp = ctx.Rsp; }
                    /* TEMP: only print for the (usually one) ACTIVELY
                     * executing thread -- RIP changed since last sample --
                     * to re-identify the hot function after a rebuild shifts
                     * addresses, without reprinting all ~80+ idle/blocked
                     * threads every second. Also does a crude raw-stack scan
                     * (not proper unwind info) for module-range return
                     * addresses, since single-RIP-sample-to-symbol mapping
                     * has repeatedly proven unreliable for this codebase --
                     * see "the thread explosion" investigation notes in
                     * diagnostics/menu_recovery_2026-09-20.md. */
                    if (idx >= 0 && last_rip[idx] != 0 && last_rip[idx] != rip) {
                        uintptr_t mod_base = (uintptr_t)GetModuleHandleA(NULL);
                        if (rip >= mod_base && rip < mod_base + 0x10000000ULL)
                            fprintf(stderr, "  ACTIVE tid=%lu RIP=0x%llX (module RVA=0x%llX) RSP=0x%llX\n",
                                    (unsigned long)te.th32ThreadID, (unsigned long long)rip,
                                    (unsigned long long)(rip - mod_base), (unsigned long long)rsp);
                        else
                            fprintf(stderr, "  ACTIVE tid=%lu RIP=0x%llX (outside module) RSP=0x%llX\n",
                                    (unsigned long)te.th32ThreadID, (unsigned long long)rip, (unsigned long long)rsp);
                        if (rsp) {
                            DWORD64 *stack = (DWORD64 *)(uintptr_t)rsp;
                            fprintf(stderr, "    raw-stack-scan (module-range values, first 40 slots):");
                            __try {
                                for (int s = 0; s < 40; s++) {
                                    DWORD64 v = stack[s];
                                    if (v >= mod_base && v < mod_base + 0x10000000ULL)
                                        fprintf(stderr, " [%d]=0x%llX(RVA0x%llX)", s, (unsigned long long)v,
                                                (unsigned long long)(v - mod_base));
                                }
                            } __except (EXCEPTION_EXECUTE_HANDLER) {
                                fprintf(stderr, " <stack read faulted>");
                            }
                            fprintf(stderr, "\n");
                        }
                    }
                    ResumeThread(th);
                    if (idx >= 0) last_rip[idx] = rip;
                }
                CloseHandle(th);
            } while (Thread32Next(snap, &te));
        }
        fprintf(stderr, "[WATCHDOG] thread count=%d\n", total_this_sample);
        CloseHandle(snap);
        fflush(stderr);
    }
    return 0;
}

/* xboxrecomp runtime headers */
#include <xbox/xboxrecomp.h>

/*
 * If xboxrecomp.h is not an umbrella header in your setup, include
 * the individual headers directly:
 *
 * #include "kernel.h"
 * #include "xbox_memory_layout.h"
 * #include "d3d8_xbox.h"
 * #include "dsound_xbox.h"
 * #include "xinput_xbox.h"
 */

/* ── Global register state (defined in xbox_memory_layout.c) ── */

/* RECOMP_TLS is not optional here. The runtime defines these thread-local, and
 * a plain `extern` referencing a __declspec(thread) variable does not resolve
 * to the calling thread's copy -- it resolves to the image's TLS template. The
 * host side then writes g_esp somewhere the generated code never reads, so the
 * guest starts with every register at zero and faults immediately, having
 * apparently ignored the setup that visibly ran. */
extern RECOMP_TLS uint32_t g_eax, g_ecx, g_edx, g_esp;
extern RECOMP_TLS uint32_t g_ebx, g_esi, g_edi;
extern RECOMP_TLS uint32_t g_seh_ebp;
/* x87 and SSE state. Global for the same reason the volatile GPRs are: one
 * guest routine can lift to several C functions, so a value written in one
 * body is read in the next. Defined in xbox_memory_layout.c like the rest of
 * the register file. */
extern RECOMP_TLS double g_fp_stack[8];
extern RECOMP_TLS int g_fp_top;
extern RECOMP_TLS uint16_t g_fp_control_word;
extern RECOMP_TLS int g_fp_cmp;
extern RECOMP_TLS RecompXmm g_xmm0, g_xmm1, g_xmm2, g_xmm3;
extern RECOMP_TLS RecompXmm g_xmm4, g_xmm5, g_xmm6, g_xmm7;
extern ptrdiff_t g_xbox_mem_offset;

/* Some runtime libraries invoke guest callbacks from host-created threads.
 * Their RECOMP_TLS register file begins zeroed, so lazily give such a thread a
 * simulated Xbox stack before its first guest push. */
static RECOMP_TLS uint32_t g_callback_stack_top;
static RECOMP_TLS unsigned g_callback_stack_resets;

uint32_t recomp_ensure_thread_stack(void)
{
    uint32_t top = g_callback_stack_top;
    if (!top) {
        top = xbox_AllocThreadStack();
        g_callback_stack_top = top;
    }
    if (!top) {
        fprintf(stderr, "[THREAD] no simulated stack available for callback\n");
        abort();
    }
    g_esp = top;
    g_seh_ebp = top;
    if (g_callback_stack_resets++ < 16) {
        uintptr_t caller = (uintptr_t)_ReturnAddress();
        uintptr_t base = (uintptr_t)GetModuleHandleW(NULL);
        fprintf(stderr, "[THREAD] callback stack reset %u at %08X, caller RVA=%llX\n",
                g_callback_stack_resets, top,
                (unsigned long long)(caller - base));
    }
    return top;
}

/* ── XBE Constants ─────────────────────────────────────────── */

/*
 * TODO: Set these from your xbe_parser output.
 * Run: py -3 -m tools.xbe_parser game/default.xbe
 */
#define YOUR_GAME_ENTRY_POINT   0x000FAF3B  /* XBE entry point VA */
#define YOUR_GAME_XBE_PATH      "game_files\\default.xbe"
#define YOUR_GAME_DIR            "Destroy All Humans! 2 (USA, Europe) (En,Fr,De,Es,It).xiso"

/* ── Forward declarations ──────────────────────────────────── */

static BOOL load_xbe(const char *path, void **out_data, size_t *out_size);

/* Recompiled entry point (generated by recomp pipeline) */
extern void xbe_entry_point(void);

/* ── VEH crash handler ─────────────────────────────────────── */

/*
 * Vectored Exception Handler for crash diagnostics.
 *
 * When the recompiled game hits an access violation, this handler prints
 * the faulting address, all Xbox register values, and a native stack trace.
 * This is your primary debugging tool during bring-up.
 *
 * Customize this for your game:
 *   - Add game-specific address checks (GPU register probes, etc.)
 *   - Add dumps of game-specific globals (heap handles, state flags)
 *   - Add SEH simulation if your game uses __try/__except
 */
static LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ep)
{
    /* TEMP diagnostic: this handler used to only recognize
     * EXCEPTION_ACCESS_VIOLATION. Any other exception (float/int divide by
     * zero, illegal instruction, etc.) fell through silently and returned
     * EXCEPTION_CONTINUE_SEARCH with nothing logged -- for this GUI
     * (WinMain) process that means Windows' default unhandled-exception
     * path takes over, which blocks indefinitely (a modal dialog with no
     * visible window to interact with, since nothing pumps messages for
     * it here), looking exactly like a silent hang from the outside. Log
     * every exception code first so a future one is never invisible again,
     * then fall through to the existing access-violation-specific handling. */
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        fprintf(stderr, "[EXCEPTION] code=0x%08X RIP=0x%llX flags=0x%08X\n",
            (unsigned)ep->ExceptionRecord->ExceptionCode,
            (unsigned long long)ep->ContextRecord->Rip,
            (unsigned)ep->ExceptionRecord->ExceptionFlags);
        fprintf(stderr, "  Xbox regs: eax=0x%08X ecx=0x%08X edx=0x%08X esp=0x%08X\n",
            g_eax, g_ecx, g_edx, g_esp);
        fprintf(stderr, "  Xbox regs: ebx=0x%08X esi=0x%08X edi=0x%08X\n",
            g_ebx, g_esi, g_edi);
        fflush(stderr);
    }
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        uintptr_t fault_addr = ep->ExceptionRecord->ExceptionInformation[1];

        /*
         * GPU register probe at 0xFD000000 range.
         * Some games probe NV2A registers directly. On real hardware this
         * returns GPU state; here we just skip the instruction.
         * TODO: Implement mini x86-64 decoder for instruction skipping,
         * or connect to the xbox_nv2a library for proper handling.
         */
        if (fault_addr >= 0xFD000000 && fault_addr < 0xFE000000) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        fprintf(stderr, "[CRASH] Access violation at RIP=0x%llX, fault addr=0x%llX (%s)\n",
            (unsigned long long)ep->ContextRecord->Rip,
            (unsigned long long)fault_addr,
            ep->ExceptionRecord->ExceptionInformation[0] ? "write" : "read");
        fprintf(stderr, "  Module base: 0x%llX, RIP RVA: 0x%llX\n",
            (unsigned long long)(uintptr_t)GetModuleHandleA(NULL),
            (unsigned long long)(ep->ContextRecord->Rip - (uintptr_t)GetModuleHandleA(NULL)));
        fprintf(stderr, "  Xbox regs: eax=0x%08X ecx=0x%08X edx=0x%08X esp=0x%08X\n",
            g_eax, g_ecx, g_edx, g_esp);
        fprintf(stderr, "  Xbox regs: ebx=0x%08X esi=0x%08X edi=0x%08X\n",
            g_ebx, g_esi, g_edi);
        fprintf(stderr, "  Xbox VA of fault: 0x%08X\n",
            (uint32_t)(fault_addr - (uintptr_t)g_xbox_mem_offset));

        /*
         * TODO: Add game-specific diagnostics here. Examples:
         *
         * Dump CRT heap handle:
         *   uint32_t heap = *(uint32_t *)((uint8_t *)g_xbox_mem_offset + HEAP_HANDLE_VA);
         *   fprintf(stderr, "  CRT heap handle: 0x%08X\n", heap);
         *
         * Dump game state:
         *   uint32_t state = *(uint32_t *)((uint8_t *)g_xbox_mem_offset + GAME_STATE_VA);
         *   fprintf(stderr, "  Game state: %u\n", state);
         */

        /* Print native stack return addresses for debugging */
        {
            void *frames[48];
            USHORT frame_count = CaptureStackBackTrace(0, 48, frames, NULL);
            uintptr_t image_base = (uintptr_t)GetModuleHandleA(NULL);
            for (USHORT frame = 0; frame < frame_count; ++frame) {
                uintptr_t address = (uintptr_t)frames[frame];
                if (address >= image_base && address < image_base + 0x10000000ULL)
                    fprintf(stderr, "  [NATIVE-FRAME] %u RVA=%llX\n", frame,
                            (unsigned long long)(address - image_base));
            }
            uintptr_t *sp = (uintptr_t *)ep->ContextRecord->Rsp;
            fprintf(stderr, "  Native stack (first 8 return addrs):\n");
            for (int i = 0; i < 64 && sp[i]; i++) {
                uintptr_t module_base = (uintptr_t)GetModuleHandleA(NULL);
                if (sp[i] >= module_base && sp[i] < module_base + 0x10000000ULL) {
                    fprintf(stderr, "    [%d] 0x%llX (RVA 0x%llX)\n", i,
                        (unsigned long long)sp[i], (unsigned long long)(sp[i] - module_base));
                }
            }
        }
        fflush(stderr);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ── WinMain ───────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    void *xbe_data = NULL;
    size_t xbe_size = 0;
    MMRESULT timer_period_result = TIMERR_NOCANDO;

    (void)hInstance;
    (void)hPrevInstance;
    (void)nCmdShow;

    /* Stdout: unbuffered so printf output is immediately visible.
     * Stderr: large block-buffered so the thousands of [LUA-INTERN] /
     * [CALL-ABI] / [RESOURCE-ALLOC] trace lines during loading don't
     * stall on per-call I/O.  The VEH crash handler calls fflush(stderr)
     * so crash diagnostics are never lost. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IOFBF, 1 << 20);  /* 1 MB fully-buffered */
    dah2_trace_initialize();
    /* Generated and manual bring-up diagnostics are verbose-only. Keeping
     * their formatting off the playable path prevents Bink decode from
     * falling behind its retail clock and skipping movie presentation. */
    if (!g_dah2_verbose_trace) {
        FILE *quiet_stderr = NULL;
        freopen_s(&quiet_stderr, "NUL", "w", stderr);
    }

    printf("=== Destroy All Humans! 2 - Static Recompilation ===\n");
    dah2_boot_window_start(hInstance);
    /* Normal launch stays on the 60 Hz menu until Enter.  --autoplay is a
       deterministic bring-up path used by the cadence probe: it runs the
       menu for five seconds, a complete 30 Hz cutscene, then 30 Hz Crypto
       gameplay until the window is closed. */
    dah2_boot_window_set_shell_autoplay(lpCmdLine && strstr(lpCmdLine, "--autoplay") != NULL);
    dah2_boot_window_set_real_menu_probe(TRUE);
    fprintf(stderr, "[REAL-MENU] translated lifecycle owns the window\n");
    dah2_boot_window_set_status("Loading original Xbox executable...");
    printf("Loading XBE...\n");

    /* Install VEH handler (first handler in chain) */
    AddVectoredExceptionHandler(1, veh_handler);

    /* Step 1: Load XBE */
    if (!load_xbe(YOUR_GAME_XBE_PATH, &xbe_data, &xbe_size)) {
        MessageBoxA(NULL, "Failed to load default.xbe.\n"
                    "Place the game files in the 'game' subdirectory.",
                    "Recomp", MB_ICONERROR);
        return 1;
    }
    printf("XBE loaded: %zu bytes\n", xbe_size);

    /* Step 2: Initialize Xbox memory layout */
    printf("Initializing Xbox memory layout...\n");
    if (!xbox_MemoryLayoutInit(xbe_data, xbe_size)) {
        MessageBoxA(NULL, "Failed to initialize Xbox memory layout.\n"
                    "The required virtual address range may be unavailable.",
                    "Recomp", MB_ICONERROR);
        free(xbe_data);
        return 1;
    }

    g_xbox_mem_offset = xbox_GetMemoryOffset();
    printf("Xbox memory mapped. Offset: 0x%llX\n", (unsigned long long)g_xbox_mem_offset);
    dah2_boot_window_set_status("Xbox memory mapped; initializing kernel bridge...");

    /* Step 3: Initialize Xbox kernel */
    printf("Initializing Xbox kernel replacement...\n");
    xbox_kernel_init();

    /* Step 4: Set game directory for file I/O path translation */
    {
        extern void xbox_path_init(const char *game_dir, const char *save_dir);
        xbox_path_init(YOUR_GAME_DIR, "game_saves");
    }

    /* Step 5: Initialize kernel bridge (thunk table in Xbox memory) */
    printf("Initializing kernel bridge...\n");
    xbox_kernel_bridge_init();

    /* Step 6: Initialize stack */
    g_esp = XBOX_STACK_TOP;

    /*
     * TODO: Pre-initialize CRT globals if needed.
     *
     * Many Xbox games use the MSVC CRT. The CRT's __heap_init sets up a
     * heap descriptor at a game-specific address. You may need to
     * pre-initialize __active_heap to avoid small-block heap issues:
     *
     *   uint32_t *active_heap = (uint32_t *)((uint8_t *)g_xbox_mem_offset + ACTIVE_HEAP_VA);
     *   *active_heap = 1;  // 1 = system heap (HeapAlloc), avoids SBH init
     *
     * Find ACTIVE_HEAP_VA by searching the disassembly for __heap_init
     * or by looking for the CRT's __active_heap global in the data section.
     */

    printf("\n=== Initialization complete ===\n");
    printf("Entry point: 0x%08X\n", YOUR_GAME_ENTRY_POINT);
    printf("ESP: 0x%08X\n", g_esp);

    /* Step 7: Call the recompiled entry point */
    printf("\nStarting game...\n");
    dah2_boot_window_set_status("Recompiled main loop active; connecting renderer...");
    fflush(stdout);

    /* The translated first thread owns its own register file (SPAWN mode)
       so the Xbox bootstrap and renderer run on proper isolated stacks. */
    xbox_SetThreadMode(XBOX_THREAD_MODE_SPAWN);
    fprintf(stderr, "[REAL-MENU] Xbox thread mode=SPAWN\n");
    fflush(stderr);

    /* The sampler suspends threads to inspect native contexts, so it must be
       opt-in: suspending a thread that owns the CRT stderr lock can otherwise
       deadlock a normal game run when the sampler tries to print its result. */
    if (getenv("DAH2_HANG_WATCHDOG") != NULL) {
        CreateThread(NULL, 0, hang_watchdog_thread, NULL, 0, NULL);
    }

    timer_period_result = timeBeginPeriod(1);
    xbe_entry_point();

    /* xbe_entry_point only schedules the Xbox bootstrap thread; keep the
       host process alive until the user closes the window. */
    fprintf(stderr, "[REAL-MENU] host wait: running until window close\n");
    fflush(stderr);
    while (dah2_boot_window_get_hwnd() &&
           IsWindow(dah2_boot_window_get_hwnd())) {
        Sleep(100);
    }
    fprintf(stderr, "[REAL-MENU] window closed\n");
    fflush(stderr);

    printf("\nGame returned. Cleaning up...\n");

    /* Cleanup */
    xbox_kernel_shutdown();
    xbox_MemoryLayoutShutdown();
    free(xbe_data);
    dah2_boot_window_stop();
    if (timer_period_result == TIMERR_NOERROR)
        timeEndPeriod(1);

    return 0;
}

/* ── XBE Loading ───────────────────────────────────────────── */

static BOOL load_xbe(const char *path, void **out_data, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open XBE: %s\n", path);
        return FALSE;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fclose(f);
        return FALSE;
    }

    void *data = malloc((size_t)size);
    if (!data) {
        fclose(f);
        return FALSE;
    }

    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return FALSE;
    }

    fclose(f);
    *out_data = data;
    *out_size = (size_t)size;
    return TRUE;
}

/* Console entry point (for debugging -- lets you see printf output) */
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOW);
}
