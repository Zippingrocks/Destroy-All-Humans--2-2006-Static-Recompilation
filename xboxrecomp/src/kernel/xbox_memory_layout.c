/**
 * Xbox Memory Layout Implementation
 *
 * Maps the XBE data sections to their expected virtual addresses on Windows.
 * This is critical for the recompiled code which references globals by
 * absolute address (e.g., mov eax, [0x004D532C]).
 *
 * Implementation:
 * 1. VirtualAlloc a contiguous region at XBOX_BASE_ADDRESS
 * 2. Copy .rdata and initialized .data from the XBE
 * 3. Zero-fill the BSS region
 * 4. Set memory protection (read-only for .rdata)
 */

#include "xbox_memory_layout.h"
#include "kernel.h"
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

/* XBE header field offsets (per xboxdevwiki.net/Xbe) */
#define XBE_MAGIC_OFFSET        0x0000
#define XBE_BASE_ADDR_OFFSET    0x0104
#define XBE_HEADER_SIZE_OFFSET  0x0108
#define XBE_SECTION_COUNT_OFFSET 0x011C
#define XBE_SECTION_HEADERS_OFFSET 0x0120

/* XBE section header layout (56 bytes each) */
#define SECTHDR_FLAGS       0x00
#define SECTHDR_VA          0x04
#define SECTHDR_VSIZE       0x08
#define SECTHDR_RAW_OFFSET  0x0C
#define SECTHDR_RAW_SIZE    0x10
#define SECTHDR_NAME_ADDR   0x14
#define SECTHDR_SIZE        56

static void *g_memory_base = NULL;
static size_t g_memory_size = 0;
static ptrdiff_t g_memory_offset = 0;  /* actual_base - XBOX_BASE_ADDRESS */

/* Actual mapped RAM for this run; see the header. Default retail 64 MB. */
size_t g_xbox_total_ram = XBOX_TOTAL_RAM;

void xbox_SetTotalRam(size_t bytes)
{
    g_xbox_total_ram = bytes;
}

/* File mapping handle for the Xbox memory region.
 * Using CreateFileMapping + MapViewOfFileEx allows mirror views to alias
 * the same physical pages as the base region, so writes to mirror addresses
 * (which wrap modulo 64 MB on real Xbox hardware) correctly modify the
 * underlying data. */
static HANDLE g_mapping_handle = NULL;

/* Mirror view pointers for cleanup */
static void *g_mirror_views[XBOX_NUM_MIRRORS] = {0};
/* Contiguous / physical memory window (see MemoryLayoutInit).
 * XBOX_CONTIG_BASE / XBOX_CONTIG_SIZE come from kernel.h - the bridges need
 * the same numbers for MmClaimGpuInstanceMemory. */
static void *g_contig_memory = NULL;
static HANDLE g_contig_mapping_handle = NULL;
#define XBOX_CONTIG_APERTURE_SIZE 0x40000000u
#define XBOX_CONTIG_WRAP_VIEW_COUNT \
    ((XBOX_CONTIG_APERTURE_SIZE / XBOX_CONTIG_SIZE) - 1u)
static void *g_contig_wrap_views[XBOX_CONTIG_WRAP_VIEW_COUNT] = {0};

/* NV2A GPU register aperture (see MemoryLayoutInit). Backed as plain RAM so
 * that D3D8 code linked into the title can poke it without faulting. */
#define XBOX_NV2A_BASE 0xFD000000u
#define XBOX_NV2A_SIZE (16u * 1024u * 1024u)
static void *g_nv2a_memory = NULL;

/* MCPX southbridge register span: APU 0xFE800000 through NIC 0xFEF00000. */
#define XBOX_MCPX_BASE 0xFE800000u
#define XBOX_MCPX_SIZE (8u * 1024u * 1024u)
static void *g_mcpx_memory = NULL;
static HANDLE g_nv2a_ack_thread = NULL;
static volatile LONG g_nv2a_ack_stop = 0;

/*
 * NV2A busy-bit acknowledgement.
 *
 * D3D8 talks to the GPU through set-a-bit / wait-for-hardware-to-clear-it
 * handshakes. Against plain RAM the bit is set and nothing ever clears it, so
 * the title spins forever. Halo hangs in the push-buffer kick at 0x001EF930:
 *
 *     mov  [eax+0x100410], edx     ; set 0x10000
 *   L: test [eax+0x100410], 0x10000
 *     jne  L                       ; wait for the GPU
 *
 * Clearing those bits from a thread is not a hack around the handshake, it is
 * the handshake: on hardware the GPU clears them asynchronously, which is
 * exactly what this does. Work that would have been submitted is being done by
 * the D3D11 layer instead, so acknowledging immediately is honest.
 *
 * Only registers listed here are touched. Blanket-zeroing the aperture would
 * also wipe registers holding real state.
 *
 * ponytail: table-driven, extend as more handshakes turn up. A spin on a bit
 * that is not listed still hangs -- run the title and the watchdog sample will
 * name the register.
 */
static const struct { uint32_t offset; uint32_t busy_mask; } NV2A_ACK[] = {
    { 0x100410, 0x00010000u },  /* PFB flush kick, Halo 0x001EF930 */

    /* Interrupt status registers. These are write-1-to-clear on hardware, so
     * an ISR "clearing" one writes the pending bit back -- against plain RAM
     * that sets it instead, the interrupt stays pending forever, and the
     * service routine re-enters until the stack is gone. Halo dies exactly
     * that way: CMiniport::ServiceGrInterrupt writes 0x1000 to PGRAPH_INTR to
     * acknowledge, reads it back still pending, and recurses into a native
     * stack overflow.
     *
     * Holding them at zero is correct rather than convenient: nothing here
     * ever raises a GPU interrupt, so "none pending" is the truth. */
    { 0x000100, 0xFFFFFFFFu },  /* PMC_INTR_0    */
    { 0x001100, 0xFFFFFFFFu },  /* PBUS_INTR_0   */
    { 0x002100, 0xFFFFFFFFu },  /* PFIFO_INTR_0  */
    { 0x400100, 0xFFFFFFFFu },  /* PGRAPH_INTR   */
    { 0x600100, 0xFFFFFFFFu },  /* PCRTC_INTR_0  */
};

/*
 * Bits that must always read as SET. The mirror image of the table above:
 * where an interrupt-pending bit is false because nothing raises interrupts,
 * a queue-empty bit is true because nothing is queued.
 *
 * Halo's CMiniport::TilingUpdateIdle spins until the PFIFO caches report
 * empty (0x001F5CD1). Zeroed RAM says "not empty" forever, so tile setup
 * during CDevice::InitializeFrameBuffers never completes.
 *
 * Note 0x003220 is deliberately absent -- that one exits on the bit being
 * CLEAR, which zeroed memory already gives.
 */
static const struct { uint32_t offset; uint32_t idle_mask; } NV2A_IDLE[] = {
    { 0x002400, 0x00000010u },  /* PFIFO_RUNOUT_STATUS  LOW_MARK (empty) */
    { 0x003214, 0x00000010u },  /* PFIFO_CACHE1_STATUS  LOW_MARK (empty) */
};

/*
 * PFIFO channel DMA pointers. Software writes DMA_PUT and spins until the GPU
 * advances DMA_GET to match -- "you have consumed everything I submitted".
 * Halo's wait is at 0x001F3948:
 *
 *   L: call BusyLoop
 *      ecx = [[dev+0x2304] + 0x44]   ; DMA_GET
 *      edx = [dev]                   ; DMA_PUT
 *      test (edx ^ ecx), 0xfffffff
 *      jne L
 *
 * [dev+0x2304] is 0xFD800000, so the channel's USER area sits at aperture
 * offset 0x800000 and the two pointers are at +0x40 / +0x44. Copying PUT to
 * GET is the acknowledgement; the commands are not executed from the push
 * buffer here -- the D3D11 layer draws -- so reporting them consumed is the
 * truthful answer.
 *
 * This was written once, removed, and restored. It was removed because
 * [dev+0x2304] read as 0x0080F7FF, i.e. no register to acknowledge -- but that
 * garbage was a downstream symptom of ordinal 47 having no stdcall arg size,
 * which walked esp 8 bytes off and made D3D initialise the DMA channel with
 * `this` = 1. With that fixed the pointer is correct and so is this.
 */
#define NV2A_USER_DMA_PUT 0x800040u
#define NV2A_USER_DMA_GET 0x800044u

/*
 * Free-running counters in the MCPX aperture.
 *
 * Some hardware registers are clocks, not flags: software reads them and waits
 * until the value passes a target. Against zeroed RAM the value never moves and
 * the wait is forever. DirectSound's CMcpxCore::SetupVoiceProcessor spins on
 * the APU sample counter at 0xFE820010 exactly this way, which is where Halo
 * stopped once input initialisation started working.
 *
 * Ticking it is the honest model: on hardware this counter advances on its own
 * whether or not anything is listening.
 *
 * ponytail: the rate is "as fast as this thread loops", not 48 kHz. Nothing
 * paces audio off it yet. Derive it from a real clock if timing starts to
 * matter.
 */
static const uint32_t MCPX_COUNTERS[] = {
    0x020010,   /* APU GP sample counter, DirectSound SetupVoiceProcessor */
};

/*
 * Words a healthy MCPX DSP holds at a fixed value.
 *
 * The retail DirectSound library (DAH2: the routine at 0x266AFx calling
 * 0x266841) reads the word at 0xFE85A018 -- through a pointer it keeps at
 * [0x2802A0] -- and treats anything other than 0x00CCCCCC as "the DSP has
 * stopped": it rewrites the APU front-end registers and then waits 10 ms for
 * the hardware to settle (KeStallExecutionProcessor(10000)). With no DSP
 * behind this aperture the word read 0, so the library "recovered" the APU on
 * EVERY frame, spending 10 ms of each 33.3 ms budget busy-waiting.
 *
 * 0x00CCCCCC is what xemu's emulated DSP presents at that address (read live
 * over its GDB stub, steady across samples, beside a ticking DSP frame
 * counter). The title only reads this word; nothing needs it to change.
 * The thread re-asserts it so it also survives guest code that clears DSP
 * memory during setup.
 */
static const struct { uint32_t offset; uint32_t value; } MCPX_DSP_WORDS[] = {
    { 0x05A018u, 0x00CCCCCCu },   /* 0xFE85A018, EP DSP idle marker */
};

static void *g_mcpx_regs = NULL;

static DWORD WINAPI nv2a_ack_thread(LPVOID param)
{
    volatile uint32_t *regs = (volatile uint32_t *)param;
    while (!InterlockedCompareExchange(&g_nv2a_ack_stop, 0, 0)) {
        for (size_t i = 0; i < sizeof(NV2A_ACK) / sizeof(NV2A_ACK[0]); i++) {
            volatile uint32_t *r =
                (volatile uint32_t *)((char *)regs + NV2A_ACK[i].offset);
            if (*r & NV2A_ACK[i].busy_mask) {
                *r &= ~NV2A_ACK[i].busy_mask;
            }
        }
        for (size_t i = 0; i < sizeof(NV2A_IDLE) / sizeof(NV2A_IDLE[0]); i++) {
            volatile uint32_t *r =
                (volatile uint32_t *)((char *)regs + NV2A_IDLE[i].offset);
            if ((*r & NV2A_IDLE[i].idle_mask) != NV2A_IDLE[i].idle_mask) {
                *r |= NV2A_IDLE[i].idle_mask;
            }
        }
        {
            volatile uint32_t *put =
                (volatile uint32_t *)((char *)regs + NV2A_USER_DMA_PUT);
            volatile uint32_t *get =
                (volatile uint32_t *)((char *)regs + NV2A_USER_DMA_GET);
            if (*get != *put) {
                *get = *put;
            }
        }
        if (g_mcpx_regs) {
            for (size_t i = 0; i < sizeof(MCPX_DSP_WORDS) / sizeof(MCPX_DSP_WORDS[0]); i++) {
                volatile uint32_t *w =
                    (volatile uint32_t *)((char *)g_mcpx_regs + MCPX_DSP_WORDS[i].offset);
                if (*w != MCPX_DSP_WORDS[i].value) {
                    *w = MCPX_DSP_WORDS[i].value;
                }
            }
            for (size_t i = 0; i < sizeof(MCPX_COUNTERS) / sizeof(MCPX_COUNTERS[0]); i++) {
                volatile uint32_t *c =
                    (volatile uint32_t *)((char *)g_mcpx_regs + MCPX_COUNTERS[i]);
                *c += 1;
            }
        }

        /* Advance KeTickCount. It was written once at init and left frozen,
         * which silently breaks every timeout that polls it: Halo's DHCP setup
         * waits on a tick deadline that never arrives and spins forever bringing
         * up XNet. A live clock is also just the truth -- KeTickCount ticks on
         * hardware whether or not anyone is asleep. GetTickCount() shares the
         * millisecond unit, so the rate matches. */
        *(volatile uint32_t *)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_TICK_COUNT)
                               + g_memory_offset) = GetTickCount();

        /* Polling every millisecond is still much faster than a title frame
         * while avoiding a permanently runnable worker that consumes an
         * entire host core. */
        Sleep(1);
    }
    return 0;
}

static void xbox_Nv2aAckStart(void)
{
    g_nv2a_ack_stop = 0;
    g_nv2a_ack_thread = CreateThread(NULL, 0, nv2a_ack_thread,
                                     g_nv2a_memory, 0, NULL);
    if (g_nv2a_ack_thread) {
        fprintf(stderr, "  NV2A busy-bit ack: %zu register(s) acknowledged\n",
                sizeof(NV2A_ACK) / sizeof(NV2A_ACK[0]));
    }
}

/* Separate allocation for Xbox kernel address space (0x80010000+).
 * Some RenderWare code reads the kernel PE header to detect features. */
static void *g_kernel_memory = NULL;

/* Global offset accessible by recompiled code (via recomp_types.h) */
ptrdiff_t g_xbox_mem_offset = 0;

/* Global registers for recompiled code (via recomp_types.h) */
RECOMP_TLS uint32_t g_eax = 0, g_ecx = 0, g_edx = 0, g_esp = 0;
RECOMP_TLS uint32_t g_ebx = 0, g_esi = 0, g_edi = 0;

/* SEH frame pointer bridge (see recomp_types.h for explanation) */
RECOMP_TLS uint32_t g_seh_ebp = 0;
/* Per-thread FS:[0] exception-list head.  -1 is the architectural
 * end-of-chain sentinel used by the Xbox/MSVC runtime. */
RECOMP_TLS uint32_t g_seh_head = 0xFFFFFFFFu;
RECOMP_TLS jmp_buf *g_recomp_unwind_jmp = NULL;
RECOMP_TLS uint32_t g_recomp_unwind_target = 0;
RECOMP_TLS double g_fp_stack[8];
RECOMP_TLS int g_fp_top = 0;
/* x87 control and status. The reset default masks every exception and
 * rounds to nearest, which is what the CRT expects before _control87. */
RECOMP_TLS uint16_t g_fp_control_word = 0x037Fu;
RECOMP_TLS int g_fp_cmp = 0;

/* SSE. 128 bits of architectural state, per-thread like the rest. */
RECOMP_TLS RecompXmm g_xmm0, g_xmm1, g_xmm2, g_xmm3;
RECOMP_TLS RecompXmm g_xmm4, g_xmm5, g_xmm6, g_xmm7;
/* Last frame established by `mov ebp, esp`. Read by frameless functions
 * that address their caller's frame through ebp. */
RECOMP_TLS uint32_t g_ebp = 0;

/* ICALL trace ring buffer */
volatile uint32_t g_icall_trace[16] = {0};
volatile uint32_t g_icall_trace_idx = 0;
volatile uint64_t g_icall_count = 0;

BOOL xbox_MemoryLayoutInit(const void *xbe_data, size_t xbe_size)
{
    DWORD old_protect;
    const uint8_t *xbe = (const uint8_t *)xbe_data;

    if (g_memory_base) {
        fprintf(stderr, "xbox_MemoryLayoutInit: already initialized\n");
        return FALSE;
    }

    /*
     * Calculate the full range we need to map.
     * From XBOX_MAP_START (0x0) to the end of the furthest section.
     * This includes low memory (KPCR at 0x0-0xFF) which game code reads
     * from, the XBE sections, and the simulated stack.
     */
    /* Map the full Xbox address space (covers all sections + stack + heap).
     * Size is runtime-configurable: retail 64 MB, devkit debug builds 128 MB. */
    g_memory_size = g_xbox_total_ram;

    /*
     * Create a file mapping backed by the page file.
     *
     * Using file mapping instead of VirtualAlloc allows us to map the same
     * physical pages at multiple virtual addresses via MapViewOfFileEx.
     * This is critical for the Xbox RAM mirror: the Xbox memory controller
     * uses a 26-bit address bus, so ALL addresses wrap modulo 64 MB.
     * Code that writes to address 0x20000448 is really writing to 0x00000448.
     * With file mapping views, we create aliased mappings at 64 MB intervals
     * that all point to the same physical memory.
     */
    g_mapping_handle = CreateFileMappingA(
        INVALID_HANDLE_VALUE,   /* page file backed */
        NULL,                   /* default security */
        PAGE_READWRITE,         /* read-write access */
        0,                      /* high DWORD of size */
        (DWORD)g_memory_size,   /* low DWORD of size (64 MB) */
        NULL                    /* unnamed mapping */
    );
    if (!g_mapping_handle) {
        fprintf(stderr, "xbox_MemoryLayoutInit: CreateFileMapping failed (error %lu)\n",
                GetLastError());
        return FALSE;
    }

    /*
     * Map the base view at the desired virtual address.
     * Try the original Xbox base address first. If that fails (common on
     * Windows 11 where low addresses are often reserved), try page-aligned
     * addresses upward until we find a free region.
     */
    {
        static const uintptr_t try_bases[] = {
            XBOX_BASE_ADDRESS,      /* 0x00010000 - original Xbox address */
            0x00800000,             /* 8 MB - above typical PEB/TEB region */
            0x01000000,             /* 16 MB */
            0x02000000,             /* 32 MB */
            0x10000000,             /* 256 MB */
            0,                      /* sentinel - let OS choose */
        };

        for (int i = 0; try_bases[i] != 0 || i == 0; i++) {
            LPVOID hint = try_bases[i] ? (LPVOID)try_bases[i] : NULL;
            g_memory_base = MapViewOfFileEx(
                g_mapping_handle,
                FILE_MAP_ALL_ACCESS,
                0, 0,           /* offset into mapping */
                g_memory_size,  /* size */
                hint            /* desired base address */
            );
            if (g_memory_base) {
                if (try_bases[i] != 0 && (uintptr_t)g_memory_base != try_bases[i]) {
                    /* OS gave us a different address, retry */
                    UnmapViewOfFile(g_memory_base);
                    g_memory_base = NULL;
                    continue;
                }
                break;
            }
        }
    }

    if (!g_memory_base) {
        fprintf(stderr, "xbox_MemoryLayoutInit: failed to map base view (%zu KB)\n",
                g_memory_size / 1024);
        CloseHandle(g_mapping_handle);
        g_mapping_handle = NULL;
        return FALSE;
    }

    g_memory_offset = (uintptr_t)g_memory_base - XBOX_MAP_START;

    if (g_memory_offset == 0) {
        fprintf(stderr, "xbox_MemoryLayoutInit: mapped %zu KB at 0x%08X (original Xbox address)\n",
                g_memory_size / 1024, XBOX_MAP_START);
    } else {
        fprintf(stderr, "xbox_MemoryLayoutInit: mapped %zu KB at 0x%p (offset %+td from Xbox base)\n",
                g_memory_size / 1024, g_memory_base, g_memory_offset);
    }

    /*
     * Helper macro: convert Xbox VA to actual mapped address.
     * When g_memory_offset == 0 (ideal case), this is identity.
     */
    #define XBOX_VA(va) ((void *)((uintptr_t)(va) + g_memory_offset))

    /*
     * Copy XBE header to base address.
     * The Xbox kernel maps the XBE image header at 0x00010000.
     * Game code reads kernel thunk table, certificate data, and
     * section info from this region.
     */
    {
        /* XBE header size is at file offset 0x0108 (SizeOfImageHeader) */
        DWORD header_size = 0;
        if (xbe_size >= 0x10C) {
            header_size = *(const DWORD *)(xbe + 0x0108);
        }
        if (header_size == 0 || header_size > 0x10000)
            header_size = 0x1000;  /* fallback: 4KB */
        if (header_size > xbe_size)
            header_size = (DWORD)xbe_size;
        memcpy(XBOX_VA(XBOX_BASE_ADDRESS), xbe, header_size);
        fprintf(stderr, "  XBE header: %u bytes at %p (Xbox VA 0x%08X)\n",
                header_size, XBOX_VA(XBOX_BASE_ADDRESS), XBOX_BASE_ADDRESS);
    }

    /*
     * Dynamically load ALL XBE sections by parsing the section headers.
     *
     * This replaces the old approach of hardcoding section addresses for
     * a specific game (Burnout 3). By reading the section table from the
     * XBE header, any game's sections are loaded automatically.
     *
     * Every section is copied to its original Xbox VA:
     * - .text: needed because memory walkers may scan code pages
     * - .rdata: constants, vtables, kernel thunk table
     * - .data: global variables (initialized portion from XBE, BSS zeroed)
     * - XDK library sections (D3D, DSOUND, WMADEC, XPP, etc.)
     * - DOLBY, BINK, XTIMAGE, etc.
     */
    {
        DWORD base_addr = *(const DWORD *)(xbe + XBE_BASE_ADDR_OFFSET);
        DWORD num_sections = *(const DWORD *)(xbe + XBE_SECTION_COUNT_OFFSET);
        DWORD sect_headers_va = *(const DWORD *)(xbe + XBE_SECTION_HEADERS_OFFSET);
        DWORD sect_headers_off = sect_headers_va - base_addr;
        int sections_loaded = 0;
        size_t total_bytes = 0;

        if (num_sections > 64) num_sections = 64;  /* sanity cap */

        fprintf(stderr, "  XBE sections: %u (headers at file offset 0x%08X)\n",
                num_sections, sect_headers_off);

        for (DWORD si = 0; si < num_sections; si++) {
            if (sect_headers_off + (si + 1) * SECTHDR_SIZE > xbe_size) break;

            const uint8_t *sh = xbe + sect_headers_off + si * SECTHDR_SIZE;
            DWORD sec_va       = *(const DWORD *)(sh + SECTHDR_VA);
            DWORD sec_vsize    = *(const DWORD *)(sh + SECTHDR_VSIZE);
            DWORD sec_raw_off  = *(const DWORD *)(sh + SECTHDR_RAW_OFFSET);
            DWORD sec_raw_size = *(const DWORD *)(sh + SECTHDR_RAW_SIZE);
            DWORD sec_name_va  = *(const DWORD *)(sh + SECTHDR_NAME_ADDR);

            /* Read section name from XBE header */
            const char *sec_name = "?";
            DWORD name_off = sec_name_va - base_addr;
            if (name_off < xbe_size && name_off + 8 <= xbe_size)
                sec_name = (const char *)(xbe + name_off);

            /* Validate: section must fit within our 64MB mapped region */
            if (sec_va < XBOX_BASE_ADDRESS || sec_va + sec_vsize > XBOX_TOTAL_RAM)
                continue;

            /* Determine copy size (raw_size may exceed vsize due to alignment) */
            DWORD copy_size = (sec_raw_size < sec_vsize) ? sec_raw_size : sec_vsize;

            /* Zero the full virtual size first (handles BSS) */
            memset(XBOX_VA(sec_va), 0, sec_vsize);

            /* Copy initialized data from XBE */
            if (copy_size > 0 && sec_raw_off + copy_size <= xbe_size) {
                memcpy(XBOX_VA(sec_va), xbe + sec_raw_off, copy_size);
            }

            sections_loaded++;
            total_bytes += copy_size;

            fprintf(stderr, "  [%2u] %-12s VA=0x%08X vsize=%-8u raw=0x%08X rsize=%-8u%s\n",
                    si, sec_name, sec_va, sec_vsize, sec_raw_off, sec_raw_size,
                    (sec_raw_size < sec_vsize) ? " (BSS)" : "");
        }

        fprintf(stderr, "  Loaded %d/%u sections (%zu bytes total)\n",
                sections_loaded, num_sections, total_bytes);
    }

    /*
     * Parse the kernel thunk table address from the XBE header.
     * The XBE stores KernelImageThunkAddress at offset 0x0158, XOR-encrypted.
     * The key differs between retail and debug XBEs, and there is no flag
     * saying which was used -- decode with both and keep whichever lands in
     * the mapped address range (this is what tools/xbe_parser does).
     *
     * Debug XBEs are not an edge case here: they are the builds most worth
     * recompiling, since they still carry assert strings and symbols. Halo's
     * cachebeta.xbe is one, and assuming the retail key decoded its thunk
     * table to 0xB4F98174 instead of 0x00253090, which silently fell back to
     * the compile-time default and resolved 0 of 378 kernel imports.
     */
    if (xbe_size >= 0x015C) {
        uint32_t thunk_raw = *(const uint32_t *)(xbe + 0x0158);
        uint32_t thunk_retail = thunk_raw ^ 0x5B6D40B6;  /* retail XOR key */
        uint32_t thunk_debug  = thunk_raw ^ 0xEFB1F152;  /* debug XOR key  */
        uint32_t thunk_va;

        if (thunk_retail >= XBOX_BASE_ADDRESS && thunk_retail < XBOX_TOTAL_RAM) {
            thunk_va = thunk_retail;
        } else {
            thunk_va = thunk_debug;
        }

        /* Validate: thunk VA should be within our mapped region */
        if (thunk_va >= XBOX_BASE_ADDRESS && thunk_va < XBOX_TOTAL_RAM) {
            /* Count thunk entries by scanning until we hit 0 */
            uint32_t thunk_count = 0;
            /* XBOX_KERNEL_THUNK_TABLE_SIZE, not 366: the kernel exports 378
             * slots, and kernel.h notes 366 is short by 12. A title importing
             * a high ordinal would have had its table truncated here. */
            for (uint32_t t = 0; t < XBOX_KERNEL_THUNK_TABLE_SIZE; t++) {
                uint32_t entry = *(volatile uint32_t *)((uintptr_t)(thunk_va + t * 4) + g_memory_offset);
                if (entry == 0) break;
                thunk_count++;
            }
            xbox_kernel_set_thunk_address(thunk_va, thunk_count);
            fprintf(stderr, "  Kernel thunks: %u entries at Xbox VA 0x%08X\n",
                    thunk_count, thunk_va);
        } else {
            fprintf(stderr, "  WARNING: kernel thunk VA 0x%08X out of range (raw=0x%08X)\n",
                    thunk_va, thunk_raw);
        }
    }

    /*
     * NOTE: .rdata is NOT set read-only.
     * VirtualProtect rounds to page boundaries, and the .rdata end (0x003B2454)
     * and .data start (0x003B2360) share the same 4KB page (0x003B2000-0x003B2FFF).
     * Making .rdata read-only also makes the first ~0xCA0 bytes of .data read-only,
     * which causes game initialization code to fault when writing to .data globals
     * in that overlap range.
     */
    (void)old_protect;

    #undef XBOX_VA

    /* Set the global offset for recompiled code MEM macros */
    g_xbox_mem_offset = g_memory_offset;

    /*
     * Initialize the Xbox stack for recompiled code.
     * The stack area lives at XBOX_STACK_BASE in Xbox address space.
     * g_esp is the global stack pointer shared by all translated functions.
     */
    g_esp = XBOX_STACK_TOP;
    fprintf(stderr, "  Stack: %u KB at Xbox VA 0x%08X (ESP = 0x%08X)\n",
            XBOX_STACK_SIZE / 1024, XBOX_STACK_BASE, g_esp);

    /*
     * Populate the fake Thread Information Block (TIB) at Xbox VA 0x0.
     *
     * The original Xbox code uses fs:[offset] to read per-thread data,
     * but the recompiler drops the fs: segment prefix and generates
     * MEM32(offset) instead. Since we mapped low memory (0x0-0xFFFF),
     * we populate the TIB fields that game code accesses:
     *
     *   fs:[0x00] = SEH exception list (-1 = end of chain)
     *   fs:[0x04] = stack base (top of stack)
     *   fs:[0x08] = stack limit (bottom of stack)
     *   fs:[0x18] = self pointer (TIB address)
     *   fs:[0x20] = KPCR Prcb pointer (→ fake structure)
     *   fs:[0x28] = TLS / RW engine context pointer
     *
     * We use free space in the BSS area for the fake structures.
     */
    {
        #define XBOX_VA(va) ((void *)((uintptr_t)(va) + g_memory_offset))
        #define MEM32_INIT(va, val) (*(uint32_t *)XBOX_VA(va) = (uint32_t)(val))

        /* Fake TIB at address 0x0 */
        MEM32_INIT(0x00, 0xFFFFFFFF);       /* SEH: end of chain */
        MEM32_INIT(0x04, XBOX_STACK_TOP);   /* Stack base (high address) */
        MEM32_INIT(0x08, XBOX_STACK_BASE);  /* Stack limit (low address) */
        MEM32_INIT(0x18, 0x00000000);       /* Self pointer (TIB at VA 0) */

        /*
         * fs:[0x20] - On Xbox KPCR, this is the Prcb pointer.
         * Game code reads [fs:[0x20] + 0x250] which on the real Xbox
         * accesses a D3D cache structure. We set it to 0 so the read
         * at offset 0x250 returns 0, causing the cache init to be skipped.
         *
         * That only holds if guest VA 0x250 (== MEM32(fs:[0x20]) + 0x250
         * once fs:[0x20] reads 0) is itself zero. Nothing else in this
         * low reserved region writes there, but it isn't guaranteed zero
         * either (observed holding stale/garbage data at runtime, which
         * sub_00254580 then dereferenced as a pointer -- crash). Zero it
         * explicitly so the "skip cache init" intent above actually holds.
         */
        MEM32_INIT(0x20, 0x00000000);
        MEM32_INIT(0x250, 0x00000000);

        /*
         * fs:[0x28] - Thread local storage / RW engine context.
         * The RW engine reads [fs:[0x28] + 0x28] to get a pointer
         * to its data area. We allocate a fake structure at 0x00760000
         * (in the BSS area) and a data buffer at 0x00700000.
         */
        #define FAKE_TLS_VA     0x00760000  /* Fake TLS structure (in BSS) */
        #define FAKE_RWDATA_VA  0x00700000  /* RW engine data area (in BSS) */

        MEM32_INIT(0x28, FAKE_TLS_VA);
        /* TLS[0x28] = pointer to RW data area */
        MEM32_INIT(FAKE_TLS_VA + 0x28, FAKE_RWDATA_VA);

        fprintf(stderr, "  TIB: fake TIB at VA 0x0, TLS at 0x%08X, RW data at 0x%08X\n",
                FAKE_TLS_VA, FAKE_RWDATA_VA);

        #undef FAKE_TLS_VA
        #undef FAKE_RWDATA_VA
        #undef MEM32_INIT
        #undef XBOX_VA
    }

    /*
     * Contiguous / physical memory window at 0x80000000.
     *
     * MmAllocateContiguousMemory hands back addresses in this window: physical
     * page P is visible at 0x80000000 + P. Titles that pin buffers at fixed
     * physical addresses then use the whole range, so it has to be backed for
     * its full length - Halo pins 3.4 MB at 0x61000 and 22 MB at 0x3A6000, and
     * with only the fake kernel page mapped here a write walked off the end of
     * it a few pages in.
     *
     * Deliberately NOT a view of the 64 MB RAM mapping. On hardware this window
     * aliases physical RAM, but we load the XBE image into the low addresses of
     * that same region, so aliasing would put a title's pinned pools on top of
     * its own code. Separate storage costs an extra mapping and behaves
     * correctly. The physical aperture repeats after its full span; Bink's
     * motion-compensation reads can cross that boundary by several megabytes.
     *
     * Reserved before the kernel page below, which lives inside it.
     */
    {
        uintptr_t contig_native = XBOX_CONTIG_BASE + g_memory_offset;
        unsigned contig_wraps_ok = 0;
        g_contig_mapping_handle = CreateFileMappingA(
            INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
            XBOX_CONTIG_SIZE, NULL);
        if (g_contig_mapping_handle) {
            g_contig_memory = MapViewOfFileEx(
                g_contig_mapping_handle, FILE_MAP_ALL_ACCESS, 0, 0,
                XBOX_CONTIG_SIZE, (LPVOID)contig_native);
            if (g_contig_memory) {
                for (unsigned view = 0; view < XBOX_CONTIG_WRAP_VIEW_COUNT; view++) {
                    uintptr_t wrap_native = contig_native +
                        (uintptr_t)(view + 1u) * XBOX_CONTIG_SIZE;
                    g_contig_wrap_views[view] = MapViewOfFileEx(
                        g_contig_mapping_handle, FILE_MAP_ALL_ACCESS, 0, 0,
                        XBOX_CONTIG_SIZE, (LPVOID)wrap_native);
                    if (g_contig_wrap_views[view]) {
                        contig_wraps_ok++;
                    } else {
                        fprintf(stderr,
                                "  WARNING: contiguous mirror %u at Xbox VA 0x%08X failed (error %lu)\n",
                                view + 1u,
                                XBOX_CONTIG_BASE + (view + 1u) * XBOX_CONTIG_SIZE,
                                GetLastError());
                    }
                }
            }
        }
        if (g_contig_memory) {
            fprintf(stderr, "  Contiguous window: %u MB at Xbox VA 0x%08X\n",
                    XBOX_CONTIG_SIZE / (1024 * 1024), XBOX_CONTIG_BASE);
            fprintf(stderr,
                    "  Contiguous mirrors: %u/%u views mapped through Xbox VA 0x%08X\n",
                    contig_wraps_ok, (unsigned)XBOX_CONTIG_WRAP_VIEW_COUNT,
                    XBOX_CONTIG_BASE + XBOX_CONTIG_APERTURE_SIZE);
        } else {
            if (g_contig_mapping_handle) {
                CloseHandle(g_contig_mapping_handle);
                g_contig_mapping_handle = NULL;
            }
            fprintf(stderr, "  WARNING: contiguous window at 0x%08X failed "
                    "(error %lu); pinned physical allocations will fault\n",
                    XBOX_CONTIG_BASE, GetLastError());
        }
    }

    /*
     * NV2A hardware register aperture at 0xFD000000 (16 MB).
     *
     * The GPU's registers are memory-mapped here on real hardware. A title
     * that only calls D3D never notices, but the D3D8 library is linked into
     * the XBE rather than provided by the kernel, so once execution is inside
     * it the register pokes are just loads and stores in recompiled code.
     * Halo faults reading 0xFD001804 during rasterizer_preinitialize, a few
     * instructions after Direct3DCreate8 returns.
     *
     * Backed as ordinary zeroed RAM. That is enough to get through
     * initialisation, and reads returning zero are the benign answer for the
     * status and capability registers touched here.
     *
     * ponytail: plain memory, no register semantics. A spin loop waiting for
     * a bit to *set* would hang rather than fault -- if that shows up, the fix
     * is to bridge the D3D8 entry point that owns the loop, not to start
     * emulating NV2A. Nothing has needed that yet.
     */
    {
        uintptr_t nv2a_native = XBOX_NV2A_BASE + g_memory_offset;
        g_nv2a_memory = VirtualAlloc(
            (LPVOID)nv2a_native,
            XBOX_NV2A_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        if (g_nv2a_memory) {
            fprintf(stderr, "  NV2A register aperture: %u MB at Xbox VA "
                    "0x%08X (zeroed, no register semantics)\n",
                    XBOX_NV2A_SIZE / (1024 * 1024), XBOX_NV2A_BASE);
        } else {
            fprintf(stderr, "  WARNING: NV2A aperture at 0x%08X failed "
                    "(error %lu); D3D register access will fault\n",
                    XBOX_NV2A_BASE, GetLastError());
        }
    }

    /*
     * MCPX device apertures.
     *
     * The NV2A block above is not the only hardware the title touches
     * directly. The southbridge devices live higher up:
     *
     *   0xFE800000  APU (audio processing unit)
     *   0xFEC00000  AC97
     *   0xFED00000  USB0 / USB1
     *   0xFEF00000  NIC
     *
     * Halo faults reading 0xFED00000 during input initialisation -- the XDK's
     * USB code talks to the host controller's registers rather than going
     * through a driver. Back the whole span as plain RAM for the same reason
     * the NV2A aperture is backed: a read of zero is survivable, a fault is
     * not.
     *
     * ponytail: no register semantics anywhere in here. If something spins
     * waiting for a bit to set, extend the NV2A ack thread's table rather than
     * emulating the device.
     */
    {
        uintptr_t mcpx_native = XBOX_MCPX_BASE + g_memory_offset;
        g_mcpx_memory = VirtualAlloc(
            (LPVOID)mcpx_native,
            XBOX_MCPX_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        g_mcpx_regs = g_mcpx_memory;
        if (g_mcpx_memory) {
            /* Valid before the ack thread's first pass, not just after it. */
            for (size_t i = 0; i < sizeof(MCPX_DSP_WORDS) / sizeof(MCPX_DSP_WORDS[0]); i++) {
                *(volatile uint32_t *)((char *)g_mcpx_memory + MCPX_DSP_WORDS[i].offset) =
                    MCPX_DSP_WORDS[i].value;
            }
            fprintf(stderr, "  MCPX device aperture: %u MB at Xbox VA "
                    "0x%08X (APU/AC97/USB/NIC, zeroed)\n",
                    XBOX_MCPX_SIZE / (1024 * 1024), XBOX_MCPX_BASE);
        } else {
            fprintf(stderr, "  WARNING: MCPX aperture at 0x%08X failed "
                    "(error %lu); USB/audio register access will fault\n",
                    XBOX_MCPX_BASE, GetLastError());
        }
    }

    if (g_nv2a_memory) {
        xbox_Nv2aAckStart();
    }

    /*
     * Allocate a page at Xbox kernel address space (0x80010000).
     *
     * RenderWare's Xbox driver code (xbcache.c) reads MEM32(0x8001003C)
     * to parse the Xbox kernel's PE header and find the INIT section for
     * CPU cache line sizing. On PC, we provide a minimal fake PE header
     * with 0 sections so the function gracefully skips the cache init.
     *
     * The actual native address is 0x80010000 + g_memory_offset.
     */
    {
        #define XBOX_KERNEL_BASE 0x80010000u
        #define KERNEL_PAGE_SIZE 4096
        uintptr_t kernel_native = XBOX_KERNEL_BASE + g_memory_offset;
        /* Already committed if the contiguous window above succeeded -
         * 0x80010000 sits inside it - so just use that storage. */
        g_kernel_memory = g_contig_memory
            ? (void *)kernel_native
            : VirtualAlloc((LPVOID)kernel_native, KERNEL_PAGE_SIZE,
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (g_kernel_memory) {
            /* Zero-fill then set e_lfanew = 0x80 (offset to PE header).
             * With the rest zeroed, NumberOfSections = 0 and the INIT
             * section search finds nothing, which is the safe path. */
            memset(g_kernel_memory, 0, KERNEL_PAGE_SIZE);
            *(uint32_t *)((uint8_t *)g_kernel_memory + 0x3C) = 0x80;  /* e_lfanew */
            fprintf(stderr, "  Kernel: fake PE header at Xbox VA 0x%08X (native %p)\n",
                    XBOX_KERNEL_BASE, g_kernel_memory);
        } else {
            fprintf(stderr, "  WARNING: could not map Xbox kernel VA 0x%08X\n",
                    XBOX_KERNEL_BASE);
        }
        #undef XBOX_KERNEL_BASE
        #undef KERNEL_PAGE_SIZE
    }

    /* Initialize the dynamic heap. */
    fprintf(stderr, "  Heap: %u MB at Xbox VA 0x%08X-0x%08X\n",
            (unsigned)((XBOX_HEAP_TOP - XBOX_HEAP_BASE) / (1024 * 1024)),
            XBOX_HEAP_BASE, XBOX_HEAP_TOP);

    /*
     * Map mirror views of the 64 MB region.
     *
     * On retail Xbox, physical RAM wraps at 64 MB due to the 26-bit
     * address bus. Address 0x04070000 reads the same data as 0x00070000.
     * The RenderWare engine's memory walker crosses 64 MB and accesses
     * mirrored data for an extended walk covering 256+ MB of virtual
     * addresses. Game init code also writes large data structures past
     * 64 MB that on real hardware wrap into physical RAM.
     *
     * We map additional views of the SAME file mapping section at 64 MB
     * intervals. All views alias the same physical pages, so reads and
     * writes at any mirror address correctly access the base data.
     */
    {
        int mirrors_ok = 0;
        for (int m = 0; m < XBOX_NUM_MIRRORS; m++) {
            uintptr_t mirror_base = (uintptr_t)g_memory_base +
                                    (uintptr_t)(m + 1) * g_memory_size;
            g_mirror_views[m] = MapViewOfFileEx(
                g_mapping_handle,
                FILE_MAP_ALL_ACCESS,
                0, 0,
                g_memory_size,
                (LPVOID)mirror_base
            );
            if (g_mirror_views[m]) {
                mirrors_ok++;
            } else {
                fprintf(stderr, "  Mirror %d: FAILED at %p (error %lu)\n",
                        m + 1, (void *)mirror_base, GetLastError());
            }
        }
        fprintf(stderr, "  RAM mirror: %d/%d views mapped (covers %d MB)\n",
                mirrors_ok, XBOX_NUM_MIRRORS,
                (int)((mirrors_ok + 1) * g_memory_size / (1024 * 1024)));
    }

    fprintf(stderr, "xbox_MemoryLayoutInit: complete\n");
    return TRUE;
}

/*
 * Make every RAM mirror read-only, for finding writes that reach low memory
 * through an alias.
 *
 * Xbox RAM is visible at 28 virtual addresses that alias the same pages, so a
 * store to 0x04000004 changes Xbox VA 4 without ever touching VA 4. Both a
 * page-protection watchpoint and a DR0 hardware watchpoint on VA 4 therefore
 * report nothing while the memory demonstrably changes -- which is exactly
 * what happened chasing Halo's fs:[4] corruption.
 *
 * Debug aid, not part of normal startup: a title that legitimately writes
 * through a mirror will fault here too, and the fault address names the alias
 * and the code.
 */
void xbox_ProtectMirrorsForDebug(void)
{
    int n = 0;
    for (int m = 0; m < XBOX_NUM_MIRRORS; m++) {
        DWORD old;
        if (g_mirror_views[m] &&
            VirtualProtect(g_mirror_views[m], g_memory_size,
                           PAGE_READONLY, &old)) {
            n++;
        }
    }
    fprintf(stderr, "  Mirrors: %d/%d made read-only (debug)\n",
            n, XBOX_NUM_MIRRORS);
}

void xbox_MemoryLayoutShutdown(void)
{
    if (g_kernel_memory) {
        if (!g_contig_memory)
            VirtualFree(g_kernel_memory, 0, MEM_RELEASE);
        g_kernel_memory = NULL;
    }
    if (g_nv2a_ack_thread) {
        InterlockedExchange(&g_nv2a_ack_stop, 1);
        WaitForSingleObject(g_nv2a_ack_thread, 1000);
        CloseHandle(g_nv2a_ack_thread);
        g_nv2a_ack_thread = NULL;
    }
    if (g_nv2a_memory) {
        VirtualFree(g_nv2a_memory, 0, MEM_RELEASE);
        g_nv2a_memory = NULL;
    }
    for (unsigned view = 0; view < XBOX_CONTIG_WRAP_VIEW_COUNT; view++) {
        if (g_contig_wrap_views[view]) {
            UnmapViewOfFile(g_contig_wrap_views[view]);
            g_contig_wrap_views[view] = NULL;
        }
    }
    if (g_contig_memory) {
        UnmapViewOfFile(g_contig_memory);
        g_contig_memory = NULL;
    }
    if (g_contig_mapping_handle) {
        CloseHandle(g_contig_mapping_handle);
        g_contig_mapping_handle = NULL;
    }
    /* Unmap mirror views first */
    for (int m = 0; m < XBOX_NUM_MIRRORS; m++) {
        if (g_mirror_views[m]) {
            UnmapViewOfFile(g_mirror_views[m]);
            g_mirror_views[m] = NULL;
        }
    }
    /* Unmap base view */
    if (g_memory_base) {
        UnmapViewOfFile(g_memory_base);
        g_memory_base = NULL;
        g_memory_size = 0;
    }
    /* Close file mapping handle */
    if (g_mapping_handle) {
        CloseHandle(g_mapping_handle);
        g_mapping_handle = NULL;
    }
    fprintf(stderr, "xbox_MemoryLayoutShutdown: released\n");
}

BOOL xbox_IsXboxAddress(uintptr_t address)
{
    return (address >= XBOX_BASE_ADDRESS &&
            address < XBOX_BASE_ADDRESS + g_memory_size);
}

void *xbox_GetMemoryBase(void)
{
    return g_memory_base;
}

ptrdiff_t xbox_GetMemoryOffset(void)
{
    return g_memory_offset;
}

/* ── Dynamic heap allocator ────────────────────────────────
 *
 * Simple bump allocator for MmAllocateContiguousMemory and similar.
 * Returns Xbox VAs within the mapped region so MEM32() works correctly.
 * No free support (bump-only for now).
 */
static uint32_t g_heap_next = XBOX_HEAP_BASE;

static int g_heap_alloc_count = 0;

/* Block table backing xbox_HeapFree. A bump pointer alone never reclaims,
 * which is fine for a title that allocates once and fatal for a debug build
 * that churns. Flat array rather than an intrusive list: allocations come back
 * in bump order, so index order is address order and coalescing is a
 * neighbour check. */
#define XBOX_HEAP_MAX_BLOCKS 65536
static struct { uint32_t addr; uint32_t size; uint8_t free; }
    g_heap_blocks[XBOX_HEAP_MAX_BLOCKS];
static int g_heap_block_count = 0;

/*
 * Simulated stacks for spawned threads.
 *
 * The main thread owns the top of the XBOX_STACK region and grows down; worker
 * stacks are carved from the bottom upward so the two cannot meet until the
 * whole 8 MB is gone. Xbox VAs, not host memory: recompiled code addresses its
 * stack through MEM32() like any other Xbox pointer.
 */
#define XBOX_THREAD_STACK_SIZE  (512 * 1024)
#define XBOX_MAX_THREAD_STACKS  8

static int g_thread_stacks_used = 0;
static volatile LONG g_thread_stack_slots[XBOX_MAX_THREAD_STACKS];

uint32_t xbox_AllocThreadStack(void)
{
    for (int stack_index = 0; stack_index < XBOX_MAX_THREAD_STACKS; ++stack_index) {
        if (InterlockedCompareExchange(&g_thread_stack_slots[stack_index], 1, 0) == 0) {
            uint32_t base = XBOX_STACK_BASE +
                (uint32_t)stack_index * XBOX_THREAD_STACK_SIZE;
            InterlockedIncrement((volatile LONG *)&g_thread_stacks_used);
            /* Top of the owned slice, 16-byte aligned, growing down. */
            return base + XBOX_THREAD_STACK_SIZE - 16;
        }
    }
    return 0;
}

void xbox_FreeThreadStack(uint32_t stack_top)
{
    uint32_t first_top = XBOX_STACK_BASE + XBOX_THREAD_STACK_SIZE - 16;
    uint32_t offset, stack_index;
    if (stack_top < first_top) return;
    offset = stack_top - first_top;
    if (offset % XBOX_THREAD_STACK_SIZE) return;
    stack_index = offset / XBOX_THREAD_STACK_SIZE;
    if (stack_index >= XBOX_MAX_THREAD_STACKS) return;
    if (InterlockedCompareExchange(&g_thread_stack_slots[stack_index], 0, 1) == 1)
        InterlockedDecrement((volatile LONG *)&g_thread_stacks_used);
}

uint32_t xbox_HeapAlloc(uint32_t size, uint32_t alignment)
{
    uint32_t result;

    if (alignment < 4) alignment = 4;

    /* Enforce minimum allocation size.
     * The Xbox D3D8 code sometimes computes resource sizes from GPU
     * capabilities that return 0 (since we don't have real NV2A hardware),
     * resulting in zero-size allocations. With a bump allocator, these all
     * return the same address, causing overlapping structures. Enforce a
     * minimum of 4096 bytes so each allocation gets its own memory. */
    if (size < 16) size = 16;

    /* Reuse a freed block first. Without this the heap only ever grows: Halo's
     * debug build allocates and releases heavily through init, exhausted all
     * 48 MB in 4,726 allocations, and its second D3D CreateDevice then failed
     * with E_OUTOFMEMORY -- which the title reports by clearing
     * global_d3d_device, so the rasterizer asserts and startup stops. */
    for (int i = 0; i < g_heap_block_count; i++) {
        if (!g_heap_blocks[i].free || g_heap_blocks[i].size < size) {
            continue;
        }
        if (g_heap_blocks[i].addr & (alignment - 1)) {
            continue;   /* wrong alignment for this request */
        }
        g_heap_blocks[i].free = 0;
        result = g_heap_blocks[i].addr;
        memset((void *)((uintptr_t)result + g_memory_offset), 0, size);
        return result;
    }

    /* Align the next pointer */
    result = (g_heap_next + alignment - 1) & ~(alignment - 1);

    if (result + size > XBOX_HEAP_TOP) {
        fprintf(stderr, "xbox_HeapAlloc: out of memory (requested %u, used %u/%u)\n",
                size, g_heap_next - XBOX_HEAP_BASE,
                (unsigned)(XBOX_HEAP_TOP - XBOX_HEAP_BASE));
        /* Who ate the heap? Group live blocks by size -- an exhausted heap is
         * nearly always one request size repeated, and the count names it. */
        {
            static int dumped = 0;
            static struct { uint32_t size; int n; } hist[256];
            if (!dumped) {
                int used = 0;
                dumped = 1;
                for (int i = 0; i < g_heap_block_count; i++) {
                    int j = 0;
                    if (g_heap_blocks[i].free || !g_heap_blocks[i].size) continue;
                    while (j < used && hist[j].size != g_heap_blocks[i].size) j++;
                    if (j == used) {
                        if (used == 256) continue;   /* ponytail: 256 distinct sizes is plenty */
                        hist[used].size = g_heap_blocks[i].size;
                        hist[used++].n = 0;
                    }
                    hist[j].n++;
                }
                for (int j = 0; j < used; j++) {
                    if ((uint64_t)hist[j].n * hist[j].size < 1024 * 1024) continue;
                    fprintf(stderr, "  [HEAP] %d live blocks of %u bytes (%u KB)\n",
                            hist[j].n, hist[j].size,
                            (unsigned)((uint64_t)hist[j].n * hist[j].size / 1024));
                }
                fflush(stderr);
            }
        }
        return 0;
    }

    g_heap_next = result + size;

    /* Zero-fill the allocated block (Xbox memory is always zeroed) */
    memset((void *)((uintptr_t)result + g_memory_offset), 0, size);

    if (g_heap_block_count < XBOX_HEAP_MAX_BLOCKS) {
        g_heap_blocks[g_heap_block_count].addr = result;
        g_heap_blocks[g_heap_block_count].size = size;
        g_heap_blocks[g_heap_block_count].free = 0;
        g_heap_block_count++;
    }

    g_heap_alloc_count++;
    /* Rate-limited: a debug title makes thousands of these and the log is a
     * diagnostic, not a transaction record. */
    if (g_heap_alloc_count <= 32 || (g_heap_alloc_count % 512) == 0) {
        fprintf(stderr, "  [HEAP] #%d: size=%u align=%u → 0x%08X..0x%08X (used %u/%u)\n",
                g_heap_alloc_count, size, alignment, result, result + size,
                g_heap_next - XBOX_HEAP_BASE,
                (unsigned)(XBOX_HEAP_TOP - XBOX_HEAP_BASE));
        fflush(stderr);
    }

    return result;
}

uint32_t xbox_HeapBlockSize(uint32_t xbox_va)
{
    if (!xbox_va) {
        return 0;
    }
    for (int i = 0; i < g_heap_block_count; i++) {
        if (g_heap_blocks[i].addr == xbox_va && !g_heap_blocks[i].free) {
            return g_heap_blocks[i].size;
        }
    }
    return 0;
}

void xbox_HeapFree(uint32_t xbox_va)
{
    static int frees = 0, matched = 0;

    if (!xbox_va) {
        return;
    }
    frees++;
    if (frees <= 8) {
        fprintf(stderr, "  [HEAP] free #%d va=0x%08X blocks=%d\n",
                frees, xbox_va, g_heap_block_count);
        fflush(stderr);
    }
    for (int i = 0; i < g_heap_block_count; i++) {
        if (g_heap_blocks[i].addr != xbox_va || g_heap_blocks[i].free) {
            continue;
        }
        g_heap_blocks[i].free = 1;
        if (++matched % 512 == 0) {
            fprintf(stderr, "  [HEAP] frees=%d matched=%d blocks=%d\n",
                    frees, matched, g_heap_block_count);
            fflush(stderr);
        }

        /* Coalesce with neighbours. Blocks are recorded in bump order, so
         * index order is address order and adjacency is a simple end==start
         * test. Keeps large contiguous requests satisfiable after a lot of
         * small churn. */
        if (i + 1 < g_heap_block_count && g_heap_blocks[i + 1].free &&
            g_heap_blocks[i].addr + g_heap_blocks[i].size == g_heap_blocks[i + 1].addr) {
            g_heap_blocks[i].size += g_heap_blocks[i + 1].size;
            g_heap_blocks[i + 1].size = 0;
            g_heap_blocks[i + 1].addr = 0;
        }
        if (i > 0 && g_heap_blocks[i - 1].free &&
            g_heap_blocks[i - 1].addr + g_heap_blocks[i - 1].size == g_heap_blocks[i].addr) {
            g_heap_blocks[i - 1].size += g_heap_blocks[i].size;
            g_heap_blocks[i].size = 0;
            g_heap_blocks[i].addr = 0;
        }
        return;
    }
}

HANDLE xbox_GetMappingHandle(void)
{
    return g_mapping_handle;
}
