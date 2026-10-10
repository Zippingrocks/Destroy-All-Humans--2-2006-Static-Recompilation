/* Diagnostic function-entry tracing for the recompiled guest code.
 *
 * Only active in a build configured with -DDAH2_FN_TRACE=ON, where
 * tools/instrument_fn_trace.py writes instrumented copies of the generated
 * sources (and recomp_manual.c) into the build tree. Normal builds compile
 * the pristine sources, which never include this header.
 *
 * Per guest function address (VA < 4 MiB): the present number at which it was
 * first entered, the global order of first entries, and an entry count. Tracing
 * is off until g_fnt_on is set (DAH2_FNT_AT_PRESENT=N turns it on at present N),
 * so a snapshot taken before an event and one after it differ by exactly the
 * functions that event caused to run. Read from outside with
 * tools/dump_fn_trace.py. */
#ifndef DAH2_FN_TRACE_H
#define DAH2_FN_TRACE_H
#include <stdint.h>
#include <intrin.h>
extern volatile long g_dah2_present_thread_id;
#define DAH2_FNT_SPACE 0x400000u
extern volatile uint32_t g_fnt_on;
extern volatile uint32_t g_fnt_stamp;      /* current present number */
extern volatile uint32_t g_fnt_seq;
extern uint32_t g_fnt_first[DAH2_FNT_SPACE];
extern uint32_t g_fnt_order[DAH2_FNT_SPACE];
extern uint32_t g_fnt_count[DAH2_FNT_SPACE];
extern volatile uint32_t g_fnt_vm_on, g_fnt_flog_idx, g_fnt_nat_idx;
extern volatile uint32_t g_fnt_wlo, g_fnt_whi, g_fnt_wlog_idx, g_fnt_wvm_idx;
extern uint32_t g_fnt_wvm[262144][3];
extern uint32_t g_fnt_wlog[1048576];
extern uint32_t g_fnt_flog[16384];          /* every function entry after the anchor native (main thread) */
#define DAH2_FNT(a) do { if (g_fnt_on) {         if (!g_fnt_order[(a)]) { g_fnt_first[(a)] = g_fnt_stamp; g_fnt_order[(a)] = ++g_fnt_seq; }         ++g_fnt_count[(a)];         if (g_fnt_vm_on && __readgsdword(0x48) == (uint32_t)g_dah2_present_thread_id)             { g_fnt_flog[(g_fnt_flog_idx++) & 16383u] = (a); if (g_fnt_nat_idx >= g_fnt_wlo && g_fnt_nat_idx <= g_fnt_whi && g_fnt_wlog_idx < 1048576u) g_fnt_wlog[g_fnt_wlog_idx++] = (a); } } } while (0)
/* Lua native-call log: every call dispatched through the script VM's native thunk
 * (sub_002117C0). Row = {present, native fn, closure, proto, pc index, src[0..2]}
 * where src is the first 12 characters of the active Lua chunk name. */
extern uint32_t g_fnt_nat[65536][8];
extern volatile uint32_t g_fnt_nat_idx;
/* Lua VM instruction log: armed by the first native call to 0xC2720 after tracing is on
 * (see dah2_fnt_log_native); records {pc pointer, instruction word} for the next 64K VM ops. */
extern volatile uint32_t g_fnt_vm_on, g_fnt_vm_idx, g_fnt_vm_pre_idx;
extern uint32_t g_fnt_vm[65536][2];
extern uint32_t g_fnt_vm_ext[65536][4];
extern uint32_t g_fnt_vm_pre[256][2];       /* rolling window of the last 256 main-thread VM ops */
extern uint32_t g_fnt_vm_pre_snap[256][2];  /* copy taken when the anchor native is first called */
#define DAH2_FNT_VMOP(pc, ins) do { if (g_fnt_on && __readgsdword(0x48) == (uint32_t)g_dah2_present_thread_id) {         if (g_fnt_nat_idx >= g_fnt_wlo && g_fnt_nat_idx <= g_fnt_whi && g_fnt_wvm_idx < 262144u) { uint32_t _w = g_fnt_wvm_idx++; g_fnt_wvm[_w][0] = (pc); g_fnt_wvm[_w][1] = (ins); g_fnt_wvm[_w][2] = g_fnt_nat_idx; }         uint32_t _p = (g_fnt_vm_pre_idx++) & 255u; g_fnt_vm_pre[_p][0] = (pc); g_fnt_vm_pre[_p][1] = (ins);         if (g_fnt_vm_on) { uint32_t _j = g_fnt_vm_idx++;         if (_j < 65536u) { g_fnt_vm[_j][0] = (pc); g_fnt_vm[_j][1] = (ins); } } } } while (0)
/* Same, plus the two TValues below the VM stack top when the op is 32 (the EQ/compare-and-jump op). */
#define DAH2_FNT_VMOP_TOP(pc, ins, top) do { DAH2_FNT_VMOP(pc, ins);         if (g_fnt_vm_on && ((ins) & 63u) == 32u && (top) >= 0x80000000u && (top) < 0x90000000u && g_fnt_vm_idx > 0u && g_fnt_vm_idx <= 65536u) {             uint32_t _k = g_fnt_vm_idx - 1u; extern uint32_t g_fnt_vm_ext_read(uint32_t);             g_fnt_vm_ext[_k][0] = g_fnt_vm_ext_read((top) - 16u); g_fnt_vm_ext[_k][1] = g_fnt_vm_ext_read((top) - 12u);             g_fnt_vm_ext[_k][2] = g_fnt_vm_ext_read((top) - 8u); g_fnt_vm_ext[_k][3] = g_fnt_vm_ext_read((top) - 4u); } } while (0)
/* Per-function argument probes (only inside the DAH2_FN_TRACE build; armed together with g_fnt_vm_on). */
extern uint32_t g_fnt_probe[8192][5];
extern volatile uint32_t g_fnt_probe_idx, g_fnt_probe_lo, g_fnt_probe_hi, g_fnt_nat_idx, g_fnt_probe_boot;
#define DAH2_FNT_PROBE(fn, a, b, c, d) do { if ((g_fnt_vm_on || g_fnt_probe_boot) && g_fnt_on && g_fnt_probe_idx < 8192u && g_fnt_nat_idx >= g_fnt_probe_lo && g_fnt_nat_idx <= g_fnt_probe_hi && __readgsdword(0x48) == (uint32_t)g_dah2_present_thread_id) {         uint32_t _q = g_fnt_probe_idx++; g_fnt_probe[_q][0] = (fn); g_fnt_probe[_q][1] = (uint32_t)(a); g_fnt_probe[_q][2] = (uint32_t)(b);         g_fnt_probe[_q][3] = (uint32_t)(c); g_fnt_probe[_q][4] = (uint32_t)(d); } } while (0)
extern uint32_t dah2_chk_children(uint32_t self);
extern void dah2_regclob(uint32_t fn, uint32_t s, uint32_t d, uint32_t b, uint32_t ns, uint32_t nd, uint32_t nb);
#define DAH2_REGCHK(fn, s, d, b) do { if (g_fnt_on && (g_esi != (s) || g_edi != (d) || g_ebx != (b))) dah2_regclob((fn), (s), (d), (b), g_esi, g_edi, g_ebx); } while (0)
extern void dah2_note_render(uint32_t tag, uint32_t a0, uint32_t a1);
extern void dah2_espchk(uint32_t fn, uint32_t esp_in, uint32_t esp_out);
extern void dah2_path(uint32_t va, uint32_t esp, uint32_t extra);
extern void dah2_note(uint32_t tag, uint32_t a, uint32_t b, uint32_t c);
extern uint32_t dah2_sap(uint32_t tag, uint32_t self, uint32_t a0, uint32_t a1, uint32_t a2);
extern uint32_t dah2_log_sort(uint32_t self, uint32_t arr, uint32_t box, uint32_t cnt, uint32_t ra);
#endif
extern volatile uint32_t g_fnt_hw_gate, g_fnt_hw_auto, g_fnt_hw_addr;
extern void dah2_loopchk(uint32_t i, uint32_t n, uint32_t esp, uint32_t reset);
extern void dah2_alloc_caller(uint32_t ra, uint32_t size, uint32_t is_free);
extern void dah2_arena(uint32_t kind, uint32_t ptr);
extern void dah2_free_probe(uint32_t ptr, uint32_t hdr, uint32_t before, uint32_t after, uint32_t freebytes, uint32_t top);
