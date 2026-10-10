"""Write DAH2_FNT()-instrumented copies of the generated guest sources.

  py -3 tools/instrument_fn_trace.py OUT_DIR file.c [file.c ...]

Inserts `DAH2_FNT(0xADDR);` as the first statement of every `void sub_XXXXXXXX(void)`
and prepends `#include "dah2_fn_trace.h"`. Files are rewritten only when their content
changes so incremental builds stay incremental. Used by the DAH2_FN_TRACE CMake option;
the repository sources are never modified."""
import re, sys
from pathlib import Path


HELPER = r"""
/* Diagnostic: log one Lua native call with the active proto/pc, found the same way the
 * [postloader] trace above does (scan the live guest stack for a {pc, f08, proto} triple). */
static void dah2_fnt_log_result(uint32_t eax, uint32_t L)
{
    extern volatile uint32_t g_fnt_on, g_fnt_nat_idx;
    extern uint32_t g_fnt_natres[65536][4];
    uint32_t i, top;
    if (!g_fnt_on || !g_fnt_nat_idx) return;
    i = (g_fnt_nat_idx - 1u) & 0xFFFFu;
    top = *manual_mem32(L);
    g_fnt_natres[i][0] = eax;
    g_fnt_natres[i][1] = (top >= 0x80000000u && top < 0x90000000u) ? *manual_mem32(top - 8u) : 0xFFFFFFFFu;
    g_fnt_natres[i][2] = (top >= 0x80000000u && top < 0x90000000u) ? *manual_mem32(top - 4u) : 0xFFFFFFFFu;
    g_fnt_natres[i][3] = top;
}

static void dah2_fnt_log_native(uint32_t target, uint32_t closure, uint32_t esp)
{
    extern volatile uint32_t g_fnt_on, g_fnt_stamp, g_fnt_nat_idx;
    extern uint32_t g_fnt_nat[65536][8];
    uint32_t i, k, row[8] = {0};
    if (!g_fnt_on) return;
    extern volatile uint32_t g_fnt_vm_on, g_fnt_vm_idx;
    {
        extern uint32_t g_fnt_natargs[65536][8];
        uint32_t L = g_esi, base = *manual_mem32(L + 0x10u), top = *manual_mem32(L), n = 0, a;
        uint32_t slot = g_fnt_nat_idx & 0xFFFFu;
        for (a = 0; a < 8; ++a) g_fnt_natargs[slot][a] = 0xFFFFFFFFu;
        g_fnt_natargs[slot][7] = *manual_mem32(L + 0x68u);  /* Lua nblocks at the call */
        if (base >= 0x80000000u && top >= base && top < 0x90000000u) {
            for (a = base; a < top && n < 3u; a += 8u, ++n) {
                g_fnt_natargs[slot][n * 2] = *manual_mem32(a); g_fnt_natargs[slot][n * 2 + 1] = *manual_mem32(a + 4u);
            }
            g_fnt_natargs[slot][6] = (top - base) / 8u;
        }
    }
    row[0] = g_fnt_stamp; row[1] = target; row[2] = esp;
    if (target == 0x001116C0u && g_fnt_stamp >= 1500u && g_fnt_vm_idx == 0u) {
        extern uint32_t g_fnt_vm_pre[256][2], g_fnt_vm_pre_snap[256][2];
        extern volatile uint32_t g_fnt_vm_pre_idx;
        uint32_t q; for (q = 0; q < 256u; ++q) { g_fnt_vm_pre_snap[q][0] = g_fnt_vm_pre[(g_fnt_vm_pre_idx + q) & 255u][0]; g_fnt_vm_pre_snap[q][1] = g_fnt_vm_pre[(g_fnt_vm_pre_idx + q) & 255u][1]; }
        g_fnt_vm_on = 1;
    }
    for (k = 2u; k < 256u; ++k) {
        uint32_t function = *manual_mem32(esp + k * 4u);
        uint32_t f08, pc, code, count, so, w;
        if (function < 0x80000000u || function >= 0x90000000u) continue;
        f08 = *manual_mem32(function + 0x08u);
        pc = *manual_mem32(esp + (k - 2u) * 4u);
        code = *manual_mem32(function + 0x18u);
        count = *manual_mem32(function + 0x1Cu);
        if (*manual_mem32(esp + (k - 1u) * 4u) != f08 || pc < code || pc > code + (count ? count * 4u : 4u)) continue;
        so = *manual_mem32(function + 0x40u);
        if (so < 0x80000000u || so >= 0x90000000u) continue;
        if (*manual_mem8(so + 20u) < 0x20u || *manual_mem8(so + 20u) > 0x7Eu) continue;
        row[3] = function; row[4] = (pc - code) / 4u;
        for (w = 0; w < 3u; ++w) row[5 + w] = *manual_mem32(so + 20u + w * 4u);
        break;
    }
    { extern volatile uint32_t g_fnt_wlo, g_fnt_whi, g_fnt_wlog_idx; extern uint32_t g_fnt_wlog[1048576];
      if (g_fnt_nat_idx >= g_fnt_wlo && g_fnt_nat_idx <= g_fnt_whi && g_fnt_wlog_idx < 1048576u) g_fnt_wlog[g_fnt_wlog_idx++] = 0xE0000000u | (target & 0x00FFFFFFu); }
    i = (g_fnt_nat_idx++) & 0xFFFFu;
    for (k = 0; k < 8u; ++k) g_fnt_nat[i][k] = row[k];
}

"""

PROBES = {
    # keep the ring free for the scene-node child validator; re-add others one at a time (windowed via PROBE_LO/HI)
    0x001D0260: "ecx, MEM32(esp + 4), dah2_log_sort(ecx, MEM32(esp + 4), MEM32(esp + 8), MEM32(esp + 12), MEM32(esp)), MEM32(esp + 8)",
    0x001831B0: "ecx, MEM32(esp + 4), dah2_chk_children(ecx), MEM32(esp)",
    0x00183210: "ecx, MEM32(esp + 4), dah2_chk_children(ecx), MEM32(esp)",
    0x00183180: "ecx, MEM32(esp + 4), dah2_chk_children(ecx), MEM32(esp)",
}
# Functions whose RETURN value we also want: renamed to *_inner and wrapped.
SAP_HOOKS = (0x1D23C0,0x1D4FE0,0x1D28C0,0x1D54A0,0x1D3A10,0x1D0F30,0x1D0FA0,0x1D0FC0,0x1D1550,0x1D0030,0x1D3C50,0x1CFF10,0x1D3280,0x1D5870)
NOTE_HOOKS = {0x0015ECA0: "dah2_note(0x15ECA0, g_ecx, MEM32(g_ecx + 0x524), MEM32(g_ecx + 0xEC));", 0x00147DC0: "dah2_note(0x147DC0, g_ecx, MEM32(g_ecx + 0x18), MEM32(g_ecx + 0x20));", 0x00148560: "dah2_note(0x148560, g_ecx, MEM32(g_ecx + 0x18), MEM32(g_ecx + 0x20));", 0x000F96C0: "dah2_alloc_caller(MEM32(g_esp), MEM32(g_esp + 4), 0);", 0x000F96E0: "dah2_alloc_caller(MEM32(g_esp), MEM32(g_esp + 4), 1); dah2_alloc_caller(0x10000000u | MEM32(MEM32(MEM32(MEM32(0x2C9640u) + 0xFCu)) + 8u), 0, 0);", 0x001AE2F0: "dah2_alloc_caller(0x1AE2F0, 0, 0);", 0x001AE650: "dah2_alloc_caller(0x1AE650, 0, 0);"}
REGCHK_ON = True
PATH_FUNCS = (0x00177FB0,)
ESP_NOTE_LABELS = ("00178294", "001782B2", "001783AE", "001783BA", "001783CC", "00178411", "00178426", "00178466", "0017848F", "00178C56")
RET_PROBES = ()
pat = re.compile(r"^(void sub_([0-9A-F]{8})\(void\)\s*\n\{)", re.M)
stub_pat = re.compile(r"^(void sub_([0-9A-F]{8})\(void\) \{)", re.M)   # one-line unresolved-call stubs
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
total = 0
for src in sys.argv[2:]:
    text = Path(src).read_text(encoding="utf-8", errors="surrogateescape")
    def _inst(m):
        probe = PROBES.get(int(m.group(2), 16))
        extra = (" DAH2_FNT_PROBE(0x%s, %s);" % (m.group(2), probe)) if probe else ""
        if int(m.group(2), 16) in NOTE_HOOKS:
            extra += " if (g_fnt_on) { " + NOTE_HOOKS[int(m.group(2), 16)] + " }"
        if int(m.group(2), 16) in SAP_HOOKS:
            extra += " if (g_fnt_on) dah2_sap(0x%s, g_ecx, MEM32(g_esp + 4), MEM32(g_esp + 8), MEM32(g_esp + 12));" % m.group(2)
        fa = m.group(2)
        head = m.group(1)
        if REGCHK_ON:
            head = ("void sub_%s_inner(void);" % fa + chr(10) + "void sub_%s(void)" % fa + chr(10) +
                    "{ uint32_t _rs = g_esi, _rd = g_edi, _rb = g_ebx, _re = g_esp; sub_%s_inner(); DAH2_REGCHK(0x%s, _rs, _rd, _rb); if (g_fnt_on) dah2_espchk(0x%s, _re, g_esp); }" % (fa, fa, fa) + chr(10) +
                    "void sub_%s_inner(void)" % fa + chr(10) + "{")
        return head + " DAH2_FNT(0x%s);" % m.group(2) + extra
    text, n = pat.subn(_inst, text)
    for _a in RET_PROBES:
        _hdr = "void sub_%08X(void)" % _a + chr(10) + "{"
        if _hdr in text and "void sub_%08X_inner(void)" % _a not in text:
            text = text.replace(_hdr, "void sub_%08X_inner(void);" % _a + chr(10) + "void sub_%08X(void)" % _a + chr(10) +
                                "{ sub_%08X_inner(); DAH2_FNT_PROBE(0x%08Xu, g_eax, g_esp, g_ecx, 1); }" % (_a, _a | 0x80000000) +
                                chr(10) + "void sub_%08X_inner(void)" % _a + chr(10) + "{", 1)
    # guest heap shadow checker: wrap the pool allocator's alloc (0x13F390) and free (0x13FFC0)
    for _a, _pre, _post in ((0x0013F390, "uint32_t _a1 = MEM32(g_esp + 4), _a2 = MEM32(g_esp + 8), _ra = MEM32(g_esp); if (_ra == 0x000F96D3u) _ra = MEM32(g_esp + 12);", "dah2_heap_alloc(g_eax, _a1, _a2, _ra);"),
                            (0x0013FFC0, "uint32_t _fp = MEM32(g_esp + 4), _fq = _fp, _fh = 0, _fb = 0; if (_fp >= 0x80000000u && _fp < 0x90000000u) { while (MEM32(_fq - 4u) == 0xFFFFFFFFu) _fq -= 4u; _fh = _fq - 0xCu; _fb = MEM32(_fh + 4u); } dah2_heap_free(MEM32(g_esp + 4), MEM32(g_esp));", "dah2_alloc_caller(0x20000001u, 0, 0); if (_fp >= 0x80000000u && _fp < 0x90000000u) dah2_alloc_caller(0x20000002u, 0, 0); if (_fh) dah2_alloc_caller(0x20000003u, 0, 0); if ((_fb & ~1u) >= 150000u) dah2_alloc_caller(0x20000004u, 0, 0);"),
                            (0x001A7680, "uint32_t _a1 = MEM32(g_esp + 4), _a2 = 0, _ra = MEM32(g_esp);", "dah2_sheap_alloc(g_eax, _a1, _ra);"),
                            (0x001A76E0, "dah2_sheap_free(MEM32(g_esp + 4), MEM32(g_esp));", ""),
                            (0x000F96E0, "uint32_t _fp = MEM32(g_esp + 4), _fq = _fp, _fh = 0, _fb = 0; if (_fp >= 0x80000000u && _fp < 0x90000000u) { while (MEM32(_fq - 4u) == 0xFFFFFFFFu) _fq -= 4u; _fh = _fq - 0xCu; _fb = MEM32(_fh + 4u); }", "if (_fh && g_fnt_on) dah2_free_probe(_fp, _fh, _fb, MEM32(_fh + 4u), MEM32(0x30D864u), g_esp);"),
                            (0x001AE2F0, "uint32_t _ct = g_ecx;", "dah2_arena(0, MEM32(_ct + 0x44));"),
                            (0x001AE650, "uint32_t _ct = g_ecx; dah2_arena(1, MEM32(_ct + 0x44));", "")):
        _hdr = "void sub_%08X(void)" % _a + chr(10) + "{"
        if _hdr in text and "void sub_%08X_hinner(void)" % _a not in text:
            text = text.replace(_hdr, "void sub_%08X_hinner(void);" % _a + chr(10) + "extern void dah2_heap_alloc(uint32_t, uint32_t, uint32_t, uint32_t); extern void dah2_heap_free(uint32_t, uint32_t); extern void dah2_sheap_alloc(uint32_t, uint32_t, uint32_t); extern void dah2_sheap_free(uint32_t, uint32_t);" + chr(10) +
                                "void sub_%08X(void)" % _a + chr(10) + "{ %s sub_%08X_hinner(); %s }" % (_pre, _a, _post) +
                                chr(10) + "void sub_%08X_hinner(void)" % _a + chr(10) + "{", 1)
    for _a in PATH_FUNCS:
        _hdr = "void sub_%08X_inner(void)" % _a + chr(10) + "{"
        _i = text.find(_hdr)
        if _i >= 0:
            _j = text.find(chr(10) + "}" + chr(10), _i)
            _body = text[_i:_j]
            _body = re.sub(r"^(loc_([0-9A-F]{8})): ;", lambda m: m.group(0) + " dah2_path(0x%sU, g_esp, %s);%s" % (m.group(2), "MEM32(g_esp + 0x20) | (MEM32(g_esp + 0x4C) << 16)" if _a == 0x177FB0 else "0", ((" dah2_note(0x%s, MEM32(g_esp + 0x20), MEM32(g_esp + 0x4C), g_esp);" if m.group(2) in ("0017848F", "00178C56") else " dah2_note(0x%s, g_eax, MEM32(g_esp + 0x2C), g_esp);") % m.group(2) + (" g_fnt_hw_gate = 1; if (g_fnt_hw_auto && !g_fnt_hw_addr) g_fnt_hw_addr = g_esp + g_fnt_hw_auto;" if m.group(2) == "0017848F" else " g_fnt_hw_gate = 0;" if m.group(2) == "00178C56" else "") if (_a == 0x177FB0 and m.group(2) in ESP_NOTE_LABELS) else "")), _body, flags=re.M)
            if _a == 0x177FB0:
                _body = _body.replace("loc_00178490: ;", "loc_00178490: ; dah2_loopchk(MEM32(g_esp + 0x20), MEM32(g_esp + 0x4C), g_esp, 0);", 1)
                _body = _body.replace("loc_0017848F: ;", "loc_0017848F: ; dah2_loopchk(0, 0, 0, 1);", 1)
            text = text[:_i] + _body + text[_j:]
    text, n2 = stub_pat.subn(lambda m: m.group(1) + " DAH2_FNT(0x%s);" % m.group(2), text)
    n += n2
    # recomp_manual.c: log every Lua native-call dispatch (the manual sub_002117C0 wins the link)
    needle = "uint32_t icall_target = *manual_mem32(g_ebx);"
    head = "void sub_002117C0(void)" + chr(10) + "{"
    if needle in text and head in text:
        text = text.replace(needle, needle + " dah2_fnt_log_native(icall_target, g_ebx, g_esp);", 1)
        text = text.replace(head, HELPER + head, 1)
        rneedle = "else { recomp_icall_fail_log(icall_target); g_esp = icall_esp; g_eax = 0; }"
        if rneedle in text:
            text = text.replace(rneedle, rneedle + " dah2_fnt_log_result(g_eax, protect_esi);", 1)
    fetch = ("    eax = MEM32(esp + 0x10);" + chr(10) + "    esi = MEM32(eax);" + chr(10) +
             "    eax = eax + 4;" + chr(10) + "    MEM32(esp + 0x10) = eax;" + chr(10))
    first = text.find(fetch)
    if first >= 0:
        # the first fetch block in recomp_0013.c is the inline VM loop (sub_00218D70), where ebp is the VM stack top
        text = text.replace(fetch, fetch + "    DAH2_FNT_VMOP(eax - 4u, esi);" + chr(10))
        if "sub_00218D70" in text[:first + 1] or True:
            text = text.replace("    DAH2_FNT_VMOP(eax - 4u, esi);" + chr(10), "    DAH2_FNT_VMOP_TOP(eax - 4u, esi, ebp);" + chr(10), 1) if "void sub_00218D70" in text else text
    text = '#include "dah2_fn_trace.h"\n' + text
    dst = out / Path(src).name
    old = dst.read_text(encoding="utf-8", errors="surrogateescape") if dst.exists() else None
    if old != text:
        dst.write_text(text, encoding="utf-8", errors="surrogateescape", newline="")
    total += n
print("instrumented %d functions in %d files" % (total, len(sys.argv) - 2))
