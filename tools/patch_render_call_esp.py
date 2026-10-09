"""Fix the hand-patched `sub_00172590` call site in sub_001732D0 (src/recomp/gen/recomp_0009.c).

An older diagnostic patch wrapped the `call 0x172590` at 0x17347F in a block that saved `esp` AFTER the first argument push and
restored `esp = render_call_sp` after the call.  The callee is `ret 0x10` (pops all four pushed args), so the restore left esp 4
bytes too low on every call: sub_001777C0 / sub_00177FB0 then ran with a shifted frame, [esp+0x20] (the cull loop index) aliased
another local, and the loop ran ~2^31 iterations (2.5 fps).  This rewrites the restore to `render_call_sp + 4` and drops the two
stderr diagnostics.  Idempotent.

  py -3 tools/patch_render_call_esp.py"""
import re
from pathlib import Path
p = Path(__file__).resolve().parent.parent / "src/recomp/gen/recomp_0009.c"
t = p.read_bytes().decode("utf-8", "surrogateescape")
old = "    esp = render_call_sp;\n    esi = render_call_esi;"
new = "    esp = render_call_sp + 4; /* the callee pops its four stack arguments (ret 0x10); render_call_sp was taken after the first push */\n    esi = render_call_esi;"
crlf = "\r\n" in t
if crlf: t = t.replace("\r\n", "\n")
n = t.count(old)
t = t.replace(old, new)
t, k = re.subn(r'    fprintf\(stderr, "\[17348E-CALL\] (?:pre|post)[^;]*;\n', "", t)
t, k2 = re.subn(r"    uint32_t render_object_field = MEM32\(render_call_esi \+ 0x90\);\n", "", t)
if crlf: t = t.replace("\n", "\r\n")
p.write_bytes(t.encode("utf-8", "surrogateescape"))
print("esp restore fixed: %d, diagnostics removed: %d, field read removed: %d" % (n, k, k2))
