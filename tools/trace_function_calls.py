"""Print a patch adding temporary before/after guest ABI traces to one body."""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
name = 'sub_' + sys.argv[1].upper().zfill(8)
matches = [(p, p.read_text()) for p in (root/'src/recomp/gen').glob('recomp_*.c')
           if re.search(rf'^void {name}\(void\)', p.read_text(), re.M)]
if len(matches) != 1:
    raise ValueError(f'Expected one definition for {name}')
path, source = matches[0]
old = re.search(rf'^void {name}\(void\)\n\{{.*?^\}}', source, re.M | re.S).group()
if '[CALL-ABI]' in old:
    raise ValueError('Already instrumented')
def trace(m):
    addr, call = m.groups()
    return ('    { uint32_t trace_sp = esp, trace_si = esi, trace_di = edi, trace_bx = ebx;\n'
            f'    PUSH32(esp, {addr}); {call}();\n'
            f'    fprintf(stderr, "[CALL-ABI] {name} at {addr} -> {call} sp=%08X->%08X si=%08X->%08X di=%08X->%08X bx=%08X->%08X\\n", trace_sp, esp, trace_si, esi, trace_di, edi, trace_bx, ebx); }}')
new = re.sub(r'    PUSH32\(esp, (0x[0-9A-F]+u)\); (sub_[0-9A-F]+)\(\); /\* call .*? \*/', trace, old)
print('*** Begin Patch\n*** Update File: ' + str(path) + '\n@@')
print('\n'.join('-'+line for line in old.splitlines()))
print('\n'.join('+'+line for line in new.splitlines()))
print('*** End Patch')
