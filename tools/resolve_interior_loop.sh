#!/bin/bash
# Rebuild; for every unresolved sub_XXXXXXXX the link reports, add a stub and lift it as a real function
# into the next unused src/recomp/gen/recomp_interior_entries_N.c.  Stops on compile errors.
cd "$(dirname "$0")/.."
BUILD=${1:-build-fnt}
S="${CLAUDE_SCRATCH:-C:/Users/Bilbo/AppData/Local/Temp/claude/D---codex--codex-workspaces-Destroy-All-Huamans--2-2006-Recomp/92b6d49b-7c3c-458b-abe8-2ec7114114e3/scratchpad}"
for pass in 1 2 3 4 5 6 7 8; do
  cmake -S . -B $BUILD >/dev/null 2>&1
  cmake --build $BUILD --config Release --parallel 6 --target dah2_recomp > "$S/loop_$pass.log" 2>&1
  if grep -qE "error C[0-9]+" "$S/loop_$pass.log"; then
    echo "compile errors in pass $pass:"; grep -E "error C[0-9]+" "$S/loop_$pass.log" | sed 's/\[D:.*//' | sort -u | head -8 | cut -c1-240; exit 2
  fi
  if ! grep -qE "error LNK" "$S/loop_$pass.log"; then echo "build ok after pass $pass"; exit 0; fi
  N=2; while [ -e "src/recomp/gen/recomp_interior_entries_$N.c" ]; do N=$((N+1)); done
  python - <<PY
import re
syms=sorted(set(re.findall(r'unresolved external symbol (sub_[0-9A-F]{8})',open(r'$S/loop_$pass.log').read())))
print('pass $pass: %d unresolved -> recomp_interior_entries_$N.c'%len(syms))
if not syms: raise SystemExit(3)
f='src/recomp/gen/recomp_extent_stubs.c'
t=open(f,newline='').read()
for s in syms:
    if ('void %s(void)'%s) not in t: t+='void %s(void) { g_esp += 4; /* 0x%s: interior branch target */ }\n'%(s,s[4:])
open(f,'w',newline='').write(t)
PY
  python tools/lift_interior_entries.py --apply --out recomp_interior_entries_$N.c | tail -2
done
echo "did not converge"; exit 1
