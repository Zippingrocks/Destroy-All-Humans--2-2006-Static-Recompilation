#!/bin/bash
# Launch a DAH2_FN_TRACE recomp run with a scripted Start, enable tracing just before it, dump logs.
#   tools/run_fnt_capture.sh NAME [ENABLE_PRESENT=1090] [SETTLE_SECONDS=20]
cd "$(dirname "$0")/.."
NAME=$1; EN=${2:-1090}; SETTLE=${3:-20}
S="${CLAUDE_SCRATCH:-C:/Users/Bilbo/AppData/Local/Temp/claude/D---codex--codex-workspaces-Destroy-All-Huamans--2-2006-Recomp/92b6d49b-7c3c-458b-abe8-2ec7114114e3/scratchpad}"
P="D:\.codex\.codex workspaces\Destroy All Huamans! 2 2006 Recomp"
powershell -NoProfile -ExecutionPolicy Bypass -File "$S/k107_run.ps1" -Name "$NAME" -BuildDir build-fnt -EnvPairs "DAH2_INPUT_SCRIPT=$P\tools\dah2_title_start_1100_hold10_input.txt;DAH2_FILE_OPEN_DIAGNOSTIC=1" -Detach > "$S/${NAME}_launch.txt" 2>&1
PID=$(grep -o 'child=[0-9]*' "$S/${NAME}_launch.txt" | cut -d= -f2); R=diagnostics/codex_parity_20260925/recomp_runs/$NAME
echo "pid $PID"; sleep 10
python - <<PY
import struct,sys,time,pathlib
sys.path.insert(0,'tools')
from read_parity_state_ring import Reader, symbol_rva
m=pathlib.Path('$R/dah2_recomp.map'); r=Reader($PID,suspend=False)
cnt=r.base+symbol_rva(m,'g_dah2_present_timing_samples')
while struct.unpack('<Q',r.read(cnt,8))[0]<$EN: time.sleep(0.01)
PY
python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_on 1
sleep $SETTLE
python tools/dump_fn_nat.py --pid $PID --map $R/dah2_recomp.map --out $R/nat.json
python tools/dump_fn_trace.py --pid $PID --map $R/dah2_recomp.map --out $R/fnt.json
echo "$PID" > $R/pid.txt
