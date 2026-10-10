#!/bin/bash
# Launch a DAH2_FN_TRACE run with Start at the title and a second Start during the intro movie.
#   tools/run_fnt_skip.sh NAME [WAIT_SECONDS=150] [CAPTURE=2400,3300,4800]
cd "$(dirname "$0")/.."
NAME=$1; WAIT=${2:-150}; CAP=${3:-}; EN=${ENABLE_AT:-1090}
S="${CLAUDE_SCRATCH:-C:/Users/Bilbo/AppData/Local/Temp/claude/D---codex--codex-workspaces-Destroy-All-Huamans--2-2006-Recomp/92b6d49b-7c3c-458b-abe8-2ec7114114e3/scratchpad}"
P="D:\.codex\.codex workspaces\Destroy All Huamans! 2 2006 Recomp"
CAPARG=""; [ -n "$CAP" ] && CAPARG="-Capture $CAP"
powershell -NoProfile -ExecutionPolicy Bypass -File "$S/k107_run.ps1" -Name "$NAME" -BuildDir build-fnt $CAPARG -EnvPairs "DAH2_INPUT_SCRIPT=$P\tools\dah2_title_start_skip_input.txt;DAH2_FILE_OPEN_DIAGNOSTIC=1;DAH2_CRASH_HOLD=1;$EXTRA_ENV" -Detach > "$S/${NAME}_launch.txt" 2>&1
PID=$(grep -o 'child=[0-9]*' "$S/${NAME}_launch.txt" | cut -d= -f2); R=diagnostics/codex_parity_20260925/recomp_runs/$NAME
echo "pid $PID" ; echo $PID > $R/pid.txt
sleep 10
python - <<PY
import struct,sys,time,pathlib
sys.path.insert(0,'tools')
from read_parity_state_ring import Reader, symbol_rva
m=pathlib.Path('$R/dah2_recomp.map'); r=Reader($PID,suspend=False)
cnt=r.base+symbol_rva(m,'g_dah2_present_timing_samples')
while struct.unpack("<Q",r.read(cnt,8))[0]<$EN: time.sleep(0.01)
PY
python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_on 1
for kv in $FNT_WRITES; do python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map ${kv%%=*} ${kv#*=}; done
if [ -n "$FREEZE" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_loop_freeze 1; fi
if [ -n "$PROBE_BOOT" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_probe_boot 1; fi
if [ -n "$WLO" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_wlo $WLO; python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_whi $WHI; fi
if [ -n "$PROBE_LO" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_probe_lo $PROBE_LO; python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_probe_hi $PROBE_HI; fi
if [ -n "$HW_MIN" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_hw_min $HW_MIN; fi
if [ -n "$HW_AUTO" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_hw_auto $HW_AUTO; fi
if [ -n "$HW_LEN" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_hw_len $HW_LEN; fi
if [ -n "$HW_ADDR" ] && [ -n "$HW_WAIT_NAT" ]; then python - <<PY
import struct,sys,time,pathlib
sys.path.insert(0,'tools')
from read_parity_state_ring import Reader, symbol_rva
m=pathlib.Path('$R/dah2_recomp.map'); r=Reader($PID,suspend=False)
nat=r.base+symbol_rva(m,'g_fnt_nat_idx')
while struct.unpack("<I",r.read(nat,4))[0]<$HW_WAIT_NAT: time.sleep(0.005)
PY
fi
if [ -n "$HW_ADDR" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_hw_addr $HW_ADDR; fi
if [ -n "$WATCH_LO" ]; then python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_watch_lo $WATCH_LO; python tools/write_global32.py --pid $PID --map $R/dah2_recomp.map g_fnt_watch_hi $WATCH_HI; fi
sleep $WAIT
grep -n "CRASH" $R/stdout.log | head -3
tail -4 $R/dah2_file_open_trace.log | sed 's/host=.*//'
