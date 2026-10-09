#!/bin/bash
# Launch the normal build idle at the title with an empty input script; hidden window.
#   tools/run_k107_idle.sh NAME [WAIT_SECONDS=120] [CAPTURE=1500,2000,3000] [BUILD_DIR=build-kernel107]
cd "$(dirname "$0")/.."
NAME=$1; WAIT=${2:-120}; CAP=${3:-}; BD=${4:-build-kernel107}
S="${CLAUDE_SCRATCH:-C:/Users/Bilbo/AppData/Local/Temp/claude/D---codex--codex-workspaces-Destroy-All-Huamans--2-2006-Recomp/92b6d49b-7c3c-458b-abe8-2ec7114114e3/scratchpad}"
P="D:\.codex\.codex workspaces\Destroy All Huamans! 2 2006 Recomp"
CAPARG=""; [ -n "$CAP" ] && CAPARG="-Capture $CAP"
powershell -NoProfile -ExecutionPolicy Bypass -File "$S/k107_run.ps1" -Name "$NAME" -BuildDir $BD $CAPARG -EnvPairs "DAH2_INPUT_SCRIPT=$P\tools\dah2_title_idle_input.txt;DAH2_FILE_OPEN_DIAGNOSTIC=1;DAH2_CRASH_HOLD=1" -Detach > "$S/${NAME}_launch.txt" 2>&1
PID=$(grep -o 'child=[0-9]*' "$S/${NAME}_launch.txt" | cut -d= -f2)
echo "pid $PID"; echo $PID > diagnostics/codex_parity_20260925/recomp_runs/$NAME/pid.txt
sleep $WAIT
R=diagnostics/codex_parity_20260925/recomp_runs/$NAME
grep -n "CRASH" $R/stdout.log | head -3
tail -3 $R/dah2_file_open_trace.log | sed 's/host=.*//'
