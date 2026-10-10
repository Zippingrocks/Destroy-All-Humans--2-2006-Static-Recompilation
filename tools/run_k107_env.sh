#!/bin/bash
# Normal build, title Start + skip input, with extra env pairs (semicolon separated) appended.
#   tools/run_k107_env.sh NAME WAIT_SECONDS "A=1;B=2" [CAPTURE=1500,2000] [BUILD_DIR=build-kernel107]
cd "$(dirname "$0")/.."
NAME=$1; WAIT=${2:-120}; EXTRA=${3:-}; CAP=${4:-}; BD=${5:-build-kernel107}
S="${CLAUDE_SCRATCH:-C:/Users/Bilbo/AppData/Local/Temp/claude/D---codex--codex-workspaces-Destroy-All-Huamans--2-2006-Recomp/92b6d49b-7c3c-458b-abe8-2ec7114114e3/scratchpad}"
P="D:\.codex\.codex workspaces\Destroy All Huamans! 2 2006 Recomp"
CAPARG=""; [ -n "$CAP" ] && CAPARG="-Capture $CAP"
powershell -NoProfile -ExecutionPolicy Bypass -File "$S/k107_run.ps1" -Name "$NAME" -BuildDir $BD $CAPARG -EnvPairs "DAH2_INPUT_SCRIPT=${P}\\tools\\${INPUT_FILE:-dah2_title_start_skip_input.txt};DAH2_FILE_OPEN_DIAGNOSTIC=1;DAH2_CRASH_HOLD=1;$EXTRA" -Detach > "$S/${NAME}_launch.txt" 2>&1
PID=$(grep -o 'child=[0-9]*' "$S/${NAME}_launch.txt" | cut -d= -f2)
echo "pid $PID"; echo $PID > diagnostics/codex_parity_20260925/recomp_runs/$NAME/pid.txt
sleep $WAIT
