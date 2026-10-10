#!/bin/bash
# Capture the current frame of a running recomp started with DAH2_CAPTURE_TRIGGER=<run dir>\cap.trigger and save it as PNG.
#   tools/grab_frame.sh RUN_NAME OUT_PNG
cd "$(dirname "$0")/.."
R=diagnostics/codex_parity_20260925/recomp_runs/$1
rm -f $R/parity_frame_*.ppm.old; before=$(ls $R/parity_frame_*.ppm 2>/dev/null | wc -l)
: > $R/cap.trigger
for i in $(seq 1 40); do sleep 0.25; n=$(ls $R/parity_frame_*.ppm 2>/dev/null | wc -l); [ "$n" -gt "$before" ] && break; done
f=$(ls -t $R/parity_frame_*.ppm | head -1)
python -c "from PIL import Image; Image.open('$f').save('$2')"
echo "saved $f -> $2"
