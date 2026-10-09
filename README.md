# Destroy All Humans! 2 — Windows Static Recompilation

This workspace contains an early native Windows static-recompilation bring-up
for the original Xbox release of *Destroy All Humans! 2* (title ID
`0x54510106`). The current milestone is a PC bring-up shell around the
recompiled title initialization; it is not yet a complete playable retail port.

## Current milestone

- The retail `default.xbe` has been validated and its 28 sections load into the
  recompiled Xbox memory map.
- 15,058 functions were discovered and 14,336 native C functions generated.
- The native present loop runs and advances through the retail title-state
  path; this does not yet establish a stable animated frontend.
- Runtime behavior is being compared against an isolated xemu instance using
  matched memory checkpoints, call traces, frame timing, and framebuffer
  captures.
- Native captures now show retail Crypto/Natalia geometry, the title logo,
  and the Press Start prompt. Fire is still missing. A Start transition can
  leave the last scene frozen while presents continue; a three-minute live
  main menu at 30 fps and exact xemu pixel/phase/timing parity are not achieved.

This is an active bring-up project, not a finished or playable port. Remaining
work includes ABI recovery in translated call chains, unresolved call targets,
kernel behavior, and NV2A rendering parity.

## Generate sources locally

Use Python 3 with Capstone (`python -m pip install capstone`) and a legally
owned `game_files/default.xbe`. From a fresh checkout, run:

```powershell
Push-Location xboxrecomp
python -m tools.disasm ../game_files/default.xbe --seed-functions ../seeds/manual_functions.json
python -m tools.func_id ../game_files/default.xbe
python -m tools.disasm ../game_files/default.xbe --seed-functions ../seeds/manual_functions.json --seed-functions tools/func_id/output/identified_functions.json
python -m tools.func_id ../game_files/default.xbe
python -m tools.abi_analysis ../game_files/default.xbe
python -m tools.recomp ../game_files/default.xbe --all --include-owned --function-extents ../seeds/verified_function_extents.json --exclude-manual ../src/recomp_manual.c --split 1000 --gen-dir ../src/recomp/gen
Pop-Location
```

The explicit extent manifest restores the verified retail pool allocator
`12FFB0..1301DA`, quad generator `179240..1799C2`, audio activity helper
`1AB6A0..1AB75A`, streaming constructor `1AE2F0..1AE48E`, and object-vector
cleanup `11A340..11A3B3`, and script-record constructor `110790..1108F5`
(exclusive ends).
Generation refuses a different XBE revision, changed function bytes, or invalid
instruction/return boundaries. Without `--function-extents`, the generic
recompiler remains unchanged. The manifest preserves other metadata and
interior entry symbols; it does not replace ABI analysis or all bring-up fixes.
Do not regenerate over locally patched generated files: this command replaces
generated source, including any repairs not yet recorded in the pipeline.

After generation, the bounded manifest regression is:

```powershell
python tools/test_verified_function_extents.py
```

It translates only these six functions in memory and compares them with the
verified repaired bodies; it does not launch either game or regenerate the
project.

Audio recovery regressions (modeled external resource/SDK contracts, not playback):

```powershell
python tools/test_audio_pool_update_recovery.py
python tools/test_streaming_voice_constructor_recovery.py
python tools/test_stream_channel_initializer_recovery.py
python tools/test_double_shift_recovery.py
python tools/test_object_vector_cleanup_recovery.py
python tools/test_script_record_constructor_recovery.py
python tools/test_scene_factory_recovery.py
```

The byte-verified stream initializer at `267D4D` and scene factory at `0B3500`
are registered in manual dispatch and discovery seeds. Their native regressions
cover 1,792 stream setup/return cases and all six scene-factory branches,
including unknown hashes, allocation failure, argument order, and RET8.
The double-shift regression compares 223,488 data results with native x86
instructions, including the retail 64-bit helper; it does not certify live flags.

Latest diagnostic run `run735` passed the former audio divide-by-zero crash but
stopped advancing at present 1623 during the Start transition. Its saved semantic
ring contains 1,623 frames. This is not a three-minute menu or a 30 fps result;
`run736` confirmed the same stall after the zero-count shift repair. Bounded
`run737` traces exposed a truncated object-vector cleanup: its empty-vector
branch called an unresolved interior stub instead of restoring the stack and
saved registers. The full retail cleanup passes 1,022 native ABI cases, including
a historical 16-byte-leak mutant. `run738` advanced to frame 1624, then stalled
in a hash lookup. `run739` observed receiver `6` even though the registry global
was a valid pointer. The retail script-record constructor was truncated before
its epilogue; its recovered 357-byte/117-instruction body passes 512 native cases
(empty/skipped/populated records, nested numeric/string paths and RET8). `run740` reached the third frontend transition, where the registry root was null.
A bounded trace proved the actual failure occurred earlier: retail registers the
scene factory at `0B3500`, but it was absent from recomp dispatch. The recovered
314-byte/102-instruction factory restores all six real object constructors and
RET8 behavior. No live-menu or frame-rate pass is claimed until a clean runtime
run verifies this repair.

## Build

From PowerShell, normalize the inherited `Path` variable before invoking CMake
(the Codex desktop environment can expose both `Path` and `PATH` to MSBuild):

```powershell
$savedPath = $env:Path
Remove-Item Env:Path
$env:Path = $savedPath
cmake -S . -B build -A x64
cmake --build build --config Release --parallel 8
```

Generated recompilation files under `src/recomp/gen` are intentionally not
distributed. Generate them locally from a legally owned copy of the game before
configuring the build. Run the resulting executable from the repository root so
`game_files/default.xbe` can be found:

```powershell
.\build\Release\dah2_recomp.exe
```

Only use game data from a copy you legally own. No original game assets should
be distributed with the recompilation project.
