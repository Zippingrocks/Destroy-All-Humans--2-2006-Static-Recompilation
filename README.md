# Destroy All Humans! 2 — Windows Static Recompilation

This workspace contains an early native Windows static-recompilation bring-up
for the original Xbox release of *Destroy All Humans! 2* (title ID
`0x54510106`). The current milestone is a PC bring-up shell around the
recompiled title initialization; it is not yet a complete playable retail port.

## Current milestone

- The retail `default.xbe` has been validated and its 28 sections load into the
  recompiled Xbox memory map.
- 15,058 functions were discovered and 14,336 native C functions generated.
- The title now reaches a stable native frame loop and advances through the
  retail title-state path.
- Runtime behavior is being compared against an isolated xemu instance using
  matched memory checkpoints, call traces, frame timing, and framebuffer
  captures.
- The current native framebuffer is still black apart from post-processing;
  the real Crypto/Natalia/fire main-menu geometry is not rendered yet.

This is an active bring-up project, not a finished or playable port. Remaining
work includes ABI recovery in translated call chains, unresolved call targets,
kernel behavior, and NV2A rendering parity.

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
