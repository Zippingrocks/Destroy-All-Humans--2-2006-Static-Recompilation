from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PGRAPH = (ROOT / "xboxrecomp/src/nv2a/nv2a_indexed_draw.h").read_text()
BOOT = (ROOT / "src/boot_window.c").read_text()
PARITY = (ROOT / "src/parity_checkpoint.h").read_text()
LAUNCHER = (ROOT / "tools/start_parity_session.ps1").read_text()


assert 'getenv("DAH2_PGRAPH_DIAGNOSTIC")' in PGRAPH
assert "if(pgraph_verbose_diagnostics_enabled() && (front_reports++<8u || isolated_front))" in PGRAPH
assert "if(pgraph_verbose_diagnostics_enabled() && g_pg.stats.frames>=1350" in PGRAPH
assert "if(pgraph_verbose_diagnostics_enabled() && g_pg.stats.frames>=1348" in PGRAPH

assert 'getenv("DAH2_PLACEHOLDER_SHELL")' in BOOT
assert "translated guest output remains authoritative" in BOOT

assert 'GetEnvironmentVariableA("DAH2_DSOUND_TRACE"' in PARITY
assert '_lock_file(stdout)' in PARITY
assert 'GetEnvironmentVariableA("DAH2_PARITY_TRACE"' in PARITY
assert "'DAH2_DSOUND_TRACE'" in LAUNCHER
