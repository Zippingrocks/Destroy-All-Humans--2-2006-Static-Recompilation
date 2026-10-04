from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    header = (ROOT / "src" / "trace_control.h").read_text(encoding="utf-8")
    source = (ROOT / "src" / "trace_control.c").read_text(encoding="utf-8")
    types = (ROOT / "src" / "recomp" / "recomp_types.h").read_text(encoding="utf-8")
    main_c = (ROOT / "src" / "main.c").read_text(encoding="utf-8")
    manual = (ROOT / "src" / "recomp_manual.c").read_text(encoding="utf-8")
    bridge = (ROOT / "src" / "guest_nv2a_bridge.c").read_text(encoding="utf-8")

    assert "extern int g_dah2_verbose_trace;" in header
    assert "g_dah2_verbose_trace ? fprintf" in header
    assert 'getenv("DAH2_VERBOSE_TRACE") != NULL' in source
    assert 'getenv("DAH2_QUIET_TRACE") == NULL' in source
    assert "#define fprintf(stream, ...) DAH2_TRACE_FPRINTF" in types
    assert main_c.index("dah2_trace_initialize();") < main_c.index(
        "if (!g_dah2_verbose_trace"
    )
    ordinary_manual = manual.split("/* DAH2_INPUT_REPLAY_BEGIN", 1)[0] + manual.split(
        "/* DAH2_INPUT_REPLAY_END */", 1
    )[1]
    assert "fprintf(stderr," not in ordinary_manual
    assert "fprintf(stderr," not in bridge
    assert "if (g_dah2_verbose_trace)" in bridge


if __name__ == "__main__":
    main()
