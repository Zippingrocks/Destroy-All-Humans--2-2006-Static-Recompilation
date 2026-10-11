"""Source contract for the non-invasive DAH2 developer console."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
window = (ROOT / "src/boot_window.c").read_text(encoding="utf-8")
console = (ROOT / "src/dev_console.c").read_text(encoding="utf-8")
manual = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")

assert "src/dev_console.c" in cmake
assert '#include "dev_console.h"' in window
assert "dah2_console_initialize(g_boot_hwnd, instance);" in window
assert "dah2_console_shutdown();" in window
assert "dah2_console_parent_resized();" in window

# Backtick is edge-triggered in both parent and console windows; key repeat
# must not rapidly open and close the overlay.
toggle_guard = "wp == VK_OEM_3 && !(lp & (1u << 30))"
assert toggle_guard in window
assert toggle_guard in console
assert console.count("dah2_console_toggle();") >= 2

# The overlay remains a child of the renderer-owned window and uses alpha,
# avoiding any writes to the guest backbuffer used for pixel parity.
assert "WS_CHILD | WS_CLIPSIBLINGS" in console
assert "SetLayeredWindowAttributes(g_console_window, 0, 230, LWA_ALPHA);" in console
assert "WS_CLIPCHILDREN" in window

for command in ("help", "clear", "version", "echo ", "quit", "font list"):
    assert command in console

for profile in ("shell", "hud", "subtitle", "mono"):
    assert f'{{ "{profile}"' in console

assert "console_apply_font(0);" in console
metrics = console.index("GetTextMetricsA")
prompt_position = console.index("prompt_y = client.bottom", metrics)
divider_start = console.index("MoveToEx", metrics)
assert metrics < prompt_position < divider_start

assert "GetTextMetricsA" in console

# While typing, neither physical Xbox input nor keyboard-derived input may
# leak through to the retail frontend and stack menus over one another.
suppression = manual.index("if (dah2_console_is_open())")
packet_copy = manual.index("memcpy(state + 4, &buttons", suppression)
assert suppression < packet_copy
neutral = manual[suppression:packet_copy]
assert "buttons = 0;" in neutral
assert "memset(analog, 0, sizeof(analog));" in neutral
assert "memset(stick, 0, sizeof(stick));" in neutral

print("PASS: DAH2 developer console toggle, font profiles, overlay, and input isolation")
