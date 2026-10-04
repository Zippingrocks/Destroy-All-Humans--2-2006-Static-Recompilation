#pragma once

#include <windows.h>

BOOL dah2_boot_window_start(HINSTANCE instance);
void dah2_boot_window_set_status(const char *status);
HWND dah2_boot_window_get_hwnd(void);
void dah2_boot_window_set_renderer_owned(BOOL owned);
void dah2_boot_window_set_shell_autoplay(BOOL enabled);
BOOL dah2_boot_window_get_shell_autoplay(void);
void dah2_boot_window_set_real_menu_probe(BOOL enabled);
BOOL dah2_boot_window_get_real_menu_probe(void);

/*
 * The retail XBE reaches a finite CRT/thread bootstrap before the missing
 * title loop.  The PC shell keeps the window and pacing alive at that
 * boundary, while still making the state transitions explicit and measurable.
 * MENU, CUTSCENE, and GAMEPLAY are all 30 Hz.
 */
void dah2_pc_shell_run(void);
void dah2_boot_window_stop(void);
