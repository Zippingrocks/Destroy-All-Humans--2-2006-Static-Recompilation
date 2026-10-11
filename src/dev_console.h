#pragma once

#include <windows.h>

BOOL dah2_console_initialize(HWND parent, HINSTANCE instance);
void dah2_console_shutdown(void);
void dah2_console_toggle(void);
BOOL dah2_console_is_open(void);
void dah2_console_parent_resized(void);
void dah2_console_log(const char *text);
