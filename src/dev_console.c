#include "dev_console.h"

#include <stdio.h>
#include <string.h>

#define DAH2_CONSOLE_CLASS "DAH2DeveloperConsole"
#define DAH2_CONSOLE_LINES 128
#define DAH2_CONSOLE_LINE_LENGTH 192
#define DAH2_CONSOLE_COMMAND_LENGTH 160

static HWND g_console_parent;
static HWND g_console_window;
static HFONT g_console_font;

typedef struct Dah2ConsoleFontProfile {
    const char *name;
    const char *description;
    const char *face;
    int height;
    int weight;
    BYTE pitch;
} Dah2ConsoleFontProfile;

static const Dah2ConsoleFontProfile g_console_font_profiles[] = {
    { "shell", "DAH2 shell/menu - condensed retro display", "Agency FB", -19, FW_BOLD, VARIABLE_PITCH | FF_SWISS },
    { "hud", "DAH2 HUD - compact technical lettering", "Bahnschrift SemiCondensed", -17, FW_SEMIBOLD, VARIABLE_PITCH | FF_SWISS },
    { "subtitle", "DAH2 dialogue/subtitle - clean narrow text", "Arial Narrow", -18, FW_SEMIBOLD, VARIABLE_PITCH | FF_SWISS },
    { "mono", "Doom-style developer console - fixed width", "Consolas", -17, FW_SEMIBOLD, FIXED_PITCH | FF_MODERN },
};
static unsigned g_console_font_profile;
static CRITICAL_SECTION g_console_lock;
static volatile LONG g_console_open;
static BOOL g_console_initialized;
static char g_console_lines[DAH2_CONSOLE_LINES][DAH2_CONSOLE_LINE_LENGTH];
static unsigned g_console_line_sequence;
static char g_console_command[DAH2_CONSOLE_COMMAND_LENGTH];
static unsigned g_console_command_length;
static char g_console_history[DAH2_CONSOLE_COMMAND_LENGTH];

static void console_invalidate(void)
{
    if (g_console_window && IsWindow(g_console_window))
        InvalidateRect(g_console_window, NULL, FALSE);
}

static void console_apply_font(unsigned profile)
{
    const Dah2ConsoleFontProfile *choice;
    HFONT replacement;

    if (profile >= ARRAYSIZE(g_console_font_profiles))
        return;
    choice = &g_console_font_profiles[profile];
    replacement = CreateFontA(choice->height, 0, 0, 0, choice->weight,
        FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, choice->pitch, choice->face);
    if (!replacement)
        return;
    if (g_console_font)
        DeleteObject(g_console_font);
    g_console_font = replacement;
    g_console_font_profile = profile;
    console_invalidate();
}

static void console_list_fonts(void)
{
    char line[DAH2_CONSOLE_LINE_LENGTH];
    dah2_console_log("font profiles (retail Xbox glyphs are packed bitmap resources):");
    for (unsigned i = 0; i < ARRAYSIZE(g_console_font_profiles); ++i) {
        const Dah2ConsoleFontProfile *profile = &g_console_font_profiles[i];
        snprintf(line, sizeof(line), "  %c %-8s %s",
                 i == g_console_font_profile ? '*' : ' ',
                 profile->name, profile->description);
        dah2_console_log(line);
    }
    dah2_console_log("usage: font <shell|hud|subtitle|mono>");
}

static BOOL console_select_font(const char *name)
{
    char line[DAH2_CONSOLE_LINE_LENGTH];
    for (unsigned i = 0; i < ARRAYSIZE(g_console_font_profiles); ++i) {
        if (_stricmp(name, g_console_font_profiles[i].name) == 0) {
            console_apply_font(i);
            snprintf(line, sizeof(line), "console font: %s - %s",
                     g_console_font_profiles[i].name,
                     g_console_font_profiles[i].description);
            dah2_console_log(line);
            return TRUE;
        }
    }
    dah2_console_log("unknown font profile; type 'font list'");
    return FALSE;
}
static void console_append_line_locked(const char *begin, size_t length)
{
    unsigned slot = g_console_line_sequence++ % DAH2_CONSOLE_LINES;
    if (length >= DAH2_CONSOLE_LINE_LENGTH)
        length = DAH2_CONSOLE_LINE_LENGTH - 1u;
    memcpy(g_console_lines[slot], begin, length);
    g_console_lines[slot][length] = 0;
}

void dah2_console_log(const char *text)
{
    const char *line;
    const char *cursor;

    if (!g_console_initialized || !text)
        return;
    EnterCriticalSection(&g_console_lock);
    line = cursor = text;
    for (;;) {
        if (*cursor == '\n' || *cursor == 0) {
            size_t length = (size_t)(cursor - line);
            if (length && line[length - 1u] == '\r')
                --length;
            console_append_line_locked(line, length);
            if (!*cursor)
                break;
            line = cursor + 1;
        }
        ++cursor;
    }
    LeaveCriticalSection(&g_console_lock);
    console_invalidate();
}

static void console_clear(void)
{
    EnterCriticalSection(&g_console_lock);
    memset(g_console_lines, 0, sizeof(g_console_lines));
    g_console_line_sequence = 0;
    LeaveCriticalSection(&g_console_lock);
    console_invalidate();
}

static void console_execute(void)
{
    char command[DAH2_CONSOLE_COMMAND_LENGTH];
    char display[DAH2_CONSOLE_COMMAND_LENGTH + 4];

    memcpy(command, g_console_command, g_console_command_length);
    command[g_console_command_length] = 0;
    while (g_console_command_length &&
           (command[g_console_command_length - 1u] == ' ' ||
            command[g_console_command_length - 1u] == '\t'))
        command[--g_console_command_length] = 0;
    snprintf(display, sizeof(display), "]%s", command);
    dah2_console_log(display);
    if (g_console_command_length)
        snprintf(g_console_history, sizeof(g_console_history), "%s", command);

    if (!command[0]) {
        /* Empty command: only echo the prompt. */
    } else if (_stricmp(command, "help") == 0 || _stricmp(command, "cmdlist") == 0) {
        dah2_console_log("commands: help, clear, version, font, echo <text>, quit");
        dah2_console_log("` toggles the console; Esc closes it without quitting the game");
    } else if (_stricmp(command, "font") == 0 || _stricmp(command, "font list") == 0) {
        console_list_fonts();
    } else if (_strnicmp(command, "font ", 5) == 0) {
        console_select_font(command + 5);
    } else if (_stricmp(command, "clear") == 0) {
        console_clear();
    } else if (_stricmp(command, "version") == 0) {
        dah2_console_log("Destroy All Humans! 2 static recompilation");
        dah2_console_log("developer console build " __DATE__ " " __TIME__);
    } else if (_strnicmp(command, "echo ", 5) == 0) {
        dah2_console_log(command + 5);
    } else if (_stricmp(command, "quit") == 0 || _stricmp(command, "exit") == 0) {
        PostMessageA(g_console_parent, WM_CLOSE, 0, 0);
    } else {
        snprintf(display, sizeof(display), "unknown command: %s", command);
        dah2_console_log(display);
        dah2_console_log("type 'help' for available commands");
    }
    g_console_command[0] = 0;
    g_console_command_length = 0;
    console_invalidate();
}

static void console_paint(HWND hwnd)
{
    PAINTSTRUCT paint;
    RECT client;
    HDC dc = BeginPaint(hwnd, &paint);
    HBRUSH background = CreateSolidBrush(RGB(0, 0, 0));
    HPEN divider = CreatePen(PS_SOLID, 1, RGB(0, 235, 235));
    HGDIOBJ old_pen;
    int line_height;
    int prompt_y;
    int visible_lines;
    unsigned available;
    char prompt[DAH2_CONSOLE_COMMAND_LENGTH + 4];
    char version[96];

    GetClientRect(hwnd, &client);
    FillRect(dc, &client, background);
    DeleteObject(background);
    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, g_console_font ? g_console_font : GetStockObject(ANSI_FIXED_FONT));
    {
        TEXTMETRICA metrics;
        GetTextMetricsA(dc, &metrics);
        line_height = metrics.tmHeight + metrics.tmExternalLeading + 2;
        if (line_height < 16)
            line_height = 16;
    }
    prompt_y = client.bottom - line_height - 6;
    old_pen = SelectObject(dc, divider);
    MoveToEx(dc, 0, prompt_y - 5, NULL);
    LineTo(dc, client.right, prompt_y - 5);
    SelectObject(dc, old_pen);
    DeleteObject(divider);

    EnterCriticalSection(&g_console_lock);
    available = g_console_line_sequence < DAH2_CONSOLE_LINES
              ? g_console_line_sequence : DAH2_CONSOLE_LINES;
    visible_lines = (prompt_y - 10) / line_height;
    if ((unsigned)visible_lines > available)
        visible_lines = (int)available;
    SetTextColor(dc, RGB(0, 235, 235));
    for (int row = 0; row < visible_lines; ++row) {
        unsigned sequence = g_console_line_sequence - (unsigned)visible_lines + (unsigned)row;
        const char *line = g_console_lines[sequence % DAH2_CONSOLE_LINES];
        TextOutA(dc, 10, 7 + row * line_height, line, (int)strlen(line));
    }
    snprintf(prompt, sizeof(prompt), "]%s_", g_console_command);
    TextOutA(dc, 10, prompt_y, prompt, (int)strlen(prompt));
    LeaveCriticalSection(&g_console_lock);

    snprintf(version, sizeof(version), "DAH2 RECOMP  %s", __DATE__);
    SetTextColor(dc, RGB(0, 235, 235));
    SetTextAlign(dc, TA_RIGHT | TA_TOP);
    TextOutA(dc, client.right - 10, prompt_y, version, (int)strlen(version));
    SetTextAlign(dc, TA_LEFT | TA_TOP);
    EndPaint(hwnd, &paint);
}

static LRESULT CALLBACK console_wndproc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp)
{
    switch (message) {
    case WM_GETDLGCODE:
        return DLGC_WANTALLKEYS | DLGC_WANTCHARS;
    case WM_KEYDOWN:
        if (wp == VK_OEM_3 && !(lp & (1u << 30))) {
            dah2_console_toggle();
            return 0;
        }
        if (wp == VK_ESCAPE) {
            if (InterlockedCompareExchange(&g_console_open, 0, 0))
                dah2_console_toggle();
            return 0;
        }
        if (wp == VK_RETURN) {
            console_execute();
            return 0;
        }
        if (wp == VK_BACK) {
            if (g_console_command_length)
                g_console_command[--g_console_command_length] = 0;
            console_invalidate();
            return 0;
        }
        if (wp == VK_UP && g_console_history[0]) {
            snprintf(g_console_command, sizeof(g_console_command), "%s", g_console_history);
            g_console_command_length = (unsigned)strlen(g_console_command);
            console_invalidate();
            return 0;
        }
        break;
    case WM_CHAR:
        if (wp >= 32u && wp < 127u && wp != '`' && wp != '~' &&
            g_console_command_length + 1u < sizeof(g_console_command)) {
            g_console_command[g_console_command_length++] = (char)wp;
            g_console_command[g_console_command_length] = 0;
            console_invalidate();
        }
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        console_paint(hwnd);
        return 0;
    default:
        return DefWindowProcA(hwnd, message, wp, lp);
    }
    return 0;
}

void dah2_console_parent_resized(void)
{
    RECT client;
    int height;
    if (!g_console_parent || !g_console_window)
        return;
    GetClientRect(g_console_parent, &client);
    height = (client.bottom - client.top) / 2;
    if (height < 180)
        height = 180;
    if (height > client.bottom)
        height = client.bottom;
    SetWindowPos(g_console_window, HWND_TOP, 0, 0, client.right, height,
                 SWP_NOACTIVATE | SWP_NOOWNERZORDER);
}

BOOL dah2_console_initialize(HWND parent, HINSTANCE instance)
{
    WNDCLASSEXA window_class = { sizeof(window_class) };
    if (g_console_initialized)
        return g_console_window != NULL;
    InitializeCriticalSection(&g_console_lock);
    g_console_initialized = TRUE;
    g_console_parent = parent;
    window_class.lpfnWndProc = console_wndproc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursor(NULL, IDC_IBEAM);
    window_class.lpszClassName = DAH2_CONSOLE_CLASS;
    window_class.hbrBackground = NULL;
    RegisterClassExA(&window_class);
    g_console_window = CreateWindowExA(WS_EX_LAYERED, DAH2_CONSOLE_CLASS, "",
        WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 1, 1, parent, NULL, instance, NULL);
    if (!g_console_window) {
        g_console_parent = NULL;
        g_console_initialized = FALSE;
        DeleteCriticalSection(&g_console_lock);
        return FALSE;
    }
    SetLayeredWindowAttributes(g_console_window, 0, 230, LWA_ALPHA);
    console_apply_font(0);
    dah2_console_parent_resized();
    dah2_console_log("Destroy All Humans! 2 static recompilation");
    dah2_console_log("developer console initialized");
    dah2_console_log("type 'help' for commands; 'font list' selects a DAH2 UI profile");
    dah2_console_log("press ` to close the console");
    return TRUE;
}

void dah2_console_toggle(void)
{
    BOOL open;
    if (!g_console_window)
        return;
    open = InterlockedCompareExchange(&g_console_open, 0, 0) == 0;
    InterlockedExchange(&g_console_open, open ? 1 : 0);
    if (open) {
        dah2_console_parent_resized();
        ShowWindow(g_console_window, SW_SHOW);
        SetWindowPos(g_console_window, HWND_TOP, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetFocus(g_console_window);
        console_invalidate();
    } else {
        ShowWindow(g_console_window, SW_HIDE);
        SetFocus(g_console_parent);
    }
}

BOOL dah2_console_is_open(void)
{
    return InterlockedCompareExchange(&g_console_open, 0, 0) != 0;
}

void dah2_console_shutdown(void)
{
    InterlockedExchange(&g_console_open, 0);
    if (g_console_window && IsWindow(g_console_window))
        DestroyWindow(g_console_window);
    g_console_window = NULL;
    g_console_parent = NULL;
    if (g_console_font) {
        DeleteObject(g_console_font);
        g_console_font = NULL;
    }
    if (g_console_initialized) {
        DeleteCriticalSection(&g_console_lock);
        g_console_initialized = FALSE;
    }
    memset(g_console_lines, 0, sizeof(g_console_lines));
    g_console_line_sequence = 0;
    g_console_command[0] = 0;
    g_console_command_length = 0;
    g_console_history[0] = 0;
    g_console_font_profile = 0;
}
