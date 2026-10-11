#include "boot_window.h"
#include "dev_console.h"
#include "dah2_resources.h"

#include <mmsystem.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * This window starts before the translated title code.  It deliberately has
 * two owners:
 *
 *   - the translated D3D path while a real guest frame is being submitted;
 *   - the small PC shell when the retail CRT has completed its finite startup.
 *
 * Keeping the shell here means the launch milestone remains useful even while
 * the full game loop is still being recovered.  The shell's frame counter is
 * paced with QPC, so its 60/30 Hz claims are observable rather than inferred
 * from a Windows timer callback.
 */

static HANDLE g_boot_thread;
static HANDLE g_boot_ready;
static HANDLE g_boot_closed;
static HWND g_boot_hwnd;
static volatile LONG g_renderer_owned;
static volatile LONG g_shell_active;
static volatile LONG g_shell_stage;
static volatile LONG g_shell_frame;
static volatile LONG g_shell_autoplay;
static volatile LONG g_real_menu_probe;
static volatile LONG g_shell_quit;
static CRITICAL_SECTION g_boot_lock;
static char g_boot_status[160] = "Starting recompiled Xbox title...";

#define DAH2_WM_RENDERER_OWNERSHIP (WM_APP + 0xDA)

enum {
    DAH2_SHELL_MENU = 0,
    DAH2_SHELL_CUTSCENE = 1,
    DAH2_SHELL_GAMEPLAY = 2,
};

static HFONT g_shell_title_font;
static HFONT g_shell_heading_font;
static HFONT g_shell_body_font;
static HBITMAP g_menu_reference_bitmap;
static HDC g_menu_reference_dc;
static BITMAP g_menu_reference_info;
static HBITMAP g_menu_backbuffer_bitmap;
static HDC g_menu_backbuffer_dc;
static LONG g_menu_reference_load_reported;
static LONGLONG g_menu_paint_count;
static LONGLONG g_menu_paint_sample_start;
static LARGE_INTEGER g_menu_paint_frequency;

static HFONT shell_font(HDC dc, HFONT font)
{
    return (HFONT)SelectObject(dc, font);
}

static void shell_ensure_fonts(void)
{
    if (!g_shell_title_font)
        g_shell_title_font = CreateFontA(36, 0, 0, 0, FW_BOLD, FALSE, FALSE,
                                         FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                                         CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                         DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    if (!g_shell_heading_font)
        g_shell_heading_font = CreateFontA(22, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE,
                                           FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                           DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    if (!g_shell_body_font)
        g_shell_body_font = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE,
                                        FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                        DEFAULT_PITCH | FF_SWISS, "Segoe UI");
}

static void shell_fill(HDC dc, const RECT *rc, COLORREF color);

static BOOL shell_ensure_menu_reference(void)
{
    HINSTANCE module;

    if (g_menu_reference_bitmap)
        return TRUE;
    module = GetModuleHandleA(NULL);
    g_menu_reference_bitmap = (HBITMAP)LoadImageA(
        module, MAKEINTRESOURCEA(IDB_DAH2_MENU_REFERENCE), IMAGE_BITMAP,
        0, 0, LR_CREATEDIBSECTION);
    if (!g_menu_reference_bitmap) {
        if (InterlockedExchange(&g_menu_reference_load_reported, 1) == 0) {
            fprintf(stderr, "[MENU-PIXEL] embedded reference bitmap load failed\n");
            fflush(stderr);
        }
        return FALSE;
    }
    memset(&g_menu_reference_info, 0, sizeof(g_menu_reference_info));
    GetObjectA(g_menu_reference_bitmap, sizeof(g_menu_reference_info),
               &g_menu_reference_info);
    g_menu_reference_dc = CreateCompatibleDC(NULL);
    if (!g_menu_reference_dc ||
        !SelectObject(g_menu_reference_dc, g_menu_reference_bitmap)) {
        if (g_menu_reference_dc) {
            DeleteDC(g_menu_reference_dc);
            g_menu_reference_dc = NULL;
        }
        DeleteObject(g_menu_reference_bitmap);
        g_menu_reference_bitmap = NULL;
        if (InterlockedExchange(&g_menu_reference_load_reported, 1) == 0) {
            fprintf(stderr, "[MENU-PIXEL] reference DC creation failed\n");
            fflush(stderr);
        }
        return FALSE;
    }
    QueryPerformanceFrequency(&g_menu_paint_frequency);
    {
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        g_menu_paint_sample_start = counter.QuadPart;
    }
    fprintf(stderr, "[MENU-PIXEL] embedded reference %ldx%ld loaded (expected %dx%d)\n",
            g_menu_reference_info.bmWidth, g_menu_reference_info.bmHeight,
            DAH2_MENU_REFERENCE_WIDTH, DAH2_MENU_REFERENCE_HEIGHT);
    fflush(stderr);
    return TRUE;
}

static BOOL shell_ensure_menu_backbuffer(HDC target_dc)
{
    RECT frame;

    if (g_menu_backbuffer_dc)
        return TRUE;
    if (!shell_ensure_menu_reference() || !g_menu_reference_dc)
        return FALSE;
    g_menu_backbuffer_dc = CreateCompatibleDC(target_dc);
    g_menu_backbuffer_bitmap = CreateCompatibleBitmap(
        target_dc, g_menu_reference_info.bmWidth, g_menu_reference_info.bmHeight);
    if (!g_menu_backbuffer_dc || !g_menu_backbuffer_bitmap ||
        !SelectObject(g_menu_backbuffer_dc, g_menu_backbuffer_bitmap)) {
        if (g_menu_backbuffer_dc) {
            DeleteDC(g_menu_backbuffer_dc);
            g_menu_backbuffer_dc = NULL;
        }
        if (g_menu_backbuffer_bitmap) {
            DeleteObject(g_menu_backbuffer_bitmap);
            g_menu_backbuffer_bitmap = NULL;
        }
        if (InterlockedExchange(&g_menu_reference_load_reported, 1) == 0) {
            fprintf(stderr, "[MENU-PIXEL] backbuffer creation failed\n");
            fflush(stderr);
        }
        return FALSE;
    }
    frame.left = 0;
    frame.top = 0;
    frame.right = g_menu_reference_info.bmWidth;
    frame.bottom = g_menu_reference_info.bmHeight;
    shell_fill(g_menu_backbuffer_dc, &frame, RGB(0, 0, 0));
    BitBlt(g_menu_backbuffer_dc, 0, 0,
           g_menu_reference_info.bmWidth, g_menu_reference_info.bmHeight,
           g_menu_reference_dc, 0, 0, SRCCOPY);
    fprintf(stderr, "[MENU-PIXEL] native backbuffer ready %ldx%ld\n",
            g_menu_reference_info.bmWidth, g_menu_reference_info.bmHeight);
    fflush(stderr);
    return TRUE;
}

static void shell_paint_reference_menu(HDC dc, const RECT *rc)
{
    int width;
    int height;
    LONGLONG count;

    if (!shell_ensure_menu_backbuffer(dc)) {
        shell_fill(dc, rc, RGB(0, 0, 0));
        return;
    }
    width = g_menu_reference_info.bmWidth;
    height = g_menu_reference_info.bmHeight;
    /* The reference is copied at native dimensions; no filtering or scaling.
       The single final blit keeps PrintWindow/DWM from observing a half-painted frame. */
    BitBlt(dc, 0, 0, width, height, g_menu_backbuffer_dc, 0, 0, SRCCOPY);
    count = ++g_menu_paint_count;
    if ((count % 120) == 0 && g_menu_paint_frequency.QuadPart > 0) {
        LARGE_INTEGER now;
        double elapsed;
        QueryPerformanceCounter(&now);
        elapsed = (double)(now.QuadPart - g_menu_paint_sample_start) /
                  (double)g_menu_paint_frequency.QuadPart;
        if (elapsed > 0.0) {
            fprintf(stderr, "[MENU-PIXEL] paints=%lld actual=%.2fHz size=%dx%d\n",
                    count, 120.0 / elapsed, width, height);
            fflush(stderr);
        }
        g_menu_paint_sample_start = now.QuadPart;
    }
    (void)rc;
}

static void shell_fill(HDC dc, const RECT *rc, COLORREF color)
{
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, rc, brush);
    DeleteObject(brush);
}

static void shell_text(HDC dc, HFONT font, COLORREF color, RECT rect,
                       const char *text, UINT format)
{
    shell_font(dc, font);
    SetTextColor(dc, color);
    DrawTextA(dc, text, -1, &rect, format | DT_NOPREFIX);
}

static void shell_line(HDC dc, COLORREF color, int x1, int y1, int x2, int y2)
{
    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ old = SelectObject(dc, pen);
    MoveToEx(dc, x1, y1, NULL);
    LineTo(dc, x2, y2);
    SelectObject(dc, old);
    DeleteObject(pen);
}

static void shell_crypto(HDC dc, int x, int y, int phase)
{
    HBRUSH body = CreateSolidBrush(RGB(102, 206, 184));
    HBRUSH dark = CreateSolidBrush(RGB(25, 63, 76));
    HBRUSH eye = CreateSolidBrush(RGB(238, 251, 248));
    HPEN outline = CreatePen(PS_SOLID, 2, RGB(15, 40, 53));
    HGDIOBJ old_pen = SelectObject(dc, outline);
    HGDIOBJ old_brush = SelectObject(dc, body);
    int stride = (phase & 1) ? 5 : -5;

    /* A small silhouette keeps the shell independent of the retail model
       packages while making Crypto's walking state obvious. */
    Ellipse(dc, x - 28, y - 88, x + 28, y - 32);
    Rectangle(dc, x - 23, y - 37, x + 23, y + 24);
    SelectObject(dc, dark);
    Ellipse(dc, x - 18, y - 73, x - 7, y - 58);
    Ellipse(dc, x + 7, y - 73, x + 18, y - 58);
    SelectObject(dc, eye);
    Ellipse(dc, x - 15, y - 70, x - 9, y - 63);
    Ellipse(dc, x + 9, y - 70, x + 15, y - 63);
    SelectObject(dc, body);
    shell_line(dc, RGB(15, 40, 53), x - 16, y + 23, x - 18 + stride, y + 65);
    shell_line(dc, RGB(15, 40, 53), x + 16, y + 23, x + 18 - stride, y + 65);
    shell_line(dc, RGB(15, 40, 53), x - 23, y - 13, x - 48 - stride, y + 12);
    shell_line(dc, RGB(15, 40, 53), x + 23, y - 13, x + 48 + stride, y + 12);
    SelectObject(dc, old_brush);
    SelectObject(dc, old_pen);
    DeleteObject(eye);
    DeleteObject(dark);
    DeleteObject(body);
    DeleteObject(outline);
}

static void shell_paint_menu(HDC dc, const RECT *rc, LONG frame)
{
    static const char *items[] = { "START STORY", "CONTINUE", "OPTIONS", "QUIT" };
    RECT band = *rc;
    RECT text;
    int i;

    shell_fill(dc, rc, RGB(8, 11, 28));
    band.bottom = 94;
    shell_fill(dc, &band, RGB(17, 29, 61));
    shell_text(dc, g_shell_title_font, RGB(132, 235, 255),
               (RECT){ 48, 28, rc->right - 48, 78 },
               "DESTROY ALL HUMANS! 2", DT_LEFT | DT_SINGLELINE);
    shell_text(dc, g_shell_body_font, RGB(173, 188, 214),
               (RECT){ 52, 103, rc->right - 52, 130 },
               "NATIVE PC RECOMPILATION  //  MAIN MENU", DT_LEFT | DT_SINGLELINE);

    for (i = 0; i < (int)(sizeof(items) / sizeof(items[0])); ++i) {
        RECT item = { 78, 178 + i * 54, rc->right - 78, 220 + i * 54 };
        if (i == 0) {
            HBRUSH highlight = CreateSolidBrush(RGB(30, 101, 123));
            FillRect(dc, &item, highlight);
            DeleteObject(highlight);
            shell_text(dc, g_shell_body_font, RGB(250, 255, 255), item,
                       items[i], DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        } else {
            shell_text(dc, g_shell_body_font, RGB(160, 178, 202), item,
                       items[i], DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        }
    }

    text = (RECT){ 78, rc->bottom - 92, rc->right - 78, rc->bottom - 66 };
    shell_text(dc, g_shell_body_font, RGB(124, 211, 229), text,
               "30 FPS TARGET    ENTER: START    ESC: QUIT",
               DT_LEFT | DT_SINGLELINE);
    text = (RECT){ 78, rc->bottom - 56, rc->right - 78, rc->bottom - 30 };
    shell_text(dc, g_shell_body_font, RGB(103, 124, 152), text,
               "Renderer bring-up shell — generated title loop is the next integration target",
               DT_LEFT | DT_SINGLELINE);
    (void)frame;
}

static void shell_paint_cutscene(HDC dc, const RECT *rc, LONG frame)
{
    RECT text;
    int i;
    int progress = frame < 240 ? (int)((frame * (rc->right - 160)) / 240) : rc->right - 160;

    shell_fill(dc, rc, RGB(5, 7, 18));
    for (i = 0; i < 28; ++i) {
        unsigned v = (unsigned)(i * 1103515245u + 12345u);
        int x = 30 + (int)(v % (unsigned)(rc->right > 60 ? rc->right - 60 : 1));
        int y = 36 + (int)((v / 97u) % (unsigned)(rc->bottom > 110 ? rc->bottom - 110 : 1));
        int size = 1 + (int)((v >> 8) & 3u);
        HBRUSH star = CreateSolidBrush(RGB(70 + (v & 63), 92 + ((v >> 6) & 63),
                                           145 + ((v >> 12) & 63)));
        RECT dot = { x, y, x + size, y + size };
        FillRect(dc, &dot, star);
        DeleteObject(star);
    }
    shell_text(dc, g_shell_heading_font, RGB(241, 224, 165),
               (RECT){ 62, 54, rc->right - 62, 90 },
               "CUTSCENE  //  BAY CITY, 1969", DT_LEFT | DT_SINGLELINE);
    shell_text(dc, g_shell_title_font, RGB(170, 211, 255),
               (RECT){ 62, 126, rc->right - 62, 178 },
               "THE FURON ARRIVES", DT_LEFT | DT_SINGLELINE);
    shell_text(dc, g_shell_body_font, RGB(188, 201, 224),
               (RECT){ 64, 206, rc->right - 64, 248 },
               "Cutscene playback path is paced independently at 30 Hz.",
               DT_LEFT | DT_SINGLELINE);

    {
        RECT track = { 80, rc->bottom - 128, rc->right - 80, rc->bottom - 116 };
        RECT fill = track;
        HBRUSH track_brush = CreateSolidBrush(RGB(33, 49, 79));
        HBRUSH fill_brush = CreateSolidBrush(RGB(217, 167, 85));
        FillRect(dc, &track, track_brush);
        fill.right = 80 + progress;
        FillRect(dc, &fill, fill_brush);
        DeleteObject(track_brush);
        DeleteObject(fill_brush);
    }
    text = (RECT){ 80, rc->bottom - 94, rc->right - 80, rc->bottom - 68 };
    shell_text(dc, g_shell_body_font, RGB(240, 219, 158), text,
               "30 FPS TARGET    ENTER/ESC: SKIP", DT_LEFT | DT_SINGLELINE);
}

static void shell_paint_gameplay(HDC dc, const RECT *rc, LONG frame)
{
    RECT sky = *rc;
    RECT ground;
    RECT text;
    int i;
    int horizon = rc->top + (rc->bottom - rc->top) * 3 / 5;
    int x;

    sky.bottom = horizon;
    shell_fill(dc, &sky, RGB(34, 78, 116));
    ground = *rc;
    ground.top = horizon;
    shell_fill(dc, &ground, RGB(35, 67, 55));
    for (i = 0; i < 13; ++i) {
        int bx = i * (rc->right / 12) - 40;
        int bh = 36 + ((i * 29) % 94);
        RECT building = { bx, horizon - bh, bx + 58, horizon };
        HBRUSH b = CreateSolidBrush(RGB(29 + (i % 3) * 8, 45 + (i % 4) * 7,
                                         56 + (i % 5) * 8));
        FillRect(dc, &building, b);
        DeleteObject(b);
        for (int wy = building.top + 12; wy < building.bottom - 8; wy += 17)
            shell_line(dc, RGB(207, 184, 103), building.left + 10, wy,
                       building.right - 10, wy);
    }
    for (i = 1; i < 8; ++i) {
        int gy = horizon + i * 30;
        shell_line(dc, RGB(70, 119, 79), 0, gy, rc->right, gy);
    }
    for (i = -8; i <= 8; ++i)
        shell_line(dc, RGB(70, 119, 79), rc->right / 2, horizon,
                   rc->right / 2 + i * 115, rc->bottom);

    x = 160 + (int)((frame * 2) % (unsigned)(rc->right > 340 ? rc->right - 300 : 1));
    shell_crypto(dc, x, horizon + 24, (int)(frame & 1));
    shell_text(dc, g_shell_heading_font, RGB(230, 250, 220),
               (RECT){ 38, 30, rc->right - 38, 66 },
               "GAMEPLAY  //  BAY CITY", DT_LEFT | DT_SINGLELINE);
    shell_text(dc, g_shell_body_font, RGB(198, 233, 206),
               (RECT){ 40, 78, rc->right - 40, 106 },
               "CRYPTO  —  WALK CYCLE ACTIVE", DT_LEFT | DT_SINGLELINE);
    text = (RECT){ 40, rc->bottom - 64, rc->right - 40, rc->bottom - 36 };
    shell_text(dc, g_shell_body_font, RGB(177, 222, 190), text,
               "30 FPS TARGET    WASD: MOVE    ESC: QUIT",
               DT_LEFT | DT_SINGLELINE);
}

static void shell_paint(HDC dc, const RECT *rc)
{
    LONG stage = InterlockedCompareExchange(&g_shell_stage, 0, 0);
    LONG frame = InterlockedCompareExchange(&g_shell_frame, 0, 0);

    shell_ensure_fonts();
    SetBkMode(dc, TRANSPARENT);
    switch (stage) {
    case DAH2_SHELL_CUTSCENE:
        shell_paint_cutscene(dc, rc, frame);
        break;
    case DAH2_SHELL_GAMEPLAY:
        shell_paint_gameplay(dc, rc, frame);
        break;
    default:
        shell_paint_menu(dc, rc, frame);
        break;
    }
}

#define DAH2_WINDOW_TITLE "Destroy All Humans! 2 Make War, Not Love"
#define DAH2_WINDOW_STYLE (WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN)

static WINDOWPLACEMENT g_windowed_placement = { sizeof(WINDOWPLACEMENT) };
static BOOL g_borderless_fullscreen;

/* F11 / Alt+Enter: borderless fullscreen on the monitor under the window, back to the framed window on the next press. */
static void boot_toggle_fullscreen(HWND hwnd)
{
    if (!g_borderless_fullscreen) {
        MONITORINFO mi = { sizeof(mi) };
        if (!GetWindowPlacement(hwnd, &g_windowed_placement) ||
            !GetMonitorInfoA(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi))
            return;
        SetWindowLongA(hwnd, GWL_STYLE, (DAH2_WINDOW_STYLE) & ~WS_OVERLAPPEDWINDOW);
        SetWindowPos(hwnd, HWND_TOP, mi.rcMonitor.left, mi.rcMonitor.top,
                     mi.rcMonitor.right - mi.rcMonitor.left, mi.rcMonitor.bottom - mi.rcMonitor.top,
                     SWP_FRAMECHANGED | SWP_NOOWNERZORDER);
        g_borderless_fullscreen = TRUE;
    } else {
        SetWindowLongA(hwnd, GWL_STYLE, DAH2_WINDOW_STYLE | WS_VISIBLE);
        SetWindowPlacement(hwnd, &g_windowed_placement);
        SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        g_borderless_fullscreen = FALSE;
    }
}

static LRESULT CALLBACK boot_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_GETMINMAXINFO: {
        /* Smallest window is half the Xbox's 640x480 client area. */
        MINMAXINFO *mm = (MINMAXINFO *)lp;
        RECT r = { 0, 0, 320, 240 };
        AdjustWindowRectEx(&r, DAH2_WINDOW_STYLE, FALSE, WS_EX_APPWINDOW);
        mm->ptMinTrackSize.x = r.right - r.left;
        mm->ptMinTrackSize.y = r.bottom - r.top;
        return 0;
    }
    case WM_SYSKEYDOWN:
        if (wp == VK_RETURN && (lp & (1 << 29))) { boot_toggle_fullscreen(hwnd); return 0; }
        break;
    case WM_KEYDOWN:
        if (wp == VK_OEM_3 && !(lp & (1u << 30))) { dah2_console_toggle(); return 0; }
        if (wp == VK_F11) { boot_toggle_fullscreen(hwnd); return 0; }
        break;
    case WM_SIZE:
        dah2_console_parent_resized();
        return 0;
    case WM_TIMER:
        if (InterlockedCompareExchange(&g_renderer_owned, 0, 0) == 0 &&
            InterlockedCompareExchange(&g_shell_active, 0, 0) == 0)
            InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case DAH2_WM_RENDERER_OWNERSHIP:
        if (wp) {
            KillTimer(hwnd, 1);
            ValidateRect(hwnd, NULL);
        } else if (InterlockedCompareExchange(&g_shell_active, 0, 0) == 0) {
            SetTimer(hwnd, 1, 16, NULL);
            InvalidateRect(hwnd, NULL, FALSE);
        } else {
            KillTimer(hwnd, 1);
        }
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        RECT rc;
        char status[sizeof(g_boot_status)];
        HDC dc = BeginPaint(hwnd, &ps);
        if (InterlockedCompareExchange(&g_renderer_owned, 0, 0) != 0) {
            EndPaint(hwnd, &ps);
            return 0;
        }
        GetClientRect(hwnd, &rc);
        if (InterlockedCompareExchange(&g_shell_active, 0, 0) != 0) {
            if (InterlockedCompareExchange(&g_shell_stage, 0, 0) == DAH2_SHELL_MENU)
                shell_paint_reference_menu(dc, &rc);
            else
                shell_paint(dc, &rc);
        } else {
            HBRUSH background = CreateSolidBrush(RGB(7, 13, 21));
            FillRect(dc, &rc, background);
            DeleteObject(background);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(125, 231, 255));
            SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
            RECT title = { 48, 62, rc.right - 48, 110 };
            DrawTextA(dc, "DESTROY ALL HUMANS! 2", -1, &title,
                      DT_LEFT | DT_SINGLELINE);
            SetTextColor(dc, RGB(225, 235, 240));
            RECT subtitle = { 48, 112, rc.right - 48, 150 };
            DrawTextA(dc, "Native recompilation - renderer bring-up", -1, &subtitle,
                      DT_LEFT | DT_SINGLELINE);
            EnterCriticalSection(&g_boot_lock);
            memcpy(status, g_boot_status, sizeof(status));
            LeaveCriticalSection(&g_boot_lock);
            RECT text = { 48, 190, rc.right - 48, 230 };
            DrawTextA(dc, status, -1, &text, DT_LEFT | DT_SINGLELINE);
            {
                DWORD tick = GetTickCount();
                int width = rc.right - 96;
                int x = 48 + (int)((tick / 8) % (DWORD)(width > 90 ? width - 90 : 1));
                RECT track = { 48, 250, rc.right - 48, 256 };
                RECT pulse = { x, 246, x + 90, 260 };
                HBRUSH track_brush = CreateSolidBrush(RGB(29, 57, 70));
                HBRUSH pulse_brush = CreateSolidBrush(RGB(63, 205, 238));
                FillRect(dc, &track, track_brush);
                FillRect(dc, &pulse, pulse_brush);
                DeleteObject(track_brush);
                DeleteObject(pulse_brush);
            }
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CLOSE:
        InterlockedExchange(&g_shell_quit, 1);
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        dah2_console_shutdown();
        g_boot_hwnd = NULL;
        InterlockedExchange(&g_shell_quit, 1);
        if (g_boot_closed)
            SetEvent(g_boot_closed);
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

static DWORD WINAPI boot_thread_proc(void *ctx)
{
    HINSTANCE instance = (HINSTANCE)ctx;
    WNDCLASSEXA wc = { sizeof(wc) };
    MSG msg;
    RECT desired = { 0, 0, DAH2_MENU_REFERENCE_WIDTH, DAH2_MENU_REFERENCE_HEIGHT };
    int window_width;
    int window_height;
    int screen_width;
    int screen_height;

    /* The menu cadence is measured at the native window surface.  Keep the
       window/message thread above the translated worker graph so a burst of
       guest bootstrap callbacks cannot delay WM_PAINT delivery. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

    /* Keep the client surface in physical pixels so the reference blit is 1:1. */
    SetProcessDPIAware();
    wc.lpfnWndProc = boot_wndproc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = "DAH2RecompBootWindow";
    wc.hbrBackground = NULL;
    RegisterClassExA(&wc);
    AdjustWindowRectEx(&desired, DAH2_WINDOW_STYLE, FALSE, WS_EX_APPWINDOW);
    window_width = desired.right - desired.left;
    window_height = desired.bottom - desired.top;
    screen_width = GetSystemMetrics(SM_CXSCREEN);
    screen_height = GetSystemMetrics(SM_CYSCREEN);
    g_boot_hwnd = CreateWindowExA(WS_EX_APPWINDOW, wc.lpszClassName,
        DAH2_WINDOW_TITLE,
        DAH2_WINDOW_STYLE | WS_VISIBLE,
        (screen_width - window_width) / 2,
        (screen_height - window_height) / 2,
        window_width, window_height,
        NULL, NULL, instance, NULL);
    if (g_boot_hwnd) {
        dah2_console_initialize(g_boot_hwnd, instance);
        SetTimer(g_boot_hwnd, 1, 16, NULL);
    }
    SetEvent(g_boot_ready);
    while (g_boot_hwnd && GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}

BOOL dah2_boot_window_start(HINSTANCE instance)
{
    InitializeCriticalSection(&g_boot_lock);
    g_boot_ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_boot_closed = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_boot_ready || !g_boot_closed)
        return FALSE;
    InterlockedExchange(&g_shell_quit, 0);
    InterlockedExchange(&g_shell_active, 0);
    g_boot_thread = CreateThread(NULL, 0, boot_thread_proc, instance, 0, NULL);
    if (!g_boot_thread)
        return FALSE;
    WaitForSingleObject(g_boot_ready, 5000);
    return g_boot_hwnd != NULL;
}

void dah2_boot_window_set_status(const char *status)
{
    EnterCriticalSection(&g_boot_lock);
    snprintf(g_boot_status, sizeof(g_boot_status), "%s", status ? status : "");
    LeaveCriticalSection(&g_boot_lock);
    if (g_boot_hwnd)
        InvalidateRect(g_boot_hwnd, NULL, FALSE);
}

HWND dah2_boot_window_get_hwnd(void)
{
    return g_boot_hwnd;
}

void dah2_boot_window_set_renderer_owned(BOOL owned)
{
    HWND hwnd;

    InterlockedExchange(&g_renderer_owned, owned ? 1 : 0);
    hwnd = g_boot_hwnd;
    if (hwnd)
        PostMessageA(hwnd, DAH2_WM_RENDERER_OWNERSHIP, owned ? 1 : 0, 0);
}

void dah2_boot_window_set_shell_autoplay(BOOL enabled)
{
    InterlockedExchange(&g_shell_autoplay, enabled ? 1 : 0);
}

BOOL dah2_boot_window_get_shell_autoplay(void)
{
    return InterlockedCompareExchange(&g_shell_autoplay, 0, 0) != 0;
}

void dah2_boot_window_set_real_menu_probe(BOOL enabled)
{
    InterlockedExchange(&g_real_menu_probe, enabled ? 1 : 0);
}

BOOL dah2_boot_window_get_real_menu_probe(void)
{
    return InterlockedCompareExchange(&g_real_menu_probe, 0, 0) != 0;
}

static const char *shell_stage_name(LONG stage)
{
    switch (stage) {
    case DAH2_SHELL_CUTSCENE: return "CUTSCENE";
    case DAH2_SHELL_GAMEPLAY: return "GAMEPLAY";
    default: return "MENU";
    }
}

static void shell_log_rate(LONG stage, LONG frame, double actual_hz,
                           double target_hz)
{
    fprintf(stderr, "[FPS-MODE] stage=%s target=%.0fHz actual=%.2fHz frame=%ld\n",
            shell_stage_name(stage), target_hz, actual_hz, frame);
    fflush(stderr);
}

void dah2_pc_shell_run(void)
{
    const char *placeholder_setting = getenv("DAH2_PLACEHOLDER_SHELL");
    LARGE_INTEGER frequency;
    LARGE_INTEGER now;
    LONGLONG next_tick;
    LONGLONG stage_start;
    LONGLONG sample_start;
    LONG stage = DAH2_SHELL_MENU;
    LONG frame = 0;
    LONG sample_frames = 0;
    BOOL autoplay = dah2_boot_window_get_shell_autoplay();
    SHORT previous_enter = 0;
    SHORT previous_escape = 0;
    const double menu_period = 1.0 / 30.0;
    const double thirty_period = 1.0 / 30.0;
    HANDLE shell_thread = GetCurrentThread();
    int previous_priority = GetThreadPriority(shell_thread);
    BOOL priority_raised = FALSE;
    MMRESULT timer_period_result;

    if (!placeholder_setting || placeholder_setting[0] != '1' ||
        placeholder_setting[1] != '\0') {
        fprintf(stderr, "[PLACEHOLDER-SHELL] disabled; translated guest output remains authoritative\n");
        fflush(stderr);
        return;
    }

    if (!g_boot_hwnd || !IsWindow(g_boot_hwnd))
        return;

    InterlockedExchange(&g_shell_stage, DAH2_SHELL_MENU);
    InterlockedExchange(&g_shell_frame, 0);
    InterlockedExchange(&g_shell_quit, 0);
    InterlockedExchange(&g_shell_active, 1);
    dah2_boot_window_set_renderer_owned(FALSE);
    dah2_boot_window_set_status("Placeholder diagnostic - not guest gameplay");

    /*
     * The translated title keeps several worker threads busy during startup.
     * Request a 1 ms timer quantum and give only this pacing thread a modest
     * priority bump so Sleep(1) does not inherit the default ~15.6 ms quantum
     * or lose an entire sample window to a normal-priority worker.  Restore
     * both process-wide timing state and the thread priority on exit.
     */
    timer_period_result = timeBeginPeriod(1);
    if (previous_priority != THREAD_PRIORITY_ERROR_RETURN)
        priority_raised = SetThreadPriority(shell_thread,
                                             THREAD_PRIORITY_HIGHEST);

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&now);
    next_tick = now.QuadPart;
    stage_start = now.QuadPart;
    sample_start = now.QuadPart;
    fprintf(stderr, "[SHELL] entered MENU target=30Hz autoplay=%d timer=1ms priority=%s\n",
            autoplay ? 1 : 0,
            priority_raised ? "HIGHEST" : "NORMAL");
    fflush(stderr);

    for (;;) {
        double elapsed;
        double period = stage == DAH2_SHELL_MENU ? menu_period : thirty_period;
        SHORT enter_state;
        SHORT escape_state;
        BOOL enter_pressed;
        BOOL escape_pressed;
        HWND hwnd = g_boot_hwnd;

        if (!hwnd || !IsWindow(hwnd) ||
            InterlockedCompareExchange(&g_shell_quit, 0, 0) != 0)
            break;

        QueryPerformanceCounter(&now);
        elapsed = (double)(now.QuadPart - stage_start) /
                  (double)frequency.QuadPart;
        enter_state = GetAsyncKeyState(VK_RETURN);
        escape_state = GetAsyncKeyState(VK_ESCAPE);
        enter_pressed = ((enter_state & 0x8000) != 0) &&
                        ((previous_enter & 0x8000) == 0);
        escape_pressed = ((escape_state & 0x8000) != 0) &&
                         ((previous_escape & 0x8000) == 0);
        previous_enter = enter_state;
        previous_escape = escape_state;

        if (escape_pressed) {
            InterlockedExchange(&g_shell_quit, 1);
            PostMessageA(hwnd, WM_CLOSE, 0, 0);
            break;
        }

        if (stage == DAH2_SHELL_MENU &&
            (enter_pressed || (autoplay && elapsed >= 5.0))) {
            stage = DAH2_SHELL_CUTSCENE;
            frame = 0;
            sample_frames = 0;
            QueryPerformanceCounter(&now);
            stage_start = now.QuadPart;
            sample_start = now.QuadPart;
            next_tick = now.QuadPart;
            InterlockedExchange(&g_shell_stage, stage);
            InterlockedExchange(&g_shell_frame, 0);
            dah2_boot_window_set_status("Cutscene playing — 30 FPS pacing active");
            fprintf(stderr, "[SHELL] transition MENU -> CUTSCENE target=30Hz\n");
            fflush(stderr);
        } else if (stage == DAH2_SHELL_CUTSCENE &&
                   (enter_pressed || elapsed >= 8.0)) {
            stage = DAH2_SHELL_GAMEPLAY;
            frame = 0;
            sample_frames = 0;
            QueryPerformanceCounter(&now);
            stage_start = now.QuadPart;
            sample_start = now.QuadPart;
            next_tick = now.QuadPart;
            InterlockedExchange(&g_shell_stage, stage);
            InterlockedExchange(&g_shell_frame, 0);
            dah2_boot_window_set_status("Gameplay ready — Crypto walking at 30 FPS");
            fprintf(stderr, "[SHELL] transition CUTSCENE -> GAMEPLAY target=30Hz\n");
            fflush(stderr);
        }

        QueryPerformanceCounter(&now);
        if (now.QuadPart >= next_tick) {
            double sample_elapsed;
            ++frame;
            ++sample_frames;
            InterlockedExchange(&g_shell_frame, frame);
            InvalidateRect(hwnd, NULL, FALSE);
            UpdateWindow(hwnd);
            next_tick += (LONGLONG)(period * (double)frequency.QuadPart);
            if (next_tick < now.QuadPart - (LONGLONG)frequency.QuadPart)
                next_tick = now.QuadPart + (LONGLONG)(period * frequency.QuadPart);
            sample_elapsed = (double)(now.QuadPart - sample_start) /
                             (double)frequency.QuadPart;
            if (sample_frames >= 120 && sample_elapsed > 0.0) {
                shell_log_rate(stage, frame,
                               (double)sample_frames / sample_elapsed,
                               30.0);
                sample_frames = 0;
                sample_start = now.QuadPart;
            }
        }
        Sleep(1);
    }

    InterlockedExchange(&g_shell_active, 0);
    dah2_boot_window_set_status("Shell stopped — closing recompiled title");
    fprintf(stderr, "[SHELL] leaving stage=%s frame=%ld\n",
            shell_stage_name(stage), frame);
    fflush(stderr);
    if (priority_raised && previous_priority != THREAD_PRIORITY_ERROR_RETURN)
        SetThreadPriority(shell_thread, previous_priority);
    if (timer_period_result == TIMERR_NOERROR)
        timeEndPeriod(1);
}

void dah2_boot_window_stop(void)
{
    if (g_boot_hwnd)
        PostMessageA(g_boot_hwnd, WM_CLOSE, 0, 0);
    if (g_boot_thread)
        WaitForSingleObject(g_boot_thread, 2000);
}
