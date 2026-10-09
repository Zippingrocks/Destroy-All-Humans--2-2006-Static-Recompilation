"""Post one bounded key event to the manifest-owned xemu window on its private desktop."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import time

from parity_framebuffer import verify_owner
from parity_probe import ProbeError, QMP, stamp

KEYS = {"ret": 0x0D, "a": 0x41, "b": 0x42, "x": 0x58, "y": 0x59,
        "backspace": 0x08, "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--key", required=True, choices=sorted(KEYS))
    parser.add_argument("--hold-ms", type=int, default=100)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")
    if not 25 <= args.hold_ms <= 1000:
        parser.error("hold duration must be 25..1000 ms")

    result = {"schema": "dah2-private-xemu-window-key-v1", "started": stamp(),
              "key": args.key, "holdMs": args.hold_ms}
    desktop = None
    qmp = None
    user32 = None
    try:
        ownership = verify_owner(args.manifest, args.qmp_port, args.gdb_port)
        result["ownership"] = ownership
        desktop_name = ownership["desktop"].split("\\", 1)[1]
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        user32.OpenDesktopW.restype = wintypes.HANDLE
        user32.CloseDesktop.argtypes = [wintypes.HANDLE]
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.MapVirtualKeyW.argtypes = [wintypes.UINT, wintypes.UINT]
        desktop = user32.OpenDesktopW(desktop_name, 0, False, 0x0041)
        if not desktop:
            raise ctypes.WinError(ctypes.get_last_error())
        windows = []
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        @callback_type
        def visit(hwnd, _):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value == ownership["pid"]:
                title = ctypes.create_unicode_buffer(512)
                klass = ctypes.create_unicode_buffer(256)
                user32.GetWindowTextW(hwnd, title, len(title))
                user32.GetClassNameW(hwnd, klass, len(klass))
                windows.append((int(hwnd), title.value, klass.value))
            return True

        if not user32.EnumDesktopWindows(desktop, visit, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if not windows:
            raise ProbeError("No window owned by the manifest xemu PID on its private desktop")
        preferred = [window for window in windows if "xemu" in (window[1] + window[2]).lower()]
        hwnd, title, klass = (preferred or windows)[0]
        result["windows"] = [{"hwnd": f"0x{h:016X}", "title": t, "class": c} for h, t, c in windows]
        result["target"] = {"hwnd": f"0x{hwnd:016X}", "title": title, "class": klass}

        qmp = QMP(args.qmp_port, 5)
        result["statusBefore"] = qmp.execute("query-status")
        if not result["statusBefore"].get("running"):
            raise ProbeError("Refusing input because the private guest is not running")
        virtual_key = KEYS[args.key]
        scan = user32.MapVirtualKeyW(virtual_key, 0)
        down_lparam = 1 | (scan << 16)
        up_lparam = down_lparam | 0xC0000000
        if not user32.PostMessageW(hwnd, 0x0100, virtual_key, down_lparam):
            raise ctypes.WinError(ctypes.get_last_error())
        time.sleep(args.hold_ms / 1000.0)
        if not user32.PostMessageW(hwnd, 0x0101, virtual_key, up_lparam):
            raise ctypes.WinError(ctypes.get_last_error())
        result["posted"] = True
        result["statusAfter"] = qmp.execute("query-status")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if qmp:
            qmp.close()
        if desktop and user32:
            user32.CloseDesktop(desktop)
        result["finished"] = stamp()
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()