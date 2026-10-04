"""Export a paused, owned xemu's native-resolution front surface without UI.

The PCRTC physical address must exactly match a retail D3D device surface.
Only linear 32-bit RGB formats and a disabled PVIDEO overlay are supported.
This is the actual guest front plane, not the host display compositor output.
QMP pmemsave uses xemu's physical-memory read path, including dirty GPU surface
download callbacks. No guest writes, breakpoints, execution or input commands.

capture --manifest .../background.json --qmp-port 4446 --gdb-port 1236
        --output .../retail_front01
convert-ppm native.ppm native.png
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import zlib

from parity_probe import GDB, QMP, ProbeError, stamp

XEMU_COMMIT = "fc24584ce88f0915ad7f04775bb7712c2e3f49ee"
PCRTC_START = 0xFD600800
PVIDEO_BUFFER = 0xFD008700
PVIDEO_SIZE_IN = 0xFD008928
SUPPORTED_FORMATS = {0x12: "LIN_A8R8G8B8", 0x1E: "LIN_X8R8G8B8"}


def png_rgb(width, height, pixels):
    """Encode RGB bytes losslessly using only the standard library."""
    if width < 1 or height < 1 or len(pixels) != width * height * 3:
        raise ValueError("RGB dimensions do not match data")
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    rows = b"".join(b"\0" + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def plane_rgb(data, width, height, pitch):
    if width < 1 or height < 1 or pitch < width * 4 or len(data) != pitch * height:
        raise ValueError("Invalid 32-bit linear plane layout")
    rgb = bytearray(width * height * 3)
    for y in range(height):
        row = data[y * pitch:y * pitch + width * 4]
        start = y * width * 3
        rgb[start:start + width * 3:3] = row[2::4]
        rgb[start + 1:start + width * 3:3] = row[1::4]
        rgb[start + 2:start + width * 3:3] = row[0::4]
    return bytes(rgb)


def ppm_rgb(data):
    tokens, cursor = [], 0
    while len(tokens) < 4:
        while cursor < len(data) and data[cursor] in b" \t\r\n": cursor += 1
        if cursor < len(data) and data[cursor] == 35:
            cursor = data.index(b"\n", cursor) + 1
            continue
        start = cursor
        while cursor < len(data) and data[cursor] not in b" \t\r\n": cursor += 1
        if cursor == start: raise ValueError("Incomplete PPM header")
        tokens.append(data[start:cursor])
    if tokens[0] != b"P6" or tokens[3] != b"255":
        raise ValueError("Only 8-bit binary RGB PPM is supported")
    width, height = map(int, tokens[1:3])
    cursor += 2 if data[cursor:cursor + 2] == b"\r\n" else 1
    pixels = data[cursor:]
    if width < 1 or height < 1 or len(pixels) != width * height * 3:
        raise ValueError("PPM byte count does not match its dimensions")
    return width, height, pixels


def verify_owner(manifest_path, qmp_port, gdb_port):
    """Match live executable and loopback listener PID to the private manifest."""
    if sys.platform != "win32": raise ProbeError("Live ownership verification requires Windows")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    pid, executable = int(manifest["childPid"]), str(Path(manifest["executable"]).resolve())
    if pid <= 0 or not manifest.get("desktop", "").startswith("WinSta0\\DAH2_Codex_"):
        raise ProbeError("Manifest does not identify a private DAH2 desktop")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle: raise ProbeError(f"Cannot inspect manifest PID {pid}: {ctypes.get_last_error()}")
    try:
        name = ctypes.create_unicode_buffer(32768); length = wintypes.DWORD(len(name))
        if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(length)):
            raise ProbeError("Cannot verify process executable")
        if os.path.normcase(str(Path(name.value).resolve())) != os.path.normcase(executable):
            raise ProbeError("Manifest PID executable no longer matches")
    finally: kernel.CloseHandle(handle)
    iphlp = ctypes.WinDLL("iphlpapi")
    size = wintypes.DWORD()
    error = iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, 3, 0)
    if error != 122: raise ProbeError(f"Cannot size listener table: {error}")
    table = ctypes.create_string_buffer(size.value)
    error = iphlp.GetExtendedTcpTable(table, ctypes.byref(size), False, socket.AF_INET, 3, 0)
    if error: raise ProbeError(f"Cannot query listener table: {error}")
    count = struct.unpack_from("<I", table.raw)[0]
    owners = {}
    for index in range(count):
        state, local, port, remote, remote_port, owner = struct.unpack_from("<6I", table.raw, 4 + 24 * index)
        owners[(socket.inet_ntoa(struct.pack("<I", local)), socket.ntohs(port & 0xFFFF))] = owner
    for port in (qmp_port, gdb_port):
        if owners.get(("127.0.0.1", port)) != pid:
            raise ProbeError(f"Loopback port {port} is not owned by manifest PID {pid}")
    return {"pid": pid, "executable": executable, "desktop": manifest["desktop"], "manifest": str(manifest_path.resolve())}


class FrameQMP(QMP):
    def save_physical(self, address, size, filename):
        if filename.exists() or address < 0 or size <= 0 or address + size > 0x08000000:
            raise ProbeError("Rejecting existing output or out-of-VRAM physical range")
        self.sequence += 1
        self.sock.sendall(json.dumps({"execute": "pmemsave", "id": self.sequence,
                                     "arguments": {"val": address, "size": size, "filename": str(filename.resolve())}}).encode() + b"\r\n")
        for _ in range(1000):
            response = self.receive()
            if "event" in response:
                self.events.append(response); continue
            if response.get("id") != self.sequence: raise ProbeError("Unexpected QMP response ID")
            if "error" in response: raise ProbeError(str(response["error"]))
            if "return" not in response: raise ProbeError("Missing QMP return")
            return response["return"]
        raise ProbeError("Too many QMP events")


def metadata(qmp, gdb):
    physical_word = lambda a: int.from_bytes(qmp.memory(a, 4, physical=True), "little")
    guest_word = lambda a: int.from_bytes(gdb.memory(a, 4), "little")
    result = {"pcrtc_start": physical_word(PCRTC_START), "pvideo_buffer": physical_word(PVIDEO_BUFFER),
              "pvideo_size_in": physical_word(PVIDEO_SIZE_IN), "device": guest_word(0x25E5A8)}
    dev = result["device"]
    if dev != 0x25E5B0: raise ProbeError(f"Unexpected retail DAH2 device: {dev:08x}")
    count = guest_word(dev + 0x1A10)
    if not 1 <= count <= 3: raise ProbeError(f"Invalid retail surface count {count}")
    result["surface_count"] = count; result["surfaces"] = []
    for index in range(count):
        pointer = guest_word(dev + 0x1A14 + 4 * index)
        common, data, lock, fmt, size = struct.unpack("<5I", gdb.memory(pointer, 20))
        result["surfaces"].append({"pointer": pointer, "common": common, "data": data, "lock": lock,
                                   "format_word": fmt, "size_word": size})
    return result


def capture_front(args):
    files = {ext: Path(str(args.output) + "." + ext) for ext in ("json", "raw", "png")}
    if any(path.exists() for path in files.values()): raise ProbeError("Output prefix already exists")
    result = {"schema": "dah2-front-plane-v1", "started": stamp(), "xemu_source_commit": XEMU_COMMIT,
              "capture_kind": "native_resolution_guest_front_plane", "guest_writes": False,
              "execution_control_sent": False, "breakpoints_installed": False,
              "limitations": ["Not the host display compositor: no window scaling or UI.",
                              "VGA line-offset/interlace state is not independently captured.",
                              "Rows retain guest memory order; RGB channel conversion is lossless.",
                              "Memory read can synchronize an already dirty GPU surface into VRAM."]}
    qmp = gdb = None
    try:
        result["ownership"] = verify_owner(args.manifest, args.qmp_port, args.gdb_port)
        qmp = FrameQMP(args.qmp_port, args.timeout)
        result["status_before"] = qmp.execute("query-status")
        if result["status_before"].get("running"): raise ProbeError("Capture requires an already-paused instance")
        gdb = GDB(args.gdb_port, args.timeout)
        before = result["metadata_before"] = metadata(qmp, gdb)
        if before["pvideo_buffer"] & 1 and before["pvideo_size_in"] != 0xFFFFFFFF:
            raise ProbeError("Active PVIDEO overlay: front plane is not the complete displayed frame")
        matches = [s for s in before["surfaces"] if (s["data"] & 0x07FFFFFF) == before["pcrtc_start"]]
        if len(matches) != 1: raise ProbeError("PCRTC start does not uniquely match a device front surface")
        surface = matches[0]; fmt = (surface["format_word"] >> 8) & 255; size = surface["size_word"]
        if fmt not in SUPPORTED_FORMATS or not size: raise ProbeError(f"Unsupported surface format/layout: {fmt:02x}")
        width, height, pitch = (size & 0xFFF) + 1, ((size >> 12) & 0xFFF) + 1, ((size >> 24) + 1) * 64
        if pitch < width * 4 or height > 2160 or width > 4096:
            raise ProbeError("Implausible front surface layout")
        result["surface"] = dict(surface, width=width, height=height, pitch=pitch, format=SUPPORTED_FORMATS[fmt],
                                  physical_address=before["pcrtc_start"], byte_length=pitch * height)
        qmp.save_physical(before["pcrtc_start"], pitch * height, files["raw"])
        after = result["metadata_after"] = metadata(qmp, gdb)
        if before != after: raise ProbeError("Front/display metadata changed during capture; raw retained, PNG rejected")
        raw = files["raw"].read_bytes(); rgb = plane_rgb(raw, width, height, pitch)
        result["raw_sha256"] = hashlib.sha256(raw).hexdigest()
        result["rgb_sha256"] = hashlib.sha256(rgb).hexdigest()
        result["rgb_nonzero_bytes"] = sum(value != 0 for value in rgb)
        with files["png"].open("xb") as stream: stream.write(png_rgb(width, height, rgb))
        result["png_sha256"] = hashlib.sha256(files["png"].read_bytes()).hexdigest()
        result["files"] = {key: str(value.resolve()) for key, value in files.items()}
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if gdb: gdb.close()
        if qmp:
            try: result["status_after"] = qmp.execute("query-status")
            except Exception as exc: result["status_after_error"] = str(exc)
            qmp.close()
        result["finished"] = stamp()
        with files["json"].open("x", encoding="utf-8") as stream: json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))
    return int("error" in result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cap = commands.add_parser("capture")
    cap.add_argument("--manifest", type=Path, required=True)
    cap.add_argument("--qmp-port", type=int, required=True)
    cap.add_argument("--gdb-port", type=int, required=True)
    cap.add_argument("--output", type=Path, required=True)
    cap.add_argument("--timeout", type=float, default=15)
    conv = commands.add_parser("convert-ppm")
    conv.add_argument("source", type=Path); conv.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "convert-ppm":
        width, height, rgb = ppm_rgb(args.source.read_bytes())
        with args.destination.open("xb") as stream: stream.write(png_rgb(width, height, rgb))
        print(json.dumps({"width": width, "height": height, "rgb_sha256": hashlib.sha256(rgb).hexdigest(),
                          "png": str(args.destination.resolve())}))
        return 0
    if not 1 <= args.qmp_port <= 65535 or not 1 <= args.gdb_port <= 65535 or not 0 < args.timeout <= 60:
        parser.error("Invalid diagnostic ports or timeout")
    return capture_front(args)


if __name__ == "__main__":
    raise SystemExit(main())
