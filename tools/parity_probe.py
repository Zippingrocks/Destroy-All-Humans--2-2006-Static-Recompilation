"""Read-only local xemu/recomp snapshots; no reset, pause, resume, or writes.

Examples (use only the dedicated instance's ports/PID):
  python tools/parity_probe.py status --qmp-port 4445
  python tools/parity_probe.py snapshot --qmp-port 4445 --gdb-port 1235 --read entry:0x10000:64 --output diagnostics/snapshot.json
  python tools/parity_probe.py snapshot --qmp-port 4445 --memory-source qmp-virtual --read state:0x400000:256 --recomp-pid 12345 --recomp-offset 0x10000 --output diagnostics/pair.json
  python tools/parity_probe.py compare diagnostics/first.json diagnostics/second.json

Numbers accept decimal or 0x-prefixed hex. The recomp offset MUST come from that
run's memory-layout log/debug symbols, never from an old probe. HMP x uses guest
virtual addresses; xp uses guest physical addresses and cannot be paired with
recomp virtual addresses without page translation. GDB m uses guest virtual
addresses. A running target can reject/time out GDB requests; this utility never
interrupts it to make requests succeed. A paired sample is sequential, not proof
of frame, instruction, or timing parity. Use a common checkpoint externally for
stable state comparisons. Host timestamps measure acquisition, not guest time.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import time


class ProbeError(RuntimeError):
    pass


def stamp():
    return {"unix_ns": time.time_ns(), "monotonic_ns": time.perf_counter_ns()}


class QMP:
    """ID-matched newline-delimited JSON, tolerating asynchronous events."""

    def __init__(self, port, timeout=3):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout)
        self.stream = self.sock.makefile("rb")
        self.sequence = 0
        self.events = []
        try:
            self.greeting = self.receive()
            if "QMP" not in self.greeting:
                raise ProbeError("Missing QMP greeting")
            self.execute("qmp_capabilities")
        except Exception:
            self.close()
            raise

    def receive(self):
        line = self.stream.readline(1024 * 1024 + 1)
        if not line or not line.endswith(b"\n") or len(line) > 1024 * 1024:
            raise ProbeError("Closed, oversized, or incomplete QMP frame")
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError) as exc:
            raise ProbeError("Invalid QMP JSON frame") from exc
        if not isinstance(value, dict):
            raise ProbeError("QMP response is not an object")
        return value

    def execute(self, command, arguments=None):
        if command not in {"qmp_capabilities", "query-status", "query-cpus-fast", "human-monitor-command"}:
            raise ProbeError(f"Disallowed QMP command: {command}")
        if command == "human-monitor-command":
            hmp = (arguments or {}).get("command-line", "")
            if hmp != "info registers" and not re.fullmatch(r"xp? /[1-9][0-9]*bx 0x[0-9a-fA-F]+", hmp):
                raise ProbeError(f"Disallowed HMP command: {hmp}")
        self.sequence += 1
        request = {"execute": command, "id": self.sequence}
        if arguments:
            request["arguments"] = arguments
        self.sock.sendall(json.dumps(request).encode("utf-8") + b"\r\n")
        for _ in range(1000):
            message = self.receive()
            if "event" in message:
                self.events.append(message)
                continue
            if message.get("id") != self.sequence:
                raise ProbeError("Unexpected QMP response ID")
            if "error" in message:
                raise ProbeError(f"QMP error: {message['error']}")
            if "return" not in message:
                raise ProbeError("QMP response missing return")
            return message["return"]
        raise ProbeError("Too many QMP events without a response")

    def hmp(self, command):
        return self.execute("human-monitor-command", {"command-line": command})

    def memory(self, address, length, physical=False):
        data = bytearray()
        while len(data) < length:
            count = min(256, length - len(data))
            reply = self.hmp(f"{'xp' if physical else 'x'} /{count}bx 0x{address + len(data):x}")
            chunk = bytearray()
            for line in reply.splitlines():
                if re.match(r"^\s*(?:0x)?[0-9a-fA-F]+:", line):
                    chunk.extend(int(value, 16) for value in re.findall(
                        r"0x([0-9a-fA-F]{2})(?![0-9a-fA-F])", line.split(":", 1)[1]))
            if len(chunk) != count:
                raise ProbeError(f"HMP returned {len(chunk)}/{count} bytes: {reply.strip()}")
            data.extend(chunk)
        return bytes(data)

    def close(self):
        self.stream.close()
        self.sock.close()


class GDB:
    """Minimal ACK-mode RSP: checksums, escaping, RLE, chunked memory reads."""

    def __init__(self, port, timeout=3):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout)

    def byte(self):
        value = self.sock.recv(1)
        if not value:
            raise ProbeError("GDB connection closed")
        return value[0]

    @staticmethod
    def decode(payload):
        result = bytearray()
        index = 0
        while index < len(payload):
            value = payload[index]
            if value == ord("}"):
                index += 1
                if index == len(payload):
                    raise ProbeError("Truncated GDB escape")
                result.append(payload[index] ^ 0x20)
            elif value == ord("*"):
                index += 1
                if not result or index == len(payload) or payload[index] < 29:
                    raise ProbeError("Invalid GDB run-length encoding")
                result.extend(bytes([result[-1]]) * (payload[index] - 29))
            else:
                result.append(value)
            index += 1
        return bytes(result)

    def request(self, payload):
        if payload != "g" and not re.fullmatch(r"m[0-9a-f]+,[0-9a-f]+", payload):
            raise ProbeError(f"Disallowed GDB packet: {payload}")
        body = payload.encode("ascii")
        packet = b"$" + body + f"#{sum(body) & 255:02x}".encode("ascii")
        self.sock.sendall(packet)
        retries = 0
        for _ in range(100):
            start = self.byte()
            if start == ord("+"):
                continue
            if start == ord("-"):
                retries += 1
                if retries > 3:
                    raise ProbeError("GDB rejected request checksum repeatedly")
                self.sock.sendall(packet)
                continue
            if start != ord("$"):
                raise ProbeError(f"Unexpected GDB stream byte 0x{start:02x}")
            response = bytearray()
            while True:
                value = self.byte()
                if value == ord("#"):
                    break
                response.append(value)
                if len(response) > 1024 * 1024:
                    raise ProbeError("Oversized GDB packet")
            checksum_bytes = bytes([self.byte(), self.byte()])
            try:
                checksum = int(checksum_bytes, 16)
            except ValueError as exc:
                raise ProbeError("Invalid GDB checksum field") from exc
            if checksum != sum(response) & 255:
                self.sock.sendall(b"-")
                retries += 1
                if retries > 3:
                    raise ProbeError("Repeated invalid GDB response checksums")
                continue
            self.sock.sendall(b"+")
            decoded = self.decode(response)
            if decoded.startswith(b"O") and decoded != b"OK":
                continue
            if decoded.startswith(b"E"):
                raise ProbeError(f"GDB remote error: {decoded.decode('ascii', errors='replace')}")
            if not decoded:
                raise ProbeError("GDB packet unsupported")
            return decoded
        raise ProbeError("No GDB response after 100 packets")

    def memory(self, address, length):
        result = bytearray()
        while len(result) < length:
            count = min(256, length - len(result))
            reply = self.request(f"m{address + len(result):x},{count:x}")
            try:
                chunk = bytes.fromhex(reply.decode("ascii"))
            except (ValueError, UnicodeError) as exc:
                raise ProbeError(f"Non-hex GDB memory response: {reply[:80]!r}") from exc
            if len(chunk) != count:
                raise ProbeError(f"Short GDB memory read: {len(chunk)}/{count}")
            result.extend(chunk)
        return bytes(result)

    def registers(self):
        reply = self.request("g")
        if len(reply) < 16 * 8 or not re.fullmatch(b"[0-9a-fA-Fx]+", reply):
            raise ProbeError("Unexpected i386 GDB register packet")
        names = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                 "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs")
        values = {}
        for index, name in enumerate(names):
            value = reply[index * 8:index * 8 + 8]
            values[name] = None if b"x" in value else f"0x{int.from_bytes(bytes.fromhex(value.decode()), 'little'):08x}"
        return {"i386": values, "raw_packet": reply.decode("ascii")}

    def close(self):
        self.sock.close()


class ProcessMemory:
    def __init__(self, pid, offset):
        if os.name != "nt":
            raise ProbeError("Recomp process reads require Windows")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ProbeError("Use 64-bit Python for the 64-bit recomp process")
        self.offset = offset
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.kernel.OpenProcess.restype = ctypes.c_void_p
        self.kernel.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel.ReadProcessMemory.restype = ctypes.c_int
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.restype = ctypes.c_int
        self.handle = self.kernel.OpenProcess(0x0010, False, pid)  # PROCESS_VM_READ only.
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def memory(self, address, length):
        buffer = ctypes.create_string_buffer(length)
        received = ctypes.c_size_t()
        native = address + self.offset
        if not 0 <= native <= 0xffffffffffffffff - length:
            raise ProbeError("Recomp host address is out of range")
        if not self.kernel.ReadProcessMemory(self.handle, native, buffer, length, ctypes.byref(received)):
            raise ctypes.WinError(ctypes.get_last_error())
        if received.value != length:
            raise ProbeError(f"Short process memory read: {received.value}/{length}")
        return buffer.raw

    def close(self):
        self.kernel.CloseHandle(self.handle)


def compare_bytes(left, right):
    mismatch = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b), None)
    if mismatch is None and len(left) != len(right):
        mismatch = min(len(left), len(right))
    return {"equal": left == right, "first_difference_offset": mismatch,
            "different_bytes": sum(a != b for a, b in zip(left, right)) + abs(len(left) - len(right)),
            "left_length": len(left), "right_length": len(right)}


def capture(reader, address, length):
    result = {"started": stamp()}
    try:
        data = reader(address, length)
        result.update({"hex": data.hex(), "sha256": hashlib.sha256(data).hexdigest()})
    except (OSError, ProbeError) as exc:
        result["error"] = str(exc)
    result["finished"] = stamp()
    return result


def parse_range(value):
    try:
        name, address, length = value.split(":")
        address, length = int(address, 0), int(length, 0)
        if not name or not 0 <= address <= 0xffffffff or not 1 <= length <= 1024 * 1024 or address + length > 0x100000000:
            raise ValueError()
        return name, address, length
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected NAME:ADDRESS:LENGTH (32-bit address; 1..1MiB length)") from exc


def compare_manifests(first, second, source):
    left = {entry["name"]: entry for entry in first.get("ranges", [])}
    right = {entry["name"]: entry for entry in second.get("ranges", [])}
    output = []
    for name in sorted(left.keys() | right.keys()):
        a, b = left.get(name), right.get(name)
        row = {"name": name}
        if a is None or b is None:
            row["error"] = "Range absent from one manifest"
        elif (a["address"], a["length"], a.get("address_space")) != (b["address"], b["length"], b.get("address_space")):
            row["error"] = "Range address, length, or address space differs"
        elif "hex" not in a.get(source, {}) or "hex" not in b.get(source, {}):
            row["error"] = f"No successful {source} read in one manifest"
        else:
            row.update(compare_bytes(bytes.fromhex(a[source]["hex"]), bytes.fromhex(b[source]["hex"])))
        output.append(row)
    return {"schema": "dah2-parity-comparison-v1", "source": source, "ranges": output,
            "note": "Byte equality alone does not establish execution or timing parity."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["status", "snapshot", "compare"])
    parser.add_argument("manifests", nargs="*")
    parser.add_argument("--qmp-port", type=int)
    parser.add_argument("--gdb-port", type=int)
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--memory-source", choices=["gdb", "qmp-virtual", "qmp-physical"], default="gdb")
    parser.add_argument("--read", action="append", type=parse_range, default=[])
    parser.add_argument("--recomp-pid", type=int)
    parser.add_argument("--recomp-offset", type=lambda value: int(value, 0))
    parser.add_argument("--compare-source", choices=["xemu", "recomp"], default="xemu")
    parser.add_argument("--output", type=Path, help="Create a new JSON file (refuses to overwrite)")
    args = parser.parse_args(argv)
    if args.command == "compare":
        if len(args.manifests) != 2:
            parser.error("compare requires two snapshot paths")
        result = compare_manifests(*(json.loads(Path(path).read_text()) for path in args.manifests), args.compare_source)
    else:
        if not args.qmp_port or not 1 <= args.qmp_port <= 65535 or args.timeout <= 0:
            parser.error("a valid --qmp-port and positive --timeout are required")
        if args.gdb_port is not None and not 1 <= args.gdb_port <= 65535:
            parser.error("invalid --gdb-port")
        if args.command == "snapshot" and args.memory_source == "gdb" and not args.gdb_port:
            parser.error("GDB snapshots require --gdb-port (or --memory-source qmp-virtual)")
        if (args.recomp_pid is None) != (args.recomp_offset is None):
            parser.error("--recomp-pid and verified --recomp-offset must be supplied together")
        if args.recomp_pid is not None and args.recomp_pid <= 0:
            parser.error("invalid --recomp-pid")
        if args.recomp_pid and args.memory_source == "qmp-physical":
            parser.error("physical xemu memory cannot be paired directly with virtual recomp memory")
        if len({item[0] for item in args.read}) != len(args.read):
            parser.error("range names must be unique")
        result = {"schema": "dah2-parity-snapshot-v1", "started": stamp(), "qmp_port": args.qmp_port,
                  "gdb_port": args.gdb_port, "memory_source": args.memory_source,
                  "recomp_pid": args.recomp_pid, "recomp_offset": args.recomp_offset,
                  "note": "Sequential observations; clocks are host timestamps, not guest frame timings. No execution control is issued."}
        qmp = gdb = recomp = None
        try:
            qmp = QMP(args.qmp_port, args.timeout)
            result["qmp_greeting"] = qmp.greeting
            result["status_before"] = qmp.execute("query-status")
            result["registers_hmp"] = qmp.hmp("info registers")
            if args.command == "snapshot":
                if args.memory_source == "gdb":
                    gdb = GDB(args.gdb_port, args.timeout)
                    result["registers_gdb"] = gdb.registers()
                if args.recomp_pid:
                    recomp = ProcessMemory(args.recomp_pid, args.recomp_offset)
                result["ranges"] = []
                for name, address, length in args.read:
                    row = {"name": name, "address": f"0x{address:08x}", "length": length,
                           "address_space": "physical" if args.memory_source == "qmp-physical" else "virtual"}
                    reader = gdb.memory if gdb else lambda a, n: qmp.memory(a, n, args.memory_source == "qmp-physical")
                    row["xemu"] = capture(reader, address, length)
                    if recomp:
                        row["recomp"] = capture(recomp.memory, address, length)
                        if "hex" in row["xemu"] and "hex" in row["recomp"]:
                            row["comparison"] = compare_bytes(bytes.fromhex(row["xemu"]["hex"]), bytes.fromhex(row["recomp"]["hex"]))
                    result["ranges"].append(row)
                    if "error" in row["xemu"]:
                        raise ProbeError(f"Stopped after failed xemu read: {row['xemu']['error']}")
            result["status_after"] = qmp.execute("query-status")
            result["qmp_events"] = qmp.events
        except (OSError, ProbeError) as exc:
            result["error"] = str(exc)
        finally:
            for client in (recomp, gdb, qmp):
                if client:
                    client.close()
        result["finished"] = stamp()
    encoded = json.dumps(result, indent=2)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
    print(encoded)
    return 1 if "error" in result or any("error" in row or any("error" in row.get(source, {}) for source in ("xemu", "recomp")) for row in result.get("ranges", [])) else 0


if __name__ == "__main__":
    sys.exit(main())
