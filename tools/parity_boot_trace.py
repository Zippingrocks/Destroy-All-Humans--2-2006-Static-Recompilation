"""Bounded boot checkpoints for a verified, dedicated localhost xemu instance.

This tool CONTROLS execution. Verify instance ownership before supplying ports.
Never use the ports of an unrelated emulator. No UI automation is performed.
  python tools/parity_boot_trace.py trace --qmp-port 4446 --gdb-port 1236 --reset --output diagnostics/boot.json
  python tools/parity_boot_trace.py checkpoint --address 0x252260 --qmp-port 4446 --gdb-port 1236 --output diagnostics/swap.json
  python tools/parity_boot_trace.py screendump --screenshot ABSOLUTE.ppm --qmp-port 4446 --gdb-port 1236

Hardware Z1 breakpoints leave guest instruction bytes unchanged. They perturb
execution timing. Capture timestamps are host acquisition times, not evidence
of guest timing parity. Breakpoints are removed and the guest resumed in finally
unless --leave-stopped is explicitly supplied. Output must be a NEW JSON path;
checkpoints and cleanup state are flushed incrementally so failure is preserved.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import socket
import sys
import time

from parity_probe import GDB, QMP, ProbeError, capture, stamp


DEFAULT_CHECKPOINTS = [
    ("xbe_entry", 0x000FAF3B),
    ("create_device", 0x0024DCB0),
    ("device_post_init", 0x0024DD0E),
    ("first_swap", 0x00252260),
]
DEVICE_FIELDS = (0, 4, 8, 0x24, 0x28, 0x2304)


class ControlQMP(QMP):
    def execute(self, command, arguments=None):
        if command in {"qmp_capabilities", "query-status", "query-cpus-fast", "human-monitor-command"}:
            return super().execute(command, arguments)
        if command not in {"system_reset", "stop", "cont", "screendump", "query-commands"}:
            raise ProbeError(f"Disallowed control QMP command: {command}")
        self.sequence += 1
        request = {"execute": command, "id": self.sequence}
        if arguments:
            request["arguments"] = arguments
        self.sock.sendall(json.dumps(request).encode() + b"\r\n")
        for _ in range(1000):
            result = self.receive()
            if "event" in result:
                self.events.append(result)
                continue
            if result.get("id") != self.sequence:
                raise ProbeError("Unexpected QMP response ID")
            if "error" in result:
                raise ProbeError(f"QMP error: {result['error']}")
            if "return" not in result:
                raise ProbeError("QMP response missing return")
            return result["return"]
        raise ProbeError("No QMP response after 1000 events")


class ControlGDB(GDB):
    def __init__(self, port, timeout=3):
        super().__init__(port, timeout)
        self.stops = []

    def request(self, payload):
        if payload not in {"g", "?"} and not re.fullmatch(r"(?:m[0-9a-f]+,[0-9a-f]+|[Zz][12],[0-9a-f]+,[0-9a-f]+)", payload):
            raise ProbeError(f"Disallowed control GDB packet: {payload}")
        data = payload.encode()
        packet = b"$" + data + f"#{sum(data) & 255:02x}".encode()
        self.sock.sendall(packet)
        retries = 0
        for _ in range(100):
            marker = self.byte()
            if marker == ord("+"):
                continue
            if marker == ord("-"):
                retries += 1
                if retries > 3:
                    raise ProbeError("GDB rejected packet repeatedly")
                self.sock.sendall(packet)
                continue
            if marker != ord("$"):
                raise ProbeError(f"Unexpected GDB framing byte: {marker:02x}")
            raw = bytearray()
            while True:
                marker = self.byte()
                if marker == ord("#"):
                    break
                raw.append(marker)
                if len(raw) > 1024 * 1024:
                    raise ProbeError("Oversized GDB response")
            try:
                checksum = int(bytes([self.byte(), self.byte()]), 16)
            except ValueError as exc:
                raise ProbeError("Invalid GDB checksum field") from exc
            if checksum != sum(raw) & 255:
                self.sock.sendall(b"-")
                retries += 1
                if retries > 3:
                    raise ProbeError("Repeated bad GDB checksum")
                continue
            self.sock.sendall(b"+")
            response = self.decode(raw)
            if response[:1] in (b"S", b"T", b"W", b"X"):
                self.stops.append({"timestamp": stamp(), "packet": response.decode(errors="replace")})
                if payload == "?":
                    return response
                continue
            if response.startswith(b"O") and response != b"OK":
                continue
            if not response or response.startswith(b"E"):
                raise ProbeError(f"GDB unsupported/failed {payload}: {response!r}")
            return response
        raise ProbeError("No GDB response after 100 packets")

    def breakpoint(self, address, insert=True, kind=1, length=1):
        response = self.request(f"{'Z' if insert else 'z'}{kind},{address:x},{length:x}")
        if response != b"OK":
            raise ProbeError(f"Hardware breakpoint rejected: {response!r}")


def memory_record(gdb, address, length):
    result = {"address": f"0x{address:08x}", "length": length, "address_space": "virtual"}
    result.update(capture(gdb.memory, address, length))
    if "hex" in result and length % 4 == 0:
        data = bytes.fromhex(result["hex"])
        result["u32_le"] = [f"0x{int.from_bytes(data[i:i+4], 'little'):08x}" for i in range(0, length, 4)]
    return result


def u32(record):
    return int.from_bytes(bytes.fromhex(record["hex"][:8]), "little") if "hex" in record else None


def checkpoint_capture(qmp, gdb, name, address):
    result = {"name": name, "address": f"0x{address:08x}", "captured": stamp(),
              "status": qmp.execute("query-status"), "registers": gdb.registers()}
    registers = result["registers"]["i386"]
    result["hit"] = registers["eip"] is not None and int(registers["eip"], 16) == address
    result["code"] = memory_record(gdb, address, 32)
    if registers["esp"] is not None:
        sp = int(registers["esp"], 16)
        result["stack"] = memory_record(gdb, sp, 0x80)
        if address == 0x24DCB0:
            pointer = memory_record(gdb, (sp + 0x14) & 0xffffffff, 4)
            result["presentation_parameters_pointer"] = pointer
            pp = u32(pointer)
            if pp:
                result["presentation_parameters"] = memory_record(gdb, pp, 0x44)
    result["device_global"] = memory_record(gdb, 0x25E5A8, 4)
    result["comparison_globals"] = {
        f"0x{address:08x}": memory_record(gdb, address, 4)
        for address in (0x002C8BA4, 0x002CA6A0, 0x00354D04)
    }
    device = u32(result["device_global"])
    if device and device <= 0xffffffff - 0x2308:
        result["device_head"] = memory_record(gdb, device, 0x100)
        result["device_fields"] = {f"0x{offset:x}": memory_record(gdb, device + offset, 4) for offset in DEVICE_FIELDS}
        if address in (0x24DD0E, 0x252260):
            ring_base = u32(result["device_fields"]["0x24"])
            ring_end = u32(result["device_fields"]["0x28"])
            if ring_base is not None and ring_end is not None and 0 < ring_base < ring_end <= 0x100000000:
                result["push_buffer_prefix"] = memory_record(gdb, ring_base, min(0x1000, ring_end - ring_base))
                result["push_buffer_prefix"]["base_source"] = "device+0x24"
                result["push_buffer_prefix"]["allocation_end"] = f"0x{ring_end:08x}"
    return result


def wait_stopped(qmp, timeout, interval):
    deadline = time.monotonic() + timeout
    while True:
        status = qmp.execute("query-status")
        if not status.get("running", False):
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError(f"No breakpoint stop within {timeout:g} seconds")
        time.sleep(min(interval, remaining))


def parse_checkpoint(value):
    try:
        name, raw = value.split(":")
        address = int(raw, 0)
        if not name or not 0 <= address <= 0xffffffff:
            raise ValueError()
        return name, address
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected NAME:0xADDRESS") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["trace", "checkpoint", "status", "commands", "reset", "stop", "cont", "screendump"])
    parser.add_argument("--qmp-port", type=int, required=True)
    parser.add_argument("--gdb-port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=30, help="Per-checkpoint wait limit (seconds)")
    parser.add_argument("--io-timeout", type=float, default=3)
    parser.add_argument("--poll-interval", type=float, default=0.05)
    parser.add_argument("--address", type=lambda value: int(value, 0))
    parser.add_argument("--checkpoint", action="append", type=parse_checkpoint, help="Override trace defaults with ordered NAME:0xADDRESS")
    parser.add_argument("--reset", action="store_true", help="Reset owned guest before tracing")
    parser.add_argument("--write-watch", action="store_true", help="Treat checkpoints as 4-byte guest write watchpoints")
    parser.add_argument("--leave-stopped", action="store_true")
    parser.add_argument("--screenshot", type=Path)
    parser.add_argument("--output", type=Path, help="NEW JSON manifest path")
    args = parser.parse_args(argv)
    if not all(1 <= port <= 65535 for port in (args.qmp_port, args.gdb_port)) or args.qmp_port == args.gdb_port:
        parser.error("two distinct valid localhost ports are required")
    if min(args.timeout, args.io_timeout, args.poll_interval) <= 0:
        parser.error("timeouts and poll interval must be positive")
    if args.command == "checkpoint" and (args.address is None or not 0 <= args.address <= 0xffffffff):
        parser.error("checkpoint requires a 32-bit --address")
    if args.command in {"trace", "checkpoint"} and args.output is None:
        parser.error("trace/checkpoint requires --output to preserve partial results")
    if args.command == "screendump" and args.screenshot is None:
        parser.error("screendump requires --screenshot")
    if args.screenshot is not None and (not args.screenshot.is_absolute() or args.screenshot.exists()):
        parser.error("--screenshot must be a NEW absolute path")
    result = {"schema": "dah2-boot-trace-v1", "started": stamp(), "qmp_port": args.qmp_port,
              "gdb_port": args.gdb_port, "command": args.command, "checkpoints": [],
              "note": "Hardware breakpoints preserve instruction bytes but perturb timing. Host timestamps are acquisition times, not timing parity.",
              "cleanup": {"completed": False, "breakpoints_remaining": [], "resume_requested": not args.leave_stopped}}
    stream = args.output.open("x+", encoding="utf-8") if args.output else None

    def save():
        if stream:
            stream.seek(0)
            json.dump(result, stream, indent=2)
            stream.write("\n")
            stream.truncate()
            stream.flush()

    qmp = gdb = None
    active_breakpoints = set()
    execution_touched = False
    save()
    try:
        qmp = ControlQMP(args.qmp_port, args.io_timeout)
        result["status_before"] = qmp.execute("query-status")
        if args.command in {"trace", "checkpoint"}:
            execution_touched = True
            qmp.execute("stop")
            wait_stopped(qmp, args.io_timeout, args.poll_interval)
            if args.reset:
                qmp.execute("system_reset")
                qmp.execute("stop")
                wait_stopped(qmp, args.io_timeout, args.poll_interval)
            gdb = ControlGDB(args.gdb_port, args.io_timeout)
            result["initial_stop_packet"] = gdb.request("?").decode(errors="replace")
            checkpoints = [("checkpoint", args.address)] if args.command == "checkpoint" else (args.checkpoint or DEFAULT_CHECKPOINTS)
            for name, address in checkpoints:
                attempt = {"name": name, "address": f"0x{address:08x}", "started": stamp(), "hit": False}
                result["checkpoints"].append(attempt)
                save()
                # Register before requesting installation so cleanup is attempted
                # even if the target installs it but its reply times out.
                active_breakpoints.add(address)
                gdb.breakpoint(address, kind=2 if args.write_watch else 1, length=4 if args.write_watch else 1)
                result["cleanup"]["breakpoints_remaining"] = [f"0x{value:08x}" for value in sorted(active_breakpoints)]
                qmp.execute("cont")
                try:
                    attempt["stop_status"] = wait_stopped(qmp, args.timeout, args.poll_interval)
                    attempt.update(checkpoint_capture(qmp, gdb, name, address))
                    if args.write_watch:
                        attempt["trigger_eip"] = attempt["registers"]["i386"]["eip"]
                        attempt["hit"] = True
                    save()
                    if not attempt["hit"]:
                        raise ProbeError(f"Guest stopped away from checkpoint {name}")
                except (OSError, ProbeError) as exc:
                    attempt["error"] = str(exc)
                    save()
                    raise
                gdb.breakpoint(address, False, kind=2 if args.write_watch else 1, length=4 if args.write_watch else 1)
                active_breakpoints.remove(address)
                save()
        elif args.command == "commands":
            result["commands"] = qmp.execute("query-commands")
        elif args.command in {"reset", "stop", "cont"}:
            execution_touched = True
            result["control_response"] = qmp.execute("system_reset" if args.command == "reset" else args.command)
        if args.screenshot is not None:
            result["screendump_response"] = qmp.execute("screendump", {"filename": str(args.screenshot)})
            result["screenshot"] = str(args.screenshot)
        result["status_after_capture"] = qmp.execute("query-status")
    except (OSError, ProbeError, KeyboardInterrupt) as exc:
        result["error"] = str(exc) or type(exc).__name__
        save()
    finally:
        cleanup_errors = []
        if qmp and execution_touched:
            try:
                if active_breakpoints or args.leave_stopped:
                    qmp.execute("stop")
                    wait_stopped(qmp, args.io_timeout, args.poll_interval)
            except (OSError, ProbeError) as exc:
                cleanup_errors.append(f"stop: {exc}")
            if gdb:
                for address in list(active_breakpoints):
                    try:
                        gdb.breakpoint(address, False, kind=2 if args.write_watch else 1, length=4 if args.write_watch else 1)
                        active_breakpoints.remove(address)
                    except (OSError, ProbeError) as exc:
                        cleanup_errors.append(f"remove 0x{address:08x}: {exc}")
            if not args.leave_stopped:
                try:
                    qmp.execute("cont")
                    result["cleanup"]["resumed"] = True
                except (OSError, ProbeError) as exc:
                    cleanup_errors.append(f"resume: {exc}")
            try:
                result["status_final"] = qmp.execute("query-status")
            except (OSError, ProbeError) as exc:
                cleanup_errors.append(f"final status: {exc}")
        if gdb:
            result["gdb_stop_packets"] = gdb.stops
            gdb.close()
        if qmp:
            result["qmp_events"] = qmp.events
            qmp.close()
        result["cleanup"].update({"completed": not cleanup_errors and not active_breakpoints,
                                  "errors": cleanup_errors,
                                  "breakpoints_remaining": [f"0x{value:08x}" for value in sorted(active_breakpoints)]})
        result["finished"] = stamp()
        save()
        if stream:
            stream.close()
    print(json.dumps(result, indent=2))
    return 1 if "error" in result or not result["cleanup"]["completed"] else 0


if __name__ == "__main__":
    sys.exit(main())
