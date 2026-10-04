"""Bounded timing-event capture/comparison for the verified private xemu.

The trace command CONTROLS execution, optionally resets the guest, and always
returns it paused with its own hardware breakpoints removed. No UI or input.
Debugger stops perturb clock inputs: this tests event order and arithmetic,
never real-time, frame-pacing, or uninstrumented timing parity.
"""
from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path
import struct
import time

from parity_boot_trace import ControlGDB, ControlQMP, wait_stopped
from parity_framebuffer import verify_owner
from parity_probe import ProbeError, stamp

POINTS = {0x13D898: "clock_sample", 0x1152AD: "simulation_delta", 0x252260: "swap"}
REGISTERS = ("eax", "ecx", "edx", "ebx", "esi", "edi", "esp", "ebp")
LAYOUT = {
    "clock": (0x2C9C88, {"current_ms": (0x24, 4), "delta_ms": (0x28, 4), "sample_count": (0x2C, 4)}),
    "simulation": (0x30FDE4, {"rate_bits": (4, 4), "delta_bits": (0x10, 4), "clamp_byte": (0x303D, 1)}),
    "configuration": (0x2CA6A0, {"mode60": (0x238, 4), "multiplier": (0x27C, 4)}),
    "device": (0x25E5A8, {"put": (0, 4), "ring_base": (0x24, 4), "ring_end": (0x28, 4), "swap_count": (0x2478, 4)}),
}


class TimingGDB(ControlGDB):
    def single_step(self):
        """Run one instruction with the current hardware breakpoint removed."""
        packet = b"$s#73"
        self.sock.sendall(packet)
        retries = 0
        for _ in range(100):
            marker = self.byte()
            if marker == ord("+"): continue
            if marker == ord("-"):
                retries += 1
                if retries > 3: raise ProbeError("GDB rejected step checksum repeatedly")
                self.sock.sendall(packet); continue
            if marker != ord("$"): raise ProbeError("Unexpected step reply framing")
            raw = bytearray()
            while True:
                marker = self.byte()
                if marker == ord("#"): break
                raw.append(marker)
                if len(raw) > 1024 * 1024: raise ProbeError("Oversized step reply")
            try: checksum = int(bytes([self.byte(), self.byte()]), 16)
            except ValueError as exc: raise ProbeError("Bad step checksum field") from exc
            if checksum != sum(raw) & 255:
                self.sock.sendall(b"-"); retries += 1
                if retries > 3: raise ProbeError("Repeated invalid step reply checksum")
                continue
            self.sock.sendall(b"+")
            response = self.decode(raw)
            if response.startswith(b"O") and response != b"OK": continue
            if response[:1] in (b"S", b"T"):
                self.stops.append({"timestamp": stamp(), "packet": response.decode(errors="replace"), "single_step": True})
                if response[1:3] != b"05": raise ProbeError(f"Unexpected step signal: {response!r}")
                return response
            raise ProbeError(f"Single-step failed: {response!r}")
        raise ProbeError("No step stop reply after 100 packets")


def retail_clock_quotient(raw):
    """XBE13D4B0: low64 multiply by3, then SIGNED _alldiv2200000.

    Return the EDX:EAX bit pattern. Python // rounds negative values down,
    unlike the retail signed helper, so divide the magnitude explicitly.
    """
    product = (raw * 3) & 0xFFFFFFFFFFFFFFFF
    signed = product if product < (1 << 63) else product - (1 << 64)
    quotient = abs(signed) // 2200000
    if signed < 0: quotient = -quotient
    return quotient & 0xFFFFFFFFFFFFFFFF


def event_capture(gdb, ordinal, points):
    regs = gdb.registers()["i386"]
    address = int(regs["eip"], 16)
    if address not in points: raise ProbeError(f"Guest stopped outside timing checkpoints: {address:08x}")
    result = {"schema": "dah2-timing-event-v1", "source": "retail", "ordinal": ordinal,
              "kind": points[address], "address": f"0x{address:08x}", "host_timestamp": stamp(),
              "registers": {key: regs[key] for key in REGISTERS}, "state": {}}
    errors = []
    def read(address, size=4):
        try: return int.from_bytes(gdb.memory(address, size), "little")
        except (OSError, ProbeError) as exc:
            errors.append({"address": f"0x{address:08x}", "size": size, "error": str(exc)})
            return None
    for name, (global_address, fields) in LAYOUT.items():
        pointer = read(global_address)
        group = {"pointer": f"0x{pointer:08x}" if pointer is not None else None}
        for field, (offset, size) in fields.items():
            value = read(pointer + offset, size) if pointer and pointer + offset + size <= 0x100000000 else None
            group[field] = f"0x{value:08x}" if value is not None else None
        result["state"][name] = group
    # Preserve the immediate call frame and the small objects named by the
    # volatile registers. This makes custom checkpoints useful for ABI and
    # intrusive-list parity work without target-specific probe code.
    def words(address, count):
        if not address or address + count * 4 > 0x100000000: return None
        values = []
        for index in range(count):
            value = read(address + index * 4)
            values.append(f"0x{value:08x}" if value is not None else None)
        return values
    esp = int(regs["esp"], 16)
    result["memory"] = {"stack": {"address": f"0x{esp:08x}", "words": words(esp, 16)}}
    for register in ("eax", "ecx", "edx", "ebx", "esi", "edi"):
        pointer = int(regs[register], 16)
        if 0x10000 <= pointer <= 0xFFFFFEFF:
            result["memory"][register] = {
                "address": f"0x{pointer:08x}", "words": words(pointer, 16)}
    if result["kind"] == "rdtsc":
        raw = (int(regs["edx"], 16) << 32) | int(regs["eax"], 16)
        quotient = retail_clock_quotient(raw)
        result["rdtsc"] = {"raw": f"0x{raw:016x}", "retail_ms_low32": quotient & 0xFFFFFFFF,
                           "retail_quotient64": f"0x{quotient:016x}", "division": "signed_truncate_toward_zero"}
    if errors: result["read_errors"] = errors
    return result


def collect_events(qmp, gdb, result, limit, per_event_timeout, total_timeout, poll, save):
    points = {int(address, 16): kind for address, kind in result["checkpoints"].items()}
    active = set()
    deadline = time.monotonic() + total_timeout
    cleanup = result["cleanup"] = {"completed": False, "breakpoints_remaining": []}
    try:
        for address in points:
            active.add(address)  # Cleanup even if installation's reply is lost.
            gdb.breakpoint(address)
        for ordinal in range(1, limit + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise ProbeError("Total timing trace deadline exceeded")
            qmp.execute("cont")
            wait_stopped(qmp, min(per_event_timeout, remaining), poll)
            event = event_capture(gdb, ordinal, points)
            result["events"].append(event); save()
            if ordinal == limit: break
            address = int(event["address"], 16)
            gdb.breakpoint(address, False); active.remove(address)
            # Resume from the same instruction without immediately hitting it again.
            gdb.single_step()
            active.add(address); gdb.breakpoint(address)
    except BaseException as exc:
        result["error"] = str(exc) or type(exc).__name__
    finally:
        cleanup_errors = []
        try:
            qmp.execute("stop"); wait_stopped(qmp, 5, poll)
        except Exception as exc: cleanup_errors.append(f"stop: {exc}")
        for address in list(active):
            try: gdb.breakpoint(address, False); active.remove(address)
            except Exception as exc: cleanup_errors.append(f"remove {address:08x}: {exc}")
        cleanup.update(completed=not cleanup_errors and not active, errors=cleanup_errors,
                       breakpoints_remaining=[f"0x{x:08x}" for x in sorted(active)])
        try: result["status_final"] = qmp.execute("query-status")
        except Exception as exc: cleanup["status_error"] = str(exc); cleanup["completed"] = False
        if result.get("status_final", {}).get("running"):
            cleanup["completed"] = False; cleanup_errors.append("Guest remains running")
        save()


def trace(args):
    points = dict(args.point) if args.point else dict(POINTS)
    if args.rdtsc: points[0x13D4B2] = "rdtsc"
    result = {"schema": "dah2-timing-trace-v1", "started": stamp(), "events": [], "reset_requested": args.reset,
              "checkpoints": {f"0x{a:08x}": name for a, name in points.items()},
              "event_limit": args.event_limit, "timing_parity_verified": False,
              "note": "Hardware stops and single steps perturb clock inputs; only event order/state/arithmetic can be compared."}
    qmp = gdb = None
    with args.output.open("x+", encoding="utf-8") as stream:
        def save():
            stream.seek(0); json.dump(result, stream, indent=2); stream.write("\n"); stream.truncate(); stream.flush()
        save()
        try:
            result["ownership"] = verify_owner(args.manifest, args.qmp_port, args.gdb_port)
            qmp = ControlQMP(args.qmp_port, args.io_timeout)
            result["status_before"] = qmp.execute("query-status")
            if result["status_before"].get("running"): raise ProbeError("Start requires an already-paused owned instance")
            if args.reset:
                qmp.execute("system_reset"); qmp.execute("stop"); wait_stopped(qmp, args.io_timeout, args.poll_interval)
            gdb = TimingGDB(args.gdb_port, args.io_timeout)
            result["initial_stop_packet"] = gdb.request("?").decode(errors="replace")
            collect_events(qmp, gdb, result, args.event_limit, args.timeout, args.total_timeout, args.poll_interval, save)
        except BaseException as exc: result["error"] = str(exc) or type(exc).__name__
        finally:
            if gdb: result["gdb_stop_packets"] = gdb.stops; gdb.close()
            if qmp: result["qmp_events"] = qmp.events; qmp.close()
            result["finished"] = stamp(); save()
    print(json.dumps({"output": str(args.output.resolve()), "events": len(result["events"]),
                      "error": result.get("error"), "cleanup": result.get("cleanup"), "status_final": result.get("status_final")}, indent=2))
    return int("error" in result or not result.get("cleanup", {}).get("completed"))


def integer(value):
    return int(value, 0) if isinstance(value, str) else value


def parse_point(value):
    try:
        name, address = value.rsplit(":", 1)
        address = int(address, 0)
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError("point must be NAME:0xADDRESS") from exc
    if not name or not 0 <= address <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("point must contain a name and 32-bit address")
    return address, name


def normalized_state(event):
    state = event["state"]; output = {}
    # Deliberately exclude allocation pointers, absolute clock epoch and host times.
    for group, fields in {"clock": ("delta_ms", "sample_count"), "simulation": ("rate_bits", "delta_bits", "clamp_byte"),
                          "configuration": ("mode60", "multiplier"), "device": ("swap_count",)}.items():
        for field in fields: output[f"{group}.{field}"] = state.get(group, {}).get(field)
    dev = state.get("device", {})
    put, base, end = (integer(dev.get(x)) for x in ("put", "ring_base", "ring_end"))
    output["device.put_offset"] = None if put is None or base is None else (put - base) & 0xFFFFFFFF
    output["device.ring_size"] = None if end is None or base is None else (end - base) & 0xFFFFFFFF
    return output


def clock_checks(events):
    result, previous = [], None
    for event in events:
        if event["kind"] != "clock_sample": continue
        state = event["state"]["clock"]
        values = [integer(state.get(k)) for k in ("current_ms", "delta_ms", "sample_count")]
        row = {"ordinal": event["ordinal"], "current_ms": values[0], "delta_ms": values[1], "sample_count": values[2]}
        if previous and all(v is not None for v in values + previous):
            row["counter_increment_one"] = ((values[2] - previous[2]) & 0xFFFFFFFF) == 1
            row["delta_matches_u32_subtraction"] = values[1] == ((values[0] - previous[0]) & 0xFFFFFFFF)
        previous = values; result.append(row)
    return result


def compare_events(retail, native):
    rows = []
    keys = lambda events: [(event["kind"], event["address"].lower()) for event in events if event["kind"] != "rdtsc"]
    retail = [event for event in retail if event["kind"] != "rdtsc"]
    native = [event for event in native if event["kind"] != "rdtsc"]
    matcher = difflib.SequenceMatcher(None, keys(retail), keys(native), autojunk=False)
    for tag, i, j, k, l in matcher.get_opcodes():
        if tag != "equal":
            rows.append({"alignment": tag, "retail_ordinals": [e["ordinal"] for e in retail[i:j]],
                         "native_ordinals": [e["ordinal"] for e in native[k:l]], "retail_kinds": keys(retail[i:j]), "native_kinds": keys(native[k:l])})
            continue
        for left, right in zip(retail[i:j], native[k:l]):
            a, b = normalized_state(left), normalized_state(right)
            differences = {name: {"retail": a[name], "native": b[name]} for name in a if a[name] != b[name]}
            rows.append({"alignment": "matched", "kind": left["kind"], "retail_ordinal": left["ordinal"],
                         "native_ordinal": right["ordinal"], "differences": differences})
    return {"schema": "dah2-timing-comparison-v1", "timing_parity_verified": False,
            "event_order_equal": keys(retail) == keys(native), "retail_events": len(retail), "native_events": len(native),
            "rows": rows, "retail_clock_checks": clock_checks(retail), "native_clock_checks": clock_checks(native),
            "note": "Absolute clock epoch, pointers and host timestamps are excluded. Deltas are observational and debugger-perturbed; equal samples cannot establish real-time parity."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    tr = commands.add_parser("trace")
    tr.add_argument("--manifest", required=True, type=Path)
    tr.add_argument("--qmp-port", required=True, type=int); tr.add_argument("--gdb-port", required=True, type=int)
    tr.add_argument("--output", required=True, type=Path); tr.add_argument("--reset", action="store_true")
    tr.add_argument("--point", action="append", type=parse_point,
                    help="Override default checkpoints with NAME:0xADDRESS (repeatable)")
    tr.add_argument("--rdtsc", action="store_true", help="Also capture reference-only raw RDTSC boundary")
    tr.add_argument("--event-limit", type=int, default=32); tr.add_argument("--timeout", type=float, default=30)
    tr.add_argument("--total-timeout", type=float, default=120); tr.add_argument("--io-timeout", type=float, default=5)
    tr.add_argument("--poll-interval", type=float, default=.02)
    comp = commands.add_parser("compare")
    comp.add_argument("--retail", type=Path, required=True); comp.add_argument("--native-log", type=Path, required=True)
    comp.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "trace":
        if not 1 <= args.event_limit <= 4096 or not all(0 < t <= 600 for t in (args.timeout, args.total_timeout, args.io_timeout, args.poll_interval)):
            parser.error("Invalid bounded event/timeout limits")
        if args.qmp_port == args.gdb_port or not all(1 <= p <= 65535 for p in (args.qmp_port, args.gdb_port)):
            parser.error("Two distinct valid ports are required")
        return trace(args)
    retail = json.loads(args.retail.read_text(encoding="utf-8"))["events"]
    native = [json.loads(line.split("[PARITY-TIME] ", 1)[1]) for line in args.native_log.read_text(encoding="utf-8").splitlines() if "[PARITY-TIME] " in line]
    if not native: raise ProbeError("Native log contains no timing events")
    result = compare_events(retail, native)
    result["sources"] = {"retail": str(args.retail.resolve()), "native_log": str(args.native_log.resolve())}
    with args.output.open("x", encoding="utf-8") as stream: json.dump(result, stream, indent=2)
    print(json.dumps({"output": str(args.output.resolve()), "retail_events": len(retail),
                      "native_events": len(native), "event_order_equal": result["event_order_equal"],
                      "timing_parity_verified": False}, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
