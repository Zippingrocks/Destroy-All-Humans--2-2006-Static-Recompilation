"""Capture repeated hits at one verified private-xemu instruction boundary."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, memory_record, stamp, wait_stopped
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from trace_xemu_vm_handoff import StepGDB


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", type=int, required=True)
    parser.add_argument("--gdb-port", type=int, required=True)
    parser.add_argument("--address", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--hits", type=int, default=32)
    parser.add_argument("--movie-frame", type=int)
    parser.add_argument("--arg18", type=lambda value: int(value, 0))
    parser.add_argument("--arg1c", type=lambda value: int(value, 0))
    parser.add_argument("--invalid-m100", action="store_true")
    parser.add_argument("--max-examined", type=int, default=200000)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")
    if not 1 <= args.hits <= 4096:
        parser.error("hits must be between 1 and 4096")

    result = {"schema": "dah2-repeated-checkpoint-v1", "started": stamp(),
              "address": f"0x{args.address:08x}", "hits": [],
              "cleanup": {"breakpoints_remaining": [], "resumed": False, "errors": []}}

    def save() -> None:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    qmp = gdb = None
    installed = False
    save()
    try:
        qmp = ControlQMP(args.qmp_port, 5.0)
        result["status_before"] = qmp.execute("query-status")
        qmp.execute("stop")
        wait_stopped(qmp, 5.0, 0.01)
        if args.reset:
            qmp.execute("system_reset")
            qmp.execute("stop")
            wait_stopped(qmp, 5.0, 0.01)
        gdb = StepGDB(args.gdb_port, 5.0)
        result["initial_stop_packet"] = gdb.request("?").decode(errors="replace")
        gdb.breakpoint(args.address, kind=1, length=1)
        installed = True
        result["cleanup"]["breakpoints_remaining"] = [f"0x{args.address:08x}"]
        save()
        deadline = time.monotonic() + args.timeout
        examined = 0
        while len(result["hits"]) < args.hits:
            examined += 1
            if examined > args.max_examined:
                raise ProbeError("maximum examined checkpoint hits reached")
            qmp.execute("cont")
            wait_stopped(qmp, max(0.01, deadline - time.monotonic()), 0.005)
            registers = gdb.registers()["i386"]
            if int(registers["eip"], 16) != args.address:
                raise ProbeError("guest stopped away from requested checkpoint")
            ebp = int(registers["ebp"], 16)
            movie_frame = None
            if args.movie_frame is not None:
                movie = int.from_bytes(gdb.memory(0x31DA8C, 4), "little")
                if movie:
                    movie_frame = int.from_bytes(gdb.memory(movie + 0xC, 4), "little")
                if movie_frame != args.movie_frame:
                    gdb.breakpoint(args.address, False, kind=1, length=1)
                    installed = False
                    result["cleanup"]["breakpoints_remaining"] = []
                    gdb.step()
                    gdb.breakpoint(args.address, kind=1, length=1)
                    installed = True
                    result["cleanup"]["breakpoints_remaining"] = [f"0x{args.address:08x}"]
                    continue
            if args.arg18 is not None or args.arg1c is not None:
                arg18 = int.from_bytes(gdb.memory(ebp + 0x18, 4), "little")
                arg1c = int.from_bytes(gdb.memory(ebp + 0x1C, 4), "little")
                if ((args.arg18 is not None and arg18 != args.arg18) or
                        (args.arg1c is not None and arg1c != args.arg1c)):
                    gdb.breakpoint(args.address, False, kind=1, length=1)
                    installed = False
                    result["cleanup"]["breakpoints_remaining"] = []
                    gdb.step()
                    gdb.breakpoint(args.address, kind=1, length=1)
                    installed = True
                    result["cleanup"]["breakpoints_remaining"] = [f"0x{args.address:08x}"]
                    continue
            if args.invalid_m100:
                m100 = int.from_bytes(gdb.memory(ebp - 0x100, 4), "little")
                if (m100 & 0xF0000000) == 0x80000000:
                    gdb.breakpoint(args.address, False, kind=1, length=1)
                    installed = False
                    result["cleanup"]["breakpoints_remaining"] = []
                    gdb.step()
                    gdb.breakpoint(args.address, kind=1, length=1)
                    installed = True
                    result["cleanup"]["breakpoints_remaining"] = [f"0x{args.address:08x}"]
                    continue
            ordinal = len(result["hits"]) + 1
            esp = int(registers["esp"], 16)
            row = {"ordinal": ordinal, "examined_hit": examined,
                   "movie_frame": movie_frame, "captured": stamp(), "registers": registers,
                   "stack": memory_record(gdb, esp, 0x80)}
            if args.address in {0x286F71, 0x2871E2, 0x28750A, 0x28800A, 0x288048, 0x288202, 0x288339, 0x288574}:
                row["bink_decoder_frame"] = memory_record(gdb, (ebp - 0x140) & 0xFFFFFFFF, 0x180)
            result["hits"].append(row)
            save()
            if len(result["hits"]) != args.hits:
                gdb.breakpoint(args.address, False, kind=1, length=1)
                installed = False
                result["cleanup"]["breakpoints_remaining"] = []
                gdb.step()
                gdb.breakpoint(args.address, kind=1, length=1)
                installed = True
                result["cleanup"]["breakpoints_remaining"] = [f"0x{args.address:08x}"]
        result["completed"] = True
        result["examined_hits"] = examined
    except (OSError, ProbeError, KeyboardInterrupt) as exc:
        result["error"] = str(exc) or type(exc).__name__
    finally:
        if gdb and installed:
            try:
                gdb.breakpoint(args.address, False, kind=1, length=1)
                result["cleanup"]["breakpoints_remaining"] = []
            except Exception as exc:
                result["cleanup"]["errors"].append(f"remove breakpoint: {exc}")
        if qmp:
            try:
                qmp.execute("cont")
                result["cleanup"]["resumed"] = True
                result["status_final"] = qmp.execute("query-status")
            except Exception as exc:
                result["cleanup"]["errors"].append(f"resume: {exc}")
            qmp.close()
        if gdb:
            gdb.close()
        result["finished"] = stamp()
        save()
    print(json.dumps({"output": str(args.output), "captured": len(result["hits"]),
                      "error": result.get("error"), "cleanup": result["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()