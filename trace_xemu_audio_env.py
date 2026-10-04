"""Capture early retail calls to the DirectSound environment setter."""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

TARGET = 0x0026504A


def word(data, offset=0):
    return int.from_bytes(data[offset:offset + 4], "little")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--count", type=int, default=8)
    args = ap.parse_args()
    if args.output.exists():
        ap.error("output must be new")

    result = {
        "schema": "dah2-retail-audio-env-v1",
        "started": stamp(),
        "calls": [],
        "cleanup": {"breakpoint_removed": False, "resumed": False},
    }
    q = ControlQMP(args.qmp_port, 5)
    g = None
    installed = False
    deadline = time.monotonic() + args.timeout
    try:
        q.execute("stop")
        wait_stopped(q, 5, 0.01)
        q.execute("system_reset")
        q.execute("stop")
        wait_stopped(q, 5, 0.01)
        g = StepGDB(args.gdb_port, 5)
        result["initial_stop"] = g.request("?").decode(errors="replace")
        g.breakpoint(TARGET, True)
        installed = True

        while len(result["calls"]) < args.count and time.monotonic() < deadline:
            q.execute("cont")
            wait_stopped(q, max(0.1, deadline - time.monotonic()), 0.01)
            regs = g.registers()["i386"]
            eip = int(regs["eip"], 16)
            esp = int(regs["esp"], 16)
            if eip != TARGET:
                raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            stack = g.memory(esp, 0x40)
            wrapper = word(stack, 4)
            interface = word(g.memory(wrapper + 8, 4)) if wrapper else 0
            call = {
                "captured": stamp(),
                "registers": regs,
                "stack": memory_record(g, esp, 0x40),
                "wrapper": f"0x{wrapper:08x}",
                "interface": f"0x{interface:08x}",
            }
            if wrapper:
                call["wrapper_memory"] = memory_record(g, wrapper, 0x40)
            if interface:
                call["interface_memory"] = memory_record(g, interface, 0x80)
            result["calls"].append(call)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            g.step()
        if not result["calls"]:
            raise ProbeError("timed out before any environment-setter call")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            q.execute("stop")
            wait_stopped(q, 5, 0.01)
        except Exception as exc:
            result["cleanup"].setdefault("errors", []).append(str(exc))
        if g and installed:
            try:
                g.breakpoint(TARGET, False)
                result["cleanup"]["breakpoint_removed"] = True
            except Exception as exc:
                result["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            q.execute("cont")
            result["cleanup"]["resumed"] = True
        except Exception as exc:
            result["cleanup"]["resume_error"] = str(exc)
        result["finished"] = stamp()
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if g:
            g.close()
        q.close()

    print(json.dumps({
        "calls": len(result["calls"]),
        "error": result.get("error"),
        "cleanup": result["cleanup"],
    }))


if __name__ == "__main__":
    main()
