"""Capture live retail animation-state calls on the dedicated xemu."""
import argparse, json, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

TARGET = 0x001BDCA0


def word(data, offset=0):
    return int.from_bytes(data[offset:offset + 4], "little")


def valid(pointer):
    return 0x10000 <= pointer < 0x04000000 or 0x80000000 <= pointer < 0x88000000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qmp-port", type=int, required=True)
    parser.add_argument("--gdb-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=24)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    result = {
        "schema": "dah2-retail-animation-state-v1",
        "started": stamp(),
        "calls": [],
        "cleanup": {"breakpoint_removed": False, "resumed": False},
    }
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    installed = False
    deadline = time.monotonic() + args.timeout
    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = StepGDB(args.gdb_port, 5)
        result["initial_stop"] = gdb.request("?").decode(errors="replace")
        gdb.breakpoint(TARGET, True)
        installed = True
        while len(result["calls"]) < args.count and time.monotonic() < deadline:
            qmp.execute("cont")
            wait_stopped(qmp, max(0.1, deadline - time.monotonic()), 0.01)
            regs = gdb.registers()["i386"]
            eip = int(regs["eip"], 16)
            esp = int(regs["esp"], 16)
            if eip != TARGET:
                raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            stack = gdb.memory(esp, 0x30)
            owner = int(regs["ecx"], 16)
            call = {
                "captured": stamp(),
                "registers": regs,
                "stack": memory_record(gdb, esp, 0x30),
                "return_address": f"0x{word(stack):08x}",
                "arguments": [f"0x{word(stack, 4 + i * 4):08x}" for i in range(5)],
                "owner": f"0x{owner:08x}",
            }
            if valid(owner):
                call["owner_memory"] = memory_record(gdb, owner, 0x240)
            current = word(stack, 4)
            if valid(current):
                call["current_memory"] = memory_record(gdb, current, 0x80)
            result["calls"].append(call)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            gdb.step()
        if not result["calls"]:
            raise ProbeError("no animation-state calls")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            qmp.execute("stop")
            wait_stopped(qmp, 5, 0.01)
        except Exception as exc:
            result["cleanup"].setdefault("errors", []).append(str(exc))
        if gdb and installed:
            try:
                gdb.breakpoint(TARGET, False)
                result["cleanup"]["breakpoint_removed"] = True
            except Exception as exc:
                result["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            qmp.execute("cont")
            result["cleanup"]["resumed"] = True
        except Exception as exc:
            result["cleanup"]["resume_error"] = str(exc)
        result["finished"] = stamp()
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if gdb:
            gdb.close()
        qmp.close()
    print(json.dumps({"calls": len(result["calls"]), "error": result.get("error"), "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()
