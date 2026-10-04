"""Capture bounded retail animation-owner binding on dedicated xemu."""
import argparse, json, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

TARGETS = (0x001BC110, 0x001BC124, 0x001BC150, 0x001BC168, 0x001BC179)


def valid(pointer):
    return 0x10000 <= pointer < 0x04000000 or 0x80000000 <= pointer < 0x88000000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qmp-port", type=int, required=True)
    parser.add_argument("--gdb-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")
    result = {"schema": "dah2-retail-animation-bind-v1", "started": stamp(),
              "targets": [f"0x{x:08x}" for x in TARGETS], "stops": [],
              "cleanup": {"breakpoints_removed": False, "resumed": False}}
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    installed = []
    deadline = time.monotonic() + args.timeout
    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = StepGDB(args.gdb_port, 5)
        result["initial_stop"] = gdb.request("?").decode(errors="replace")
        for target in TARGETS:
            gdb.breakpoint(target, True)
            installed.append(target)
        while len(result["stops"]) < args.count and time.monotonic() < deadline:
            qmp.execute("cont")
            wait_stopped(qmp, max(0.1, deadline - time.monotonic()), 0.01)
            regs = gdb.registers()["i386"]
            eip, esp = int(regs["eip"], 16), int(regs["esp"], 16)
            if eip not in TARGETS:
                raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            stop = {"captured": stamp(), "target": f"0x{eip:08x}", "registers": regs,
                    "stack": memory_record(gdb, esp, 0x40)}
            owner = int(regs["ecx" if eip == 0x001BC110 else "esi"], 16)
            if valid(owner):
                stop["owner"] = f"0x{owner:08x}"
                stop["owner_memory"] = memory_record(gdb, owner, 0x240)
            source = int(regs["eax"], 16)
            if valid(source):
                stop["source"] = f"0x{source:08x}"
                stop["source_memory"] = memory_record(gdb, source, 0x110)
            result["stops"].append(stop)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            gdb.step()
        if not result["stops"]:
            raise ProbeError("no animation-bind stops")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            qmp.execute("stop")
            wait_stopped(qmp, 5, 0.01)
        except Exception as exc:
            result["cleanup"].setdefault("errors", []).append(str(exc))
        if gdb:
            removed = True
            for target in installed:
                try:
                    gdb.breakpoint(target, False)
                except Exception as exc:
                    removed = False
                    result["cleanup"].setdefault("errors", []).append(str(exc))
            result["cleanup"]["breakpoints_removed"] = removed
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
    print(json.dumps({"stops": len(result["stops"]), "error": result.get("error"), "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()
