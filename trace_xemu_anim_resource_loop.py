"""Capture bounded retail animation resource-loop state on dedicated xemu."""
import argparse, json, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

TARGETS = (0x001BD2D0, 0x001BD8C2, 0x001BD8E0, 0x001BDB4A)


def valid(pointer):
    return 0x10000 <= pointer < 0x04000000 or 0x80000000 <= pointer < 0x88000000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qmp-port", type=int, required=True)
    parser.add_argument("--gdb-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")
    result = {"schema": "dah2-retail-animation-resource-loop-v1", "started": stamp(),
              "targets": [f"0x{x:08x}" for x in TARGETS], "stops": [],
              "cleanup": {"breakpoints_removed": False, "resumed": False}}
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    installed = []
    deadline = time.monotonic() + args.timeout
    try:
        if args.reset:
            qmp.execute("system_reset")
            time.sleep(0.1)
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
                    "stack": memory_record(gdb, esp, 0x180)}
            owner = int(regs["ecx" if eip == 0x001BD2D0 else "ebp"], 16)
            if valid(owner):
                stop["owner"] = f"0x{owner:08x}"
                stop["owner_memory"] = memory_record(gdb, owner, 0x260)
                if eip in (0x001BD8C2, 0x001BD8E0):
                    manager = int.from_bytes(gdb.memory(owner + 0x230, 4), "little")
                    if valid(manager):
                        stop["manager"] = f"0x{manager:08x}"
                        stop["manager_memory"] = memory_record(gdb, manager, 0x80)
                        table = int.from_bytes(gdb.memory(manager + 0x50, 4), "little")
                        count = int.from_bytes(gdb.memory(manager + 0x54, 4), "little")
                        if valid(table) and count <= 64:
                            stop["record_table"] = memory_record(gdb, table, max(4, count * 4))
                            stop["records"] = []
                            for i in range(count):
                                record = int.from_bytes(gdb.memory(table + i * 4, 4), "little")
                                item = {"index": i, "address": f"0x{record:08x}"}
                                if valid(record):
                                    try:
                                        item["memory"] = memory_record(gdb, record, 0x50)
                                    except Exception as exc:
                                        item["memory_error"] = f"{type(exc).__name__}: {exc}"
                                stop["records"].append(item)
            result["stops"].append(stop)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            gdb.step()
        if not result["stops"]:
            raise ProbeError("no animation resource-loop stops")
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
