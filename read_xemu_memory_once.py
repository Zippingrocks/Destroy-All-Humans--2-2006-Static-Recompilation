"""Read one bounded retail-memory range while always resuming dedicated xemu."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qmp-port", type=int, required=True)
    parser.add_argument("--gdb-port", type=int, required=True)
    parser.add_argument("--address", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")
    result = {"schema": "dah2-retail-memory-once-v1", "captured": stamp(),
              "address": f"0x{args.address:08x}", "size": args.size,
              "cleanup": {"resumed": False}}
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = StepGDB(args.gdb_port, 5)
        result["stop"] = gdb.request("?").decode(errors="replace")
        result["memory"] = memory_record(gdb, args.address, args.size)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            qmp.execute("cont")
            result["cleanup"]["resumed"] = True
        except Exception as exc:
            result["cleanup"]["resume_error"] = str(exc)
        if gdb:
            gdb.close()
        qmp.close()
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
