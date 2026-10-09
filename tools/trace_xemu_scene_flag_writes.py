"""Trace retail writes to scene record 0 active flag with a hardware watchpoint."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parity_boot_trace import ControlGDB, ControlQMP, memory_record, stamp, wait_stopped  # noqa: E402

FLAG = 0x003153DC


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--max-hits", type=int, default=32)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    output = {
        "schema": "dah2-xemu-scene-flag-writes-v1",
        "flag": f"0x{FLAG:08x}",
        "started": stamp(),
        "writes": [],
        "cleanup": {"watchpoints_remaining": [], "resumed": False},
    }
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    installed = False
    deadline = time.monotonic() + args.timeout
    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        qmp.execute("system_reset")
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = ControlGDB(args.gdb_port, 5)
        output["initial_stop"] = gdb.request("?").decode(errors="replace")
        gdb.breakpoint(FLAG, True, kind=2, length=1)
        installed = True
        output["cleanup"]["watchpoints_remaining"] = [f"0x{FLAG:08x}"]

        for ordinal in range(1, args.max_hits + 1):
            qmp.execute("cont")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                output["timeout"] = True
                break
            try:
                wait_stopped(qmp, remaining, 0.01)
            except Exception as exc:
                output["timeout"] = True
                output["timeout_error"] = str(exc)
                break
            regs = gdb.registers()["i386"]
            eip = int(regs["eip"], 16)
            esp = int(regs["esp"], 16)
            value = gdb.memory(FLAG, 1).hex()
            output["stops"] = ordinal
            row = {
                "ordinal": ordinal,
                "eip_after_write": f"0x{eip:08x}",
                "flag_value": value,
                "registers": regs,
                "stack": memory_record(gdb, esp, 0x80),
                "code": memory_record(gdb, max(0x10000, eip - 16), 0x30),
            }
            if not output["writes"] or output["writes"][-1]["flag_value"] != value:
                output["writes"].append(row)
    finally:
        try:
            qmp.execute("stop")
            wait_stopped(qmp, 5, 0.01)
        except Exception as exc:
            output["cleanup"].setdefault("errors", []).append(f"stop: {exc}")
        if gdb is not None and installed:
            try:
                gdb.breakpoint(FLAG, False, kind=2, length=1)
                installed = False
                output["cleanup"]["watchpoints_remaining"] = []
            except Exception as exc:
                output["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            qmp.execute("cont")
            output["cleanup"]["resumed"] = True
        except Exception as exc:
            output["cleanup"]["resume_error"] = str(exc)
        output["finished"] = stamp()
        args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        if gdb is not None:
            gdb.close()
        qmp.close()

    print(json.dumps({"stops": output.get("stops", 0), "transitions": len(output["writes"]), "cleanup": output["cleanup"]}))


if __name__ == "__main__":
    main()