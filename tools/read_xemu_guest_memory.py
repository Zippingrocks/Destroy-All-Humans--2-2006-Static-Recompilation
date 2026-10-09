"""Read bounded guest-memory ranges from a verified private xemu instance.

The emulator is stopped only for the read and always resumed. This tool does
not reset the guest, install breakpoints, or write guest state.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, stamp, wait_stopped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--read", action="append", required=True,
                        help="NAME:ADDRESS:LENGTH; numbers use int(..., 0)")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    ranges: list[tuple[str, int, int]] = []
    for spec in args.read:
        try:
            name, address_text, length_text = spec.split(":")
            address = int(address_text, 0)
            length = int(length_text, 0)
        except ValueError as exc:
            parser.error(f"invalid range: {spec}: {exc}")
        if not name or not 0 <= address <= 0xFFFFFFFF or not 1 <= length <= 0x100000:
            parser.error(f"invalid range: {spec}")
        if address + length > 0x100000000:
            parser.error(f"range wraps guest address space: {spec}")
        ranges.append((name, address, length))

    result = {
        "schema": "dah2-xemu-guest-memory-v1",
        "captured": stamp(),
        "ranges": [],
        "cleanup": {"resumed": False},
    }
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = ControlGDB(args.gdb_port, 5)
        result["stopPacket"] = gdb.request("?").decode(errors="replace")
        result["registers"] = gdb.registers()["i386"]
        for name, address, length in ranges:
            data = gdb.memory(address, length)
            result["ranges"].append({
                "name": name,
                "address": f"0x{address:08X}",
                "length": length,
                "hex": data.hex(),
            })
    except ProbeError as exc:
        result["error"] = str(exc)
        raise
    finally:
        try:
            qmp.execute("cont")
            result["cleanup"]["resumed"] = True
        except Exception as exc:
            result["cleanup"]["resumeError"] = str(exc)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()