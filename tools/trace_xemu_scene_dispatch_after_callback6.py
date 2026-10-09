"""Trace retail sub_0015ECA0 control flow after loader callback six."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parity_boot_trace import (  # noqa: E402
    ControlGDB,
    ControlQMP,
    ProbeError,
    memory_record,
    stamp,
    wait_stopped,
)

LOADER = 0x001A8EB0
CALL = 0x002117F9
RET = 0x002117FD
ENTRY = 0x0015ECA0
END = 0x0015EDE3
ROUTE = (
    0x0015ECAD, 0x0015ECB7, 0x0015ECC0, 0x0015ECD1, 0x0015ECE7,
    0x0015ECF3, 0x0015ED01, 0x0015ED0C, 0x0015ED16, 0x0015ED1F,
    0x0015ED30, 0x0015ED3A, 0x0015ED46, 0x0015ED50, 0x0015ED59,
    0x0015ED64, 0x0015ED6E, 0x0015ED79, 0x0015ED83, 0x0015ED8C,
    0x0015ED9D, 0x0015EDB4, 0x0015EDBF, 0x0015EDC9, 0x0015EDD2,
    END,
)


def u32(gdb: ControlGDB, address: int) -> int:
    return int.from_bytes(gdb.memory(address, 4), "little")


def snapshot(gdb: ControlGDB, address: int) -> dict:
    regs = gdb.registers()["i386"]
    esp = int(regs["esp"], 16)
    row = {
        "address": f"0x{address:08x}",
        "registers": regs,
        "stack": memory_record(gdb, esp, 0x80),
    }
    eax = int(regs["eax"], 16)
    esi = int(regs["esi"], 16)
    if 0x10000 <= eax < 0x90000000:
        row["eax_memory"] = memory_record(gdb, eax, 0xC0)
    if 0x10000 <= esi < 0x90000000:
        row["esi_memory"] = memory_record(gdb, esi, 0x2A0)
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--max-stops", type=int, default=96)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    out = {
        "schema": "dah2-xemu-scene-dispatch-after-loader-callback6-v1",
        "started": stamp(),
        "callbacks": [],
        "route": [],
        "cleanup": {"breakpoints_remaining": [], "resumed": False},
    }
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    active = set()
    deadline = time.monotonic() + args.timeout

    def breakpoint(address: int, install: bool) -> None:
        assert gdb is not None
        gdb.breakpoint(address, install)
        if install:
            active.add(address)
        else:
            active.discard(address)
        out["cleanup"]["breakpoints_remaining"] = [
            f"0x{x:08x}" for x in sorted(active)
        ]

    def run() -> tuple[int, dict]:
        qmp.execute("cont")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("trace deadline expired")
        wait_stopped(qmp, remaining, 0.01)
        regs = gdb.registers()["i386"]
        return int(regs["eip"], 16), regs

    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        qmp.execute("system_reset")
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = ControlGDB(args.gdb_port, 5)
        out["initial_stop"] = gdb.request("?").decode(errors="replace")

        breakpoint(LOADER, True)
        address, regs = run()
        if address != LOADER:
            raise ProbeError(f"expected loader, stopped at 0x{address:08x}")
        out["loader"] = {"registers": regs}
        breakpoint(LOADER, False)

        breakpoint(CALL, True)
        for ordinal in range(1, 7):
            address, regs = run()
            if address != CALL:
                raise ProbeError(f"expected callback call, stopped at 0x{address:08x}")
            ebx = int(regs["ebx"], 16)
            out["callbacks"].append({
                "ordinal": ordinal,
                "target": f"0x{u32(gdb, ebx):08x}",
                "registers": regs,
            })
            breakpoint(CALL, False)
            breakpoint(RET, True)
            address, _ = run()
            if address != RET:
                raise ProbeError(f"expected callback return, stopped at 0x{address:08x}")
            breakpoint(RET, False)
            if ordinal != 6:
                breakpoint(CALL, True)

        breakpoint(ENTRY, True)
        address, _ = run()
        if address != ENTRY:
            raise ProbeError(f"expected dispatch entry, stopped at 0x{address:08x}")
        out["entry"] = snapshot(gdb, address)
        breakpoint(ENTRY, False)

        for point in ROUTE:
            breakpoint(point, True)
        for _ in range(args.max_stops):
            address, _ = run()
            if address not in active:
                raise ProbeError(f"unexpected route stop 0x{address:08x}")
            out["route"].append(snapshot(gdb, address))
            breakpoint(address, False)
            if address == END:
                break
        else:
            out["route_limit_reached"] = True
    finally:
        try:
            qmp.execute("stop")
            wait_stopped(qmp, 5, 0.01)
        except Exception as exc:
            out["cleanup"].setdefault("errors", []).append(f"stop: {exc}")
        if gdb is not None:
            for address in list(active):
                try:
                    breakpoint(address, False)
                except Exception as exc:
                    out["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            qmp.execute("cont")
            out["cleanup"]["resumed"] = True
        except Exception as exc:
            out["cleanup"]["resume_error"] = str(exc)
        out["finished"] = stamp()
        args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        if gdb is not None:
            gdb.close()
        qmp.close()

    print(json.dumps({
        "route": [row["address"] for row in out["route"]],
        "cleanup": out["cleanup"],
    }))


if __name__ == "__main__":
    main()