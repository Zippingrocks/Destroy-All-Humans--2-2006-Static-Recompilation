"""Trace retail callback 0x001044C0 immediately after the first object load.

The probe is bounded to the supplied private xemu QMP/GDB ports. It resets
that guest, removes every hardware breakpoint, and resumes it during cleanup.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

LOADER = 0x001A8EB0
CALLBACK = 0x002117F9
CALLBACK_RETURN = 0x002117FD
TARGET = 0x001044C0


def u32(gdb: StepGDB, address: int) -> int:
    return int.from_bytes(gdb.memory(address, 4), "little")


def snapshot(gdb: StepGDB, label: str) -> dict:
    regs = gdb.registers()["i386"]
    esp = int(regs["esp"], 16)
    ecx = int(regs["ecx"], 16)
    return {
        "label": label,
        "registers": regs,
        "stack": memory_record(gdb, esp, 0x80),
        "scriptGlobals": memory_record(gdb, 0x0030FC00, 0x80),
        "ecxMemory": memory_record(gdb, ecx, 0x40)
        if 0x80000000 <= ecx < 0x90000000 else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    out = {
        "schema": "dah2-xemu-callback-1044c0-v1",
        "started": stamp(),
        "callbacks": [],
        "stages": [],
        "cleanup": {"breakpoints_remaining": [], "resumed": False},
    }
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    active: set[int] = set()
    deadline = time.monotonic() + args.timeout

    def breakpoint(address: int, install: bool) -> None:
        assert gdb is not None
        gdb.breakpoint(address, install)
        if install:
            active.add(address)
        else:
            active.discard(address)
        out["cleanup"]["breakpoints_remaining"] = [
            f"0x{value:08x}" for value in sorted(active)
        ]

    def run(expected: int) -> dict:
        assert gdb is not None
        qmp.execute("cont")
        wait_stopped(qmp, max(0.1, deadline - time.monotonic()), 0.01)
        regs = gdb.registers()["i386"]
        actual = int(regs["eip"], 16)
        if actual != expected:
            raise ProbeError(
                f"expected 0x{expected:08x}, stopped at 0x{actual:08x}"
            )
        return regs

    def run_stage(address: int, label: str) -> dict:
        breakpoint(address, True)
        run(address)
        breakpoint(address, False)
        row = snapshot(gdb, label)
        out["stages"].append(row)
        args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        return row["registers"]

    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        qmp.execute("system_reset")
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = StepGDB(args.gdb_port, 5)
        out["initial_stop"] = gdb.request("?").decode(errors="replace")

        breakpoint(LOADER, True)
        out["loader"] = {"registers": run(LOADER)}
        breakpoint(LOADER, False)

        breakpoint(CALLBACK, True)
        target = 0
        for ordinal in range(1, 7):
            regs = run(CALLBACK)
            ebx = int(regs["ebx"], 16)
            target = u32(gdb, ebx)
            out["callbacks"].append({
                "ordinal": ordinal,
                "target": f"0x{target:08x}",
                "registers": regs,
                "stack": memory_record(
                    gdb, int(regs["esp"], 16), 0x400
                ),
            })
            breakpoint(CALLBACK, False)
            if ordinal != 6:
                breakpoint(CALLBACK_RETURN, True)
                run(CALLBACK_RETURN)
                breakpoint(CALLBACK_RETURN, False)
                breakpoint(CALLBACK, True)

        if target != TARGET:
            raise ProbeError(
                f"callback six target 0x{target:08x}, expected 0x{TARGET:08x}"
            )

        run_stage(0x001044C0, "entry")
        regs = run_stage(0x001044C9, "after-103380")
        if int(regs["eax"], 16) != 0:
            run_stage(0x001044D1, "direct-branch")
            run_stage(0x001044DC, "after-direct-af400")
            run_stage(0x001040B0, "dispatch-1040b0-entry")
            run_stage(0x00103551, "dispatch-1040b0-return")
            run_stage(0x001044E4, "after-direct-103530")
        else:
            run_stage(0x001044E7, "fallback-branch")
            run_stage(0x00104460, "fallback-entry")
            run_stage(0x00104469, "fallback-after-103380")
            run_stage(0x00104474, "fallback-after-af400")
            run_stage(0x00104480, "fallback-selected-source")

        run_stage(CALLBACK_RETURN, "callback-return")
        run_stage(0x00218DF1, "vm-dispatch-after-callback")
        gdb.step()
        run_stage(0x00218DF1, "vm-dispatch-return-opcode")
        run_stage(0x0021964C, "inner-vm-return")
        run_stage(0x00211896, "outer-call-return")
        run_stage(0x00218DF1, "outer-vm-resume")
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
        "callbacks": [row["target"] for row in out["callbacks"]],
        "stages": [row["label"] for row in out["stages"]],
        "cleanup": out["cleanup"],
    }))


if __name__ == "__main__":
    main()