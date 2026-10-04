"""Trace retail GUI-manager registration events up to the first Lua lookup."""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

EVENT_MATCH = 0x00124FC3
INSERT = 0x00124B20
CALLBACK = 0x00124DC0


def word(data, offset=0):
    return int.from_bytes(data[offset:offset + 4], "little")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--timeout", type=float, default=300)
    args = ap.parse_args()
    if args.output.exists():
        ap.error("output must be new")

    result = {
        "schema": "dah2-retail-gui-registration-v1",
        "started": stamp(),
        "matched_events": [],
        "inserts": [],
        "cleanup": {"breakpoints_remaining": [], "resumed": False},
    }
    q = ControlQMP(args.qmp_port, 5)
    g = None
    active = set()
    deadline = time.monotonic() + args.timeout

    def bp(address, install):
        g.breakpoint(address, install)
        active.add(address) if install else active.discard(address)
        result["cleanup"]["breakpoints_remaining"] = [
            f"0x{x:08x}" for x in sorted(active)
        ]

    def manager_record(address):
        data = g.memory(address, 0x4C)
        return {
            "address": f"0x{address:08x}",
            "memory": memory_record(g, address, 0x4C),
            "secondary_count": word(data, 0x10),
            "primary_count": word(data, 0x20),
            "head": f"0x{word(data, 0x34):08x}",
        }

    try:
        q.execute("stop")
        wait_stopped(q, 5, 0.01)
        q.execute("system_reset")
        q.execute("stop")
        wait_stopped(q, 5, 0.01)
        g = StepGDB(args.gdb_port, 5)
        result["initial_stop"] = g.request("?").decode(errors="replace")
        for address in (EVENT_MATCH, INSERT, CALLBACK):
            bp(address, True)

        while time.monotonic() < deadline:
            q.execute("cont")
            wait_stopped(q, max(0.1, deadline - time.monotonic()), 0.01)
            regs = g.registers()["i386"]
            eip = int(regs["eip"], 16)
            esp = int(regs["esp"], 16)
            if eip == CALLBACK:
                state = int(regs["ecx"], 16)
                result["callback"] = {
                    "captured": stamp(),
                    "registers": regs,
                    "stack": memory_record(g, esp, 0x60),
                    "lua_state": memory_record(g, state, 0x20),
                }
                break
            if eip == EVENT_MATCH:
                manager = int(regs["ebx"], 16)
                event = int(regs["eax"], 16)
                event_data = g.memory(event, 0x10)
                result["matched_events"].append({
                    "captured": stamp(),
                    "registers": regs,
                    "event": memory_record(g, event, 0x40),
                    "event_type": f"0x{word(event_data, 4):08x}",
                    "payload": f"0x{word(event_data, 8):08x}",
                    "manager": manager_record(manager),
                })
            elif eip == INSERT:
                manager = int(regs["ecx"], 16)
                stack = g.memory(esp, 0x10)
                result["inserts"].append({
                    "captured": stamp(),
                    "registers": regs,
                    "object": f"0x{word(stack, 4):08x}",
                    "key": f"0x{word(stack, 8):08x}",
                    "stack": memory_record(g, esp, 0x40),
                    "manager": manager_record(manager),
                })
            else:
                raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            g.step()
        else:
            raise ProbeError("timed out before first 0x124DC0 callback")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            q.execute("stop")
            wait_stopped(q, 5, 0.01)
        except Exception as exc:
            result["cleanup"].setdefault("errors", []).append(str(exc))
        if g:
            for address in list(active):
                try:
                    bp(address, False)
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
        "matched_events": len(result["matched_events"]),
        "inserts": len(result["inserts"]),
        "callback": "callback" in result,
        "error": result.get("error"),
        "cleanup": result["cleanup"],
    }))


if __name__ == "__main__":
    main()
