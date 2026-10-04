"""Trace the first two retail 0x124DC0 Lua callbacks and helper returns."""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

ENTRY, AFTER_NAME, AFTER_ARG1 = 0x00124DC0, 0x00124DCF, 0x00124DDA
FIRST_PATH = (0x00124E05, 0x00124E14, 0x00124E1C)


def word(data, offset=0):
    return int.from_bytes(data[offset:offset + 4], "little")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--timeout", type=float, default=240)
    a = ap.parse_args()
    if a.output.exists(): ap.error("output must be new")
    result = {"schema": "dah2-retail-124dc0-v1", "started": stamp(), "calls": [],
              "cleanup": {"breakpoints_remaining": [], "resumed": False}}
    q = ControlQMP(a.qmp_port, 5); g = None; active = set()
    deadline = time.monotonic() + a.timeout

    def bp(addr, install):
        g.breakpoint(addr, install)
        active.add(addr) if install else active.discard(addr)
        result["cleanup"]["breakpoints_remaining"] = [f"0x{x:08x}" for x in sorted(active)]

    def run_to(expected):
        q.execute("cont"); wait_stopped(q, max(0.1, deadline-time.monotonic()), 0.01)
        regs = g.registers()["i386"]
        if int(regs["eip"], 16) != expected:
            raise ProbeError(f"expected 0x{expected:08x}, got {regs['eip']}")
        return regs

    def snapshot(kind, regs):
        sp = int(regs["esp"], 16); state = int(regs["ecx"], 16)
        item = {"kind": kind, "captured": stamp(), "registers": regs,
                "stack": memory_record(g, sp, 0x80)}
        if 0x80000000 <= state < 0x90000000:
            fields = g.memory(state, 0x20); top = word(fields); base = word(fields, 4)
            item["lua"] = {"state_fields": memory_record(g, state, 0x20),
                           "top": f"0x{top:08x}",
                           "base": f"0x{base:08x}",
                           "values": memory_record(g, top-0x50, 0x60),
                           "base_values": memory_record(g, base, max(8, top-base+8))}
        return item

    try:
        q.execute("stop"); wait_stopped(q, 5, 0.01)
        q.execute("system_reset"); q.execute("stop"); wait_stopped(q, 5, 0.01)
        g = StepGDB(a.gdb_port, 5); result["initial_stop"] = g.request("?").decode(errors="replace")
        bp(ENTRY, True)
        for ordinal in (1, 2):
            call = {"ordinal": ordinal}
            regs = run_to(ENTRY); call["entry"] = snapshot("entry", regs)
            bp(ENTRY, False); bp(AFTER_NAME, True)
            regs = run_to(AFTER_NAME); call["after_name"] = snapshot("after_name", regs)
            bp(AFTER_NAME, False); bp(AFTER_ARG1, True)
            regs = run_to(AFTER_ARG1); call["after_arg1"] = snapshot("after_arg1", regs)
            result["calls"].append(call)
            a.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
            bp(AFTER_ARG1, False); g.step()
            if ordinal == 1:
                call["first_path"] = []
                for address in FIRST_PATH:
                    bp(address, True); regs = run_to(address)
                    call["first_path"].append(snapshot(f"pc_{address:08x}", regs))
                    bp(address, False); g.step()
                a.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
                bp(ENTRY, True)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try: q.execute("stop"); wait_stopped(q, 5, 0.01)
        except Exception as exc: result["cleanup"].setdefault("errors", []).append(str(exc))
        if g:
            for addr in list(active):
                try: bp(addr, False)
                except Exception as exc: result["cleanup"].setdefault("errors", []).append(str(exc))
        try: q.execute("cont"); result["cleanup"]["resumed"] = True
        except Exception as exc: result["cleanup"]["resume_error"] = str(exc)
        result["finished"] = stamp(); a.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
        if g: g.close()
        q.close()
    print(json.dumps({"calls": len(result["calls"]), "error": result.get("error"),
                      "cleanup": result["cleanup"]}))


if __name__ == "__main__": main()
