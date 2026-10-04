"""Capture the retail Lua concat path immediately after native callback 9.

The trace is bounded, uses only the private parity instance's explicit ports,
removes every hardware breakpoint, and resumes the guest during cleanup.
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB


CALLBACK = 0x001018D0
CALLBACK_RETURN = 0x0021188A
CONCAT = 0x00218AB0
WATCH = (0x00218C6B, 0x00218C7A, 0x00218C8F, 0x00218C93)


def word(data, offset=0):
    return int.from_bytes(data[offset:offset + 4], "little")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--timeout", type=float, default=180)
    a = ap.parse_args()
    if a.output.exists():
        ap.error("output must be new")

    result = {"schema": "dah2-retail-callback9-concat-v1", "started": stamp(),
              "callbacks": [], "events": [],
              "cleanup": {"breakpoints_remaining": [], "resumed": False}}
    q = ControlQMP(a.qmp_port, 5)
    g = None
    active = set()
    deadline = time.monotonic() + a.timeout

    def bp(address, install):
        g.breakpoint(address, install)
        active.add(address) if install else active.discard(address)
        result["cleanup"]["breakpoints_remaining"] = [f"0x{x:08x}" for x in sorted(active)]

    def run():
        q.execute("cont")
        wait_stopped(q, max(0.1, deadline - time.monotonic()), 0.01)
        return g.registers()["i386"]

    def row(kind, regs):
        sp = int(regs["esp"], 16)
        item = {"kind": kind, "captured": stamp(), "registers": regs,
                "stack": memory_record(g, sp, 0x90)}
        if kind == "concat_entry":
            top = word(g.memory(sp + 4, 4))
            item["concat"] = {"state": regs["ecx"], "count": regs["edx"],
                              "top_argument": f"0x{top:08x}",
                              "operands": memory_record(g, top - 0x30, 0x40)}
        else:
            # At these four points the retail frame has the same aligned local
            # layout as the translated function: group at +14, count at +18,
            # state at +10, and saved argument at EBP+8.
            frame = int(regs["ebp"], 16)
            item["locals"] = {
                "state": f"0x{word(g.memory(sp + 0x10, 4)):08x}",
                "group": f"0x{word(g.memory(sp + 0x14, 4)):08x}",
                "count": f"0x{word(g.memory(sp + 0x18, 4)):08x}",
                "saved_argument": f"0x{word(g.memory(frame + 8, 4)):08x}",
            }
        return item

    try:
        q.execute("stop"); wait_stopped(q, 5, 0.01)
        q.execute("system_reset"); q.execute("stop"); wait_stopped(q, 5, 0.01)
        g = StepGDB(a.gdb_port, 5)
        result["initial_stop"] = g.request("?").decode(errors="replace")

        bp(CALLBACK, True)
        for ordinal in range(1, 10):
            regs = run()
            if int(regs["eip"], 16) != CALLBACK:
                raise ProbeError("unexpected callback entry stop")
            result["callbacks"].append({"ordinal": ordinal, "entry": regs})
            bp(CALLBACK, False); bp(CALLBACK_RETURN, True)
            returned = run()
            if int(returned["eip"], 16) != CALLBACK_RETURN:
                raise ProbeError("unexpected callback return stop")
            result["callbacks"][-1]["return"] = returned
            bp(CALLBACK_RETURN, False)
            if ordinal != 9:
                bp(CALLBACK, True)

        bp(CONCAT, True)
        regs = run()
        if int(regs["eip"], 16) != CONCAT:
            raise ProbeError("expected concat entry")
        result["events"].append(row("concat_entry", regs))
        bp(CONCAT, False)
        for address in WATCH:
            bp(address, True)
        for _ in range(12):
            regs = run()
            pc = int(regs["eip"], 16)
            if pc not in WATCH:
                raise ProbeError(f"unexpected concat stop 0x{pc:08x}")
            result["events"].append(row(f"pc_{pc:08x}", regs))
            a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            bp(pc, False); g.step(); bp(pc, True)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            q.execute("stop"); wait_stopped(q, 5, 0.01)
        except Exception as exc:
            result["cleanup"].setdefault("errors", []).append(str(exc))
        if g:
            for address in list(active):
                try: bp(address, False)
                except Exception as exc: result["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            q.execute("cont"); result["cleanup"]["resumed"] = True
        except Exception as exc:
            result["cleanup"]["resume_error"] = str(exc)
        result["finished"] = stamp()
        a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if g: g.close()
        q.close()
    print(json.dumps({"events": len(result["events"]), "error": result.get("error"),
                      "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()
