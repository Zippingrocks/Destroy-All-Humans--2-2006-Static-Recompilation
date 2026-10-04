"""Trace retail Lua VM dispatches between native callback 8 and callback 9.

This is intentionally bounded and operates only on explicitly supplied QMP/GDB
ports.  Hardware breakpoints are removed and the guest is resumed in cleanup.
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, memory_record, stamp, wait_stopped


CALLBACK = 0x001018D0
CALLBACK_RETURN = 0x0021188A
VM_DISPATCH = 0x00218DF1


class StepGDB(ControlGDB):
    def step(self):
        """Execute one guest instruction and return its stop reply."""
        payload = b"s"
        packet = b"$" + payload + f"#{sum(payload) & 255:02x}".encode()
        self.sock.sendall(packet)
        retries = 0
        for _ in range(1000):
            marker = self.byte()
            if marker == ord("+"):
                continue
            if marker == ord("-"):
                retries += 1
                if retries > 3:
                    raise ProbeError("GDB rejected step packet repeatedly")
                self.sock.sendall(packet)
                continue
            if marker != ord("$"):
                raise ProbeError(f"Unexpected GDB framing byte: {marker:02x}")
            raw = bytearray()
            while True:
                marker = self.byte()
                if marker == ord("#"):
                    break
                raw.append(marker)
            checksum = int(bytes([self.byte(), self.byte()]), 16)
            if checksum != sum(raw) & 255:
                self.sock.sendall(b"-")
                continue
            self.sock.sendall(b"+")
            response = self.decode(raw)
            if response.startswith(b"O") and response != b"OK":
                continue
            if response[:1] in (b"S", b"T", b"W", b"X"):
                self.stops.append({"timestamp": stamp(), "packet": response.decode(errors="replace")})
                return response
            if not response or response.startswith(b"E"):
                raise ProbeError(f"GDB step failed: {response!r}")
        raise ProbeError("No GDB step response after 1000 packets")


def word(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


def read_string(gdb, address, limit=384):
    if not 0x80000000 <= address < 0x90000000:
        return ""
    return gdb.memory(address, limit).split(b"\0", 1)[0].decode("latin1", errors="replace")


def vm_row(gdb, ordinal):
    regs = gdb.registers()["i386"]
    sp = int(regs["esp"], 16)
    stack = gdb.memory(sp, 0x80)
    func = word(stack, 0x18)
    pc = word(stack, 0x10)
    opcode = int.from_bytes(gdb.memory(pc, 4), "little")
    row = {
        "ordinal": ordinal,
        "captured": stamp(),
        "registers": regs,
        "stack": memory_record(gdb, sp, 0x80),
        "vm": {
            # The breakpoint is at the beginning of 0x218DF1, before the VM
            # loads and advances the instruction pointer.
            "pc": f"0x{pc:08x}",
            "opcode": f"0x{opcode:08x}",
            "hook": regs["eax"],
            "base_arg": f"0x{word(stack, 0x34):08x}",
            "top": regs["ebp"],
            "context": regs["edi"],
            "function": f"0x{func:08x}",
            "code": f"0x{word(stack, 0x0c):08x}",
        },
    }
    top = int(regs["ebp"], 16)
    if top >= 0x18:
        row["lua_operands"] = memory_record(gdb, top - 0x18, 0x18)
    if 0x80000000 <= func < 0x90000000:
        fields = gdb.memory(func, 0x48)
        source_obj = word(fields, 0x40)
        row["proto"] = {
            "fields_hex": fields.hex(),
            "source_object": f"0x{source_obj:08x}",
            "source": read_string(gdb, source_obj + 20),
            "instruction_count": word(fields, 0x1c),
            "line_field": word(fields, 0x3c),
        }
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--steps", type=int, default=256)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    if a.output.exists():
        ap.error("output must be new")

    result = {
        "schema": "dah2-xemu-vm-handoff-v1",
        "started": stamp(),
        "callbacks_before_trace": 8,
        "vm_steps": [],
        "cleanup": {"breakpoints_remaining": [], "resumed": False},
    }
    q = ControlQMP(a.qmp_port, 5)
    g = None
    active = set()
    deadline = time.monotonic() + a.timeout

    def bp(address, install):
        g.breakpoint(address, install)
        if install:
            active.add(address)
        else:
            active.discard(address)
        result["cleanup"]["breakpoints_remaining"] = [f"0x{x:08x}" for x in sorted(active)]

    def run_to(address):
        q.execute("cont")
        wait_stopped(q, max(0.1, deadline - time.monotonic()), 0.01)
        regs = g.registers()["i386"]
        actual = int(regs["eip"], 16)
        if actual != address:
            raise ProbeError(f"expected 0x{address:08x}, stopped at 0x{actual:08x}")
        return regs

    try:
        q.execute("stop")
        wait_stopped(q, 5, 0.01)
        if a.reset:
            q.execute("system_reset")
            q.execute("stop")
            wait_stopped(q, 5, 0.01)
        g = StepGDB(a.gdb_port, 5)
        result["initial_stop"] = g.request("?").decode(errors="replace")

        bp(CALLBACK, True)
        for ordinal in range(1, 9):
            entry = run_to(CALLBACK)
            result.setdefault("callback_entries", []).append({"ordinal": ordinal, "registers": entry})
            bp(CALLBACK, False)
            bp(CALLBACK_RETURN, True)
            returned = run_to(CALLBACK_RETURN)
            result.setdefault("callback_returns", []).append({"ordinal": ordinal, "registers": returned})
            bp(CALLBACK_RETURN, False)
            if ordinal != 8:
                bp(CALLBACK, True)

        bp(CALLBACK, True)
        bp(VM_DISPATCH, True)
        for ordinal in range(1, a.steps + 1):
            q.execute("cont")
            wait_stopped(q, max(0.1, deadline - time.monotonic()), 0.01)
            regs = g.registers()["i386"]
            pc = int(regs["eip"], 16)
            if pc == CALLBACK:
                result["next_callback"] = {
                    "registers": regs,
                    "stack": memory_record(g, int(regs["esp"], 16), 0x100),
                }
                break
            if pc != VM_DISPATCH:
                raise ProbeError(f"unexpected handoff stop at 0x{pc:08x}")
            result["vm_steps"].append(vm_row(g, ordinal))
            a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            bp(VM_DISPATCH, False)
            g.step()
            bp(VM_DISPATCH, True)
        else:
            result["step_limit_reached"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        try:
            q.execute("stop")
            wait_stopped(q, 5, 0.01)
        except Exception as exc:
            result["cleanup"].setdefault("errors", []).append(f"stop before cleanup: {exc}")
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
        a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if g:
            g.close()
        q.close()
    print(json.dumps({"vm_steps": len(result["vm_steps"]), "next_callback": "next_callback" in result,
                      "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()
