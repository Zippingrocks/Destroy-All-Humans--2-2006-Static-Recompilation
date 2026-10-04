"""Capture the retail event that publishes the final screen-ready flag."""
import struct
import sys
import time

sys.path.insert(0, "tools")
from parity_boot_trace import ControlGDB, ControlQMP

qmp = ControlQMP(4447, 3)
gdb = ControlGDB(1237, 3)
manager = 0x00307318
address = 0x0015A1A2

try:
    qmp.execute("stop")
    time.sleep(0.02)
    qmp.execute("system_reset")
    qmp.execute("cont")
    deadline = time.time() + 35
    while True:
        time.sleep(0.5)
        qmp.execute("stop")
        time.sleep(0.01)
        current, pending, flags = struct.unpack("<3I", gdb.memory(manager + 0x7E18, 12))
        print(
            "ARM-CHECK",
            f"current={current:08X}",
            f"pending={pending:08X}",
            f"flags={flags:08X}",
            flush=True,
        )
        if current == 0x0030BF30 and pending == 0x0030D830:
            break
        if time.time() >= deadline:
            raise RuntimeError("final logo state was not reached")
        qmp.execute("cont")
    gdb.breakpoint(address, True)
    qmp.execute("cont")
    deadline = time.time() + 60
    while time.time() < deadline:
        status = qmp.execute("query-status")
        if not status.get("running"):
            break
        time.sleep(0.01)
    if status.get("running"):
        raise RuntimeError("final ready event timeout")
    regs = gdb.registers()["i386"]
    stack = gdb.memory(int(regs["esp"], 16), 96)
    current, pending, flags = struct.unpack("<3I", gdb.memory(manager + 0x7E18, 12))
    print(
        "FINAL-READY",
        regs,
        f"current={current:08X}",
        f"pending={pending:08X}",
        f"flags={flags:08X}",
        "stack=" + stack.hex(),
        flush=True,
    )
    gdb.breakpoint(address, False)
finally:
    qmp.close()
    gdb.close()
