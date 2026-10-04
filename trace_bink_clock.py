"""Capture retail Bink-script clock samples once the final logo is active."""
import struct
import sys
import time

sys.path.insert(0, "tools")
from parity_boot_trace import ControlGDB, ControlQMP

qmp = ControlQMP(4447, 3)
gdb = ControlGDB(1237, 3)
manager = 0x00307318
address = 0x001573DC

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
        if current == 0x0030BF30 and pending == 0x0030D830:
            break
        if time.time() >= deadline:
            raise RuntimeError("final logo state was not reached")
        qmp.execute("cont")
    for ordinal in range(4):
        gdb.breakpoint(address, True)
        qmp.execute("cont")
        deadline = time.time() + 20
        while time.time() < deadline:
            status = qmp.execute("query-status")
            if not status.get("running"):
                break
            time.sleep(0.005)
        if status.get("running"):
            raise RuntimeError("Bink clock breakpoint timeout")
        regs = gdb.registers()["i386"]
        print(ordinal + 1, regs, flush=True)
        gdb.breakpoint(address, False)
        qmp.execute("cont")
        time.sleep(0.003)
        qmp.execute("stop")
        time.sleep(0.01)
finally:
    qmp.close()
    gdb.close()
