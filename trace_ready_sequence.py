"""Trace successive retail renderer-ready callback states on private xemu."""
import struct
import sys
import time
sys.path.insert(0, "tools")
from parity_boot_trace import ControlGDB, ControlQMP
qmp = ControlQMP(4447, 3)
gdb = ControlGDB(1237, 3)
address = 0x00156B00
manager = 0x00307318
try:
    for ordinal in range(40):
        qmp.execute("cont")
        time.sleep(0.003)
        qmp.execute("stop")
        time.sleep(0.01)
        gdb.breakpoint(address, True)
        qmp.execute("cont")
        deadline = time.time() + 8
        while time.time() < deadline:
            status = qmp.execute("query-status")
            if not status.get("running"):
                break
            time.sleep(0.01)
        if status.get("running"):
            raise RuntimeError("renderer-ready breakpoint timeout")
        registers = gdb.registers()["i386"]
        phase = struct.unpack("<I", gdb.memory(manager + 0x1A28, 4))[0]
        current, pending, flags = struct.unpack("<3I", gdb.memory(manager + 0x7E18, 12))
        print(ordinal + 1, registers["eip"], f"phase={phase}", f"current={current:08X}", f"pending={pending:08X}", f"flags={flags:08X}", flush=True)
        gdb.breakpoint(address, False)
        if phase == 0x19:
            break
    # The initial setup callback rewrites manager+0x1C to the normal frame
    # function.  The later Bink completion reaches 0x156B00 through a saved
    # asynchronous callback, so wait long enough to capture that distinct
    # caller and stack.
    qmp.execute("cont")
    time.sleep(0.003)
    qmp.execute("stop")
    time.sleep(0.01)
    gdb.breakpoint(address, True)
    qmp.execute("cont")
    deadline = time.time() + 40
    while time.time() < deadline:
        status = qmp.execute("query-status")
        if not status.get("running"):
            break
        time.sleep(0.01)
    if status.get("running"):
        raise RuntimeError("final renderer-ready breakpoint timeout")
    registers = gdb.registers()["i386"]
    stack = gdb.memory(int(registers["esp"], 16), 64)
    phase = struct.unpack("<I", gdb.memory(manager + 0x1A28, 4))[0]
    current, pending, flags = struct.unpack("<3I", gdb.memory(manager + 0x7E18, 12))
    print("FINAL", registers, f"phase={phase}", f"current={current:08X}", f"pending={pending:08X}", f"flags={flags:08X}", "stack=" + stack.hex(), flush=True)
    gdb.breakpoint(address, False)
finally:
    qmp.close()
    gdb.close()
