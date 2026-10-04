"""Trace retail writes to the render-manager flag word on private xemu."""
import re
import struct
import sys
import time

sys.path.insert(0, "tools")
from parity_boot_trace import ControlGDB, ControlQMP
from parity_probe import ProbeError


class WatchGDB(ControlGDB):
    def request(self, payload):
        if payload not in {"g", "?"} and not re.fullmatch(
            r"(?:m[0-9a-f]+,[0-9a-f]+|[Zz][12],[0-9a-f]+,[14])", payload
        ):
            raise ProbeError(f"Disallowed watch GDB packet: {payload}")
        data = payload.encode()
        packet = b"$" + data + f"#{sum(data) & 255:02x}".encode()
        self.sock.sendall(packet)
        retries = 0
        for _ in range(100):
            marker = self.byte()
            if marker == ord("+"):
                continue
            if marker == ord("-"):
                retries += 1
                if retries > 3:
                    raise ProbeError("GDB rejected packet repeatedly")
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
                retries += 1
                continue
            self.sock.sendall(b"+")
            response = self.decode(raw)
            if response[:1] in (b"S", b"T", b"W", b"X"):
                if payload == "?":
                    return response
                continue
            if response.startswith(b"O") and response != b"OK":
                continue
            if not response or response.startswith(b"E"):
                raise ProbeError(f"GDB unsupported/failed {payload}: {response!r}")
            return response
        raise ProbeError("No GDB response after 100 packets")


qmp = ControlQMP(4447, 3)
gdb = WatchGDB(1237, 3)
manager = 0x00307318
watched = manager + 0x7E20

try:
    qmp.execute("stop")
    time.sleep(0.02)
    # Clean up the execution breakpoint left by the preceding bounded probe.
    try:
        gdb.request("z1,156b00,1")
    except ProbeError:
        pass
    try:
        gdb.request(f"z2,{watched:x},4")
    except ProbeError:
        pass
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
            raise RuntimeError("final logo state was not reached before watchpoint arm")
        qmp.execute("cont")
    gdb.request(f"Z2,{watched:x},4")
    last_state = None
    for ordinal in range(12000):
        qmp.execute("cont")
        deadline = time.time() + 60
        while time.time() < deadline:
            status = qmp.execute("query-status")
            if not status.get("running"):
                break
            time.sleep(0.005)
        if status.get("running"):
            raise RuntimeError("manager flag watchpoint timeout")
        regs = gdb.registers()["i386"]
        current, pending, flags = struct.unpack("<3I", gdb.memory(manager + 0x7E18, 12))
        eip = int(regs["eip"], 16)
        state = (current, pending, flags)
        if state != last_state:
            print(
                ordinal + 1,
                f"eip={eip:08X}",
                f"current={current:08X}",
                f"pending={pending:08X}",
                f"flags={flags:08X}",
                flush=True,
            )
            last_state = state
        if current == 0x0030D830 and pending == 0:
            break
    gdb.request(f"z2,{watched:x},4")
finally:
    qmp.close()
    gdb.close()
