"""Capture hardware write-watchpoint hits in the owned private xemu guest.

The guest is always resumed and all watchpoints are removed in cleanup.
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, memory_record, stamp, wait_stopped


class WatchGDB(ControlGDB):
    def request(self, payload):
        if re.fullmatch(r"[Zz]2,[0-9a-f]+,[1248]", payload):
            data = payload.encode()
            packet = b"$" + data + f"#{sum(data) & 255:02x}".encode()
            self.sock.sendall(packet)
            for _ in range(100):
                marker = self.byte()
                if marker == ord("+"):
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
                if response[:1] in (b"S", b"T", b"W", b"X"):
                    self.stops.append({"timestamp": stamp(), "packet": response.decode(errors="replace")})
                    continue
                if not response or response.startswith(b"E"):
                    raise ProbeError(f"GDB unsupported/failed {payload}: {response!r}")
                return response
            raise ProbeError("No GDB response after 100 packets")
        return super().request(payload)

    def watchpoint(self, address, length=4, insert=True):
        response = self.request(f"{'Z' if insert else 'z'}2,{address:x},{length:x}")
        if response != b"OK":
            raise ProbeError(f"Hardware watchpoint rejected: {response!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--address", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--length", type=int, choices=(1, 2, 4, 8), default=4)
    ap.add_argument("--hits", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=90)
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--stop-on-change", action="store_true")
    ap.add_argument("--stop-on-nonzero", action="store_true")
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    if a.output.exists():
        ap.error("output must be new")

    result = {"schema": "dah2-xemu-write-watch-v1", "started": stamp(),
              "address": f"0x{a.address:08x}", "length": a.length,
              "hits": [], "cleanup": {"watchpoint_removed": False, "resumed": False}}
    q = ControlQMP(a.qmp_port, 5)
    g = None
    installed = False
    try:
        q.execute("stop")
        wait_stopped(q, 5, 0.02)
        if a.reset:
            q.execute("system_reset")
            q.execute("stop")
            wait_stopped(q, 5, 0.02)
        g = WatchGDB(a.gdb_port, 5)
        result["initial_stop"] = g.request("?").decode(errors="replace")
        g.watchpoint(a.address, a.length)
        installed = True
        deadline = time.monotonic() + a.timeout
        initial_value = memory_record(g, a.address, a.length)
        result["initial_value"] = initial_value
        prior_hex = initial_value.get("hex")
        for ordinal in range(1, a.hits + 1):
            q.execute("cont")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result["timeout"] = True
                break
            try:
                status = wait_stopped(q, remaining, 0.02)
            except ProbeError:
                result["timeout"] = True
                break
            regs = g.registers()
            row = {"ordinal": ordinal, "captured": stamp(), "status": status,
                   "registers": regs, "value": memory_record(g, a.address, a.length)}
            sp = regs.get("i386", {}).get("esp")
            pc = regs.get("i386", {}).get("eip")
            if sp:
                row["stack"] = memory_record(g, int(sp, 16), 0x80)
            if pc:
                row["code_near_pc"] = memory_record(g, (int(pc, 16) - 16) & 0xffffffff, 0x40)
            result["hits"].append(row)
            a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            current_hex = row["value"].get("hex")
            if a.stop_on_change and current_hex != prior_hex:
                result["change_ordinal"] = ordinal
                break
            if a.stop_on_nonzero and current_hex and int.from_bytes(bytes.fromhex(current_hex), "little") != 0:
                result["nonzero_ordinal"] = ordinal
                break
            prior_hex = current_hex
    finally:
        if g and installed:
            try:
                g.watchpoint(a.address, a.length, False)
                result["cleanup"]["watchpoint_removed"] = True
            except Exception as exc:
                result["cleanup"]["watchpoint_error"] = str(exc)
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
    print(json.dumps({"output": str(a.output), "hits": len(result["hits"]),
                      "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()
