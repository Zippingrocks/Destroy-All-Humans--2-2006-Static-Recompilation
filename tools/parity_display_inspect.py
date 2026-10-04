"""Read-only display capability/register inventory for a dedicated local xemu.

python -B tools/parity_display_inspect.py --qmp-port 4446 --display-registers --output diagnostics/display.json

No screenshots, input, execution control, or framebuffer modifications. Selected
PCRTC/PVIDEO reads have no state-changing read behavior in xemu commit fc24584.
PCRTC_RASTER is deliberately excluded because reading it increments its state.
Register values are sequential samples while the guest runs, not an atomic frame.
"""

import argparse
import json
from pathlib import Path
import re

from parity_probe import QMP, ProbeError, stamp


REGISTERS = {
    "PCRTC_START": 0x600800,
    "PVIDEO_BUFFER": 0x8700,
    "PVIDEO_BASE": 0x8900,
    "PVIDEO_LIMIT": 0x8908,
    "PVIDEO_OFFSET": 0x8920,
    "PVIDEO_SIZE_IN": 0x8928,
    "PVIDEO_POINT_IN": 0x8930,
    "PVIDEO_DS_DX": 0x8938,
    "PVIDEO_DT_DY": 0x8940,
    "PVIDEO_POINT_OUT": 0x8948,
    "PVIDEO_SIZE_OUT": 0x8950,
    "PVIDEO_FORMAT": 0x8958,
    "PVIDEO_COLOR_KEY": 0x8B00,
}


class DisplayQMP(QMP):
    def inspect(self, command, arguments=None):
        if command not in {"query-commands", "query-display-options", "human-monitor-command"}:
            raise ProbeError("Only display inspection commands are permitted")
        if command == "human-monitor-command":
            hmp = (arguments or {}).get("command-line", "")
            if hmp not in {"help", "help screendump"} and not re.fullmatch(r"xp /1wx 0x[0-9a-f]+", hmp):
                raise ProbeError("Only help or a single physical dword read is permitted")
        self.sequence += 1
        request = {"execute": command, "id": self.sequence}
        if arguments:
            request["arguments"] = arguments
        self.sock.sendall(json.dumps(request).encode() + b"\r\n")
        for _ in range(1000):
            response = self.receive()
            if "event" in response:
                self.events.append(response)
                continue
            if response.get("id") != self.sequence:
                raise ProbeError("Unexpected QMP response ID")
            if "error" in response:
                raise ProbeError(str(response["error"]))
            return response["return"]
        raise ProbeError("No QMP response after 1000 events")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--display-registers", action="store_true")
    parser.add_argument("--nv2a-base", type=lambda value: int(value, 0), default=0xFD000000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.qmp_port <= 65535 or args.timeout <= 0 or not 0 <= args.nv2a_base <= 0xFF9FF7FF:
        parser.error("invalid port, timeout, or NV2A MMIO base")
    result = {"schema": "dah2-display-inspection-v1", "started": stamp(), "qmp_port": args.qmp_port}
    qmp = None
    try:
        qmp = DisplayQMP(args.qmp_port, args.timeout)
        result["status_before"] = qmp.execute("query-status")
        result["commands"] = sorted(item["name"] for item in qmp.inspect("query-commands"))
        result["qmp_screendump_available"] = "screendump" in result["commands"]
        result["hmp_help"] = qmp.inspect("human-monitor-command", {"command-line": "help"})
        result["hmp_screendump_help"] = qmp.inspect("human-monitor-command", {"command-line": "help screendump"})
        result["display_options"] = qmp.inspect("query-display-options")
        if args.display_registers:
            result["nv2a_base"] = f"0x{args.nv2a_base:08x}"
            result["registers"] = {}
            for name, offset in REGISTERS.items():
                address = args.nv2a_base + offset
                raw = qmp.inspect("human-monitor-command", {"command-line": f"xp /1wx 0x{address:x}"})
                match = re.search(r":\s*0x([0-9a-fA-F]{8})\b", raw)
                result["registers"][name] = {"address": f"0x{address:08x}", "value": f"0x{int(match[1], 16):08x}" if match else None, "raw": raw}
        result["status_after"] = qmp.execute("query-status")
    except (OSError, ProbeError) as exc:
        result["error"] = str(exc)
    finally:
        if qmp:
            qmp.close()
    result["finished"] = stamp()
    result["note"] = "No execution/input commands sent. Register values are sequential samples, not an atomic displayed frame."
    encoded = json.dumps(result, indent=2)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
    print(encoded)
    return int("error" in result)


if __name__ == "__main__":
    raise SystemExit(main())
