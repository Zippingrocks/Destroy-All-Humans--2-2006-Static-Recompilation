"""Send one bounded key event only to a manifest-verified private xemu."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from parity_framebuffer import verify_owner
from parity_probe import ProbeError, QMP, stamp

ALLOWED_KEYS = {"ret", "spc", "esc", "backspace", "up", "down", "left", "right",
                "a", "s", "d", "f", "q", "w", "x", "z"}


class InputQMP(QMP):
    def send_key(self, key: str, hold_ms: int) -> None:
        self.sequence += 1
        request = {"execute": "send-key", "id": self.sequence,
                   "arguments": {"keys": [{"type": "qcode", "data": key}],
                                 "hold-time": hold_ms}}
        self.sock.sendall(json.dumps(request).encode("utf-8") + b"\r\n")
        for _ in range(1000):
            message = self.receive()
            if "event" in message:
                self.events.append(message)
                continue
            if message.get("id") != self.sequence:
                raise ProbeError("Unexpected QMP response ID")
            if "error" in message:
                raise ProbeError(f"QMP error: {message['error']}")
            if "return" not in message:
                raise ProbeError("QMP response missing return")
            return
        raise ProbeError("Too many QMP events without a response")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--key", required=True, choices=sorted(ALLOWED_KEYS))
    parser.add_argument("--hold-ms", type=int, default=100)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")
    if not 25 <= args.hold_ms <= 1000:
        parser.error("hold duration must be 25..1000 ms")

    result = {"schema": "dah2-private-xemu-key-v1", "started": stamp(),
              "key": args.key, "holdMs": args.hold_ms, "events": []}
    qmp = None
    try:
        result["ownership"] = verify_owner(args.manifest, args.qmp_port, args.gdb_port)
        qmp = InputQMP(args.qmp_port, 5)
        result["statusBefore"] = qmp.execute("query-status")
        if not result["statusBefore"].get("running"):
            raise ProbeError("Refusing input because the private guest is not running")
        qmp.send_key(args.key, args.hold_ms)
        result["sent"] = True
        result["statusAfter"] = qmp.execute("query-status")
        result["events"] = qmp.events
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if qmp:
            qmp.close()
        result["finished"] = stamp()
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()