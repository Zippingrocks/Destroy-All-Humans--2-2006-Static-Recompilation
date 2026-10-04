"""Guard the background hardware-service loop against full-core spinning."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "xboxrecomp/src/kernel/xbox_memory_layout.c").read_text(encoding="utf-8")
start = SOURCE.index("static DWORD WINAPI nv2a_ack_thread")
end = SOURCE.index("static void xbox_Nv2aAckStart", start)
worker = SOURCE[start:end]
assert "Sleep(1);" in worker
assert "Sleep(0);" not in worker
print("PASS: NV2A acknowledgement worker uses a bounded 1 ms poll cadence")